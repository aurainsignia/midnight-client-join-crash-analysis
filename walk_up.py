"""Walk the stack upward from the crash, using each binary's .pdata for unwind.

We continue past engine_Sys_FPrintf (which already returned us into tier0
via the chained-funclet's parent 0x21a890). Now use tier0.dll's .pdata
to walk above tier0+0x7fed.

Also: survey ALL captured memory ranges in the dump, looking for any
that cover heap addresses we care about.
"""
import struct
from pathlib import Path
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DMP = Path(r"C:\Users\Chris\Desktop\dubiousnet\bugs\gmod client crash on third party zs server 2026-05-19\gmod.exe.29108.dmp")
TIER0 = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\tier0.dll")
ENGINE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\engine.dll")

dmp = DMP.read_bytes()

# --- mem index ---
sig, ver, n_streams, dir_rva = struct.unpack_from("<IIII", dmp, 0)
streams = {}
for i in range(n_streams):
    off = dir_rva + i * 12
    stype, sz, srva = struct.unpack_from("<III", dmp, off)
    streams.setdefault(stype, []).append((sz, srva))

mem_idx = []
for sz, srva in streams.get(9, []):
    n_ranges, base_rva = struct.unpack_from("<QQ", dmp, srva)
    cursor = base_rva
    for i in range(n_ranges):
        start, size = struct.unpack_from("<QQ", dmp, srva + 16 + i * 16)
        mem_idx.append((start, start + size, cursor))
        cursor += size
for sz, srva in streams.get(5, []):
    n_ranges = struct.unpack_from("<I", dmp, srva)[0]
    for i in range(n_ranges):
        off = srva + 4 + i * 16
        start, dsize, drva = struct.unpack_from("<QII", dmp, off)
        mem_idx.append((start, start + dsize, drva))
mem_idx.sort()

# --- module bases from the dump's ModuleList ---
modules = {}  # name (lower) -> (base, size)
for sz, srva in streams.get(4, []):
    n_mods = struct.unpack_from("<I", dmp, srva)[0]
    off = srva + 4
    for i in range(n_mods):
        base, size_img, _csum, _ts, name_rva = struct.unpack_from("<QIIII", dmp, off)
        slen = struct.unpack_from("<I", dmp, name_rva)[0]
        sbytes = dmp[name_rva + 4:name_rva + 4 + slen]
        name = sbytes.decode("utf-16-le", errors="replace")
        short = name.split("\\")[-1].lower()
        modules[short] = (base, size_img, name)
        off += 108

TIER0_BASE = modules["tier0.dll"][0]
ENGINE_BASE = modules["engine.dll"][0]
print(f"engine.dll @ 0x{ENGINE_BASE:016x}")
print(f"tier0.dll  @ 0x{TIER0_BASE:016x}")

# --- read VA from dump ---
def read_va(va, n):
    for s, e, fo in mem_idx:
        if s <= va and va + n <= e:
            return dmp[fo + (va - s):fo + (va - s) + n]
        if s <= va < e:
            avail = e - va
            partial = dmp[fo + (va - s):fo + (va - s) + avail]
            rest = read_va(e, n - avail)
            return partial + (rest if rest else b"\x00" * (n - avail))
    return None

def in_range_module(va, base, size):
    return base <= va < base + size

def vname(va):
    for name, (base, size, full) in modules.items():
        if base <= va < base + size:
            return f"{name}+0x{va - base:x}"
    return None


# --- Parse .pdata of a PE and return list of (begin, end, unwind) RVAs ---
def parse_pdata(pefile_obj):
    pdata_sec = next(s for s in pefile_obj.sections if s.Name.rstrip(b"\x00") == b".pdata")
    pdata = pefile_obj.__data__[pdata_sec.PointerToRawData:pdata_sec.PointerToRawData + pdata_sec.SizeOfRawData]
    funcs = []
    for i in range(len(pdata) // 12):
        b, e, u = struct.unpack_from("<III", pdata, i * 12)
        if b == 0: break
        funcs.append((b, e, u))
    return funcs

# --- Parse unwind info, return (stack_alloc, push_count, total_frame, flags, has_chaininfo, chained_parent_or_None) ---
def parse_unwind(pe_obj, unwind_rva):
    # read 4 bytes header
    pdata_sec = next(s for s in pe_obj.sections if s.Name.rstrip(b"\x00") == b".rdata" or s.Name.rstrip(b"\x00") == b".pdata")
    # Use a section-of helper
    sec = None
    for s in pe_obj.sections:
        if s.VirtualAddress <= unwind_rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            sec = s
            break
    if sec is None:
        return None
    base = sec.PointerToRawData + (unwind_rva - sec.VirtualAddress)
    raw = pe_obj.__data__[base:base + 32]
    ver_flags, sz_prolog, count, fr = struct.unpack("<BBBB", raw[:4])
    flags = (ver_flags >> 3) & 0x1f
    codes_bytes = pe_obj.__data__[base + 4:base + 4 + count * 2]
    if count == 0:
        codes = []
    else:
        codes = list(struct.unpack(f"<{count}H", codes_bytes))
    stack_alloc = 0
    push_count = 0
    i = 0
    while i < count:
        c = codes[i]
        off = c & 0xff
        op = (c >> 8) & 0xf
        info = (c >> 12) & 0xf
        size = 1
        if op == 0:  # PUSH_NONVOL
            push_count += 1
        elif op == 1:  # ALLOC_LARGE
            if info == 0:
                stack_alloc += codes[i + 1] * 8
                size = 2
            else:
                stack_alloc += (codes[i + 1] | (codes[i + 2] << 16))
                size = 3
        elif op == 2:  # ALLOC_SMALL
            stack_alloc += (info + 1) * 8
        elif op in (4, 8):  # SAVE_NONVOL, SAVE_XMM128
            size = 2
        elif op in (5, 9):  # SAVE_NONVOL_FAR, SAVE_XMM128_FAR
            size = 3
        i += size
    total = stack_alloc + push_count * 8
    chained = None
    if flags & 0x4:  # UNW_FLAG_CHAININFO
        after_codes = 4 + count * 2
        if after_codes & 2: after_codes += 2  # align to 4
        chain_raw = pe_obj.__data__[base + after_codes:base + after_codes + 12]
        cb, ce, cu = struct.unpack("<III", chain_raw)
        chained = (cb, ce, cu)
    return (stack_alloc, push_count, total, flags, chained)


# Build lookup for both modules
pe_e = pefile.PE(str(ENGINE), fast_load=False)
pe_t = pefile.PE(str(TIER0), fast_load=False)
e_funcs = parse_pdata(pe_e)
t_funcs = parse_pdata(pe_t)

def find_func(funcs, rva):
    lo, hi = 0, len(funcs) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        b, e, u = funcs[mid]
        if rva < b: hi = mid - 1
        elif rva >= e: lo = mid + 1
        else: return funcs[mid]
    return None


# Walking the stack from the crash up
crash_rsp = 0x000000667cd7ebd0

# We already walked through engine_Sys_FPrintf (12 frames up = +0x848 was its RA).
# Then the parent of the chained funclet at 0x21a890 has total_frame=0x28.
# Then tier0+0x7fed is the RA into tier0+0x7ef0.
# We now keep walking using tier0's .pdata.

# Reconstruct manually: parent of funclet 0x21a890 has total_frame=0x28.
# Its RA was at RSP+0x870 (= 0x848 + 0x28). Actually wait — engine_Sys_FPrintf's RA was at +0x848 inside the funclet. Parent of funclet share frame so we use parent's total. From the dump output: rsp+0x0878 = tier0+0x7fed.

FRAMES_ENGINE_SIDE = [
    ("__report_failure",       0x28, 0x33b572, "engine"),
    ("_invalid_parameter_walker", 0x38, 0x35f958, "engine"),
    ("_write",                 0x58, 0x364851, "engine"),
    ("_putc_nolock",           0x28, 0x364a1f, "engine"),
    ("_putc_helper2",          0x28, 0x352a43, "engine"),
    ("_write_multi_char",      0x38, 0x351403, "engine"),
    ("_output_specifier",      0x88, 0x350215, "engine"),
    ("_output_state_machine",  0x38, 0x34ff12, "engine"),
    ("_vfprintf_internal",   0x4b8, 0x34df36, "engine"),
    ("vfprintf_lockwrapper",   0x28, 0x352b8e, "engine"),
    ("__stdio_common_vfprintf", 0xc8, 0x21bbdc, "engine"),
    ("engine_Sys_FPrintf",     0x48, 0x21a8e1, "engine"),
    ("dump-loop-parent (0x21a890)", 0x28, 0x7fed,  "tier0"),
]

print("\n=== Walking the call chain via .pdata for both modules ===")
print(f"{'frame':>34}  {'RA offset':>10}  {'value':<22}  resolved")
print("-" * 110)
offs = 0
for label, total, expected_rva, mod in FRAMES_ENGINE_SIDE:
    ra_off = offs + total
    ra_b = read_va(crash_rsp + ra_off, 8)
    if ra_b:
        ra = struct.unpack("<Q", ra_b)[0]
        resolved = vname(ra) or f"0x{ra:x}"
        print(f"  {label:>34}  +0x{ra_off:04x}    0x{ra:016x}  {resolved}")
    offs = ra_off + 8

# Now continue walking ABOVE the dump-loop-parent using tier0's pdata.
# The RA at offset +0x878 = tier0+0x7fed. The function tier0+0x7ef0..0x8037 was disassembled.
# tier0+0x7ef0 prologue:
#   mov [rsp+0x18], rbx
#   push rsi
#   push rdi
#   push r14
#   sub rsp, 0x370
# 3 pushes + 0x370 alloc = 0x388. + 8 for RA = 0x390 from active RSP up to caller's RA pos.
# So next-level RA is at: 0x878 + total_frame_of_7ef0 = 0x878 + 0x388 = 0xc00.
print("\n=== Continuing walk into tier0 ===")
current_rsp_offset = offs  # this is +0x878 + 8 = +0x880 (start of dump-loop-parent's epilogue+next)
# But we want to walk by func, not by frame label. Let me redo using actual unwind.

# Restart the walk programmatically:
def walk_chain():
    """Yield (frame_idx, ra_offset_from_crash_rsp, ra_va, function_range, module_name).
    Stops at first frame that can't be resolved."""
    # initial frame: we're inside __report_failure at RIP=engine+0x33b5dc
    # __report_failure unwind: sub rsp, 0x28 (no pushes) -> total=0x28
    cur_offset = 0  # offset from crash_rsp of current frame's active RSP (it IS crash_rsp)
    cur_total = 0x28
    cur_mod = "engine"
    cur_label = "__report_failure"
    yield (0, None, None, None, cur_mod, cur_label)

    idx = 1
    while True:
        ra_offset = cur_offset + cur_total
        ra_b = read_va(crash_rsp + ra_offset, 8)
        if ra_b is None:
            yield (idx, ra_offset, None, None, None, "RSP+0x%x not captured" % ra_offset)
            return
        ra = struct.unpack("<Q", ra_b)[0]
        # find which module
        mod_name = None
        for nm, (b, sz, full) in modules.items():
            if b <= ra < b + sz:
                mod_name = nm
                break
        if mod_name is None:
            yield (idx, ra_offset, ra, None, None, f"<unknown module> 0x{ra:x}")
            return
        # get .pdata
        if mod_name == "engine.dll":
            f = find_func(e_funcs, ra - ENGINE_BASE)
            pe_obj = pe_e
        elif mod_name == "tier0.dll":
            f = find_func(t_funcs, ra - TIER0_BASE)
            pe_obj = pe_t
        else:
            # need to load that pe (vstdlib, kernel, etc) — just stop for now
            yield (idx, ra_offset, ra, None, mod_name, "(module not loaded for unwind)")
            return
        if f is None:
            yield (idx, ra_offset, ra, None, mod_name, "(no pdata entry)")
            return
        fb, fe, fu = f
        uw = parse_unwind(pe_obj, fu)
        if uw is None:
            yield (idx, ra_offset, ra, None, mod_name, "(no unwind info)")
            return
        stack_alloc, push_count, total, flags, chained = uw
        # If chained (funclet), follow to parent's unwind
        depth = 0
        while chained and depth < 4:
            depth += 1
            cb, ce, cu = chained
            uw2 = parse_unwind(pe_obj, cu)
            if uw2 is None:
                break
            stack_alloc, push_count, total, flags, chained = uw2
        yield (idx, ra_offset, ra, (fb, fe), mod_name, f"total=0x{total:x}")
        # advance
        cur_offset = ra_offset + 8
        cur_total = total
        idx += 1
        if idx > 30:
            return


print("\nFull chain walk (programmatic, using .pdata of both modules):")
print(f"{'#':>3}  {'RA offset':>10}  {'RA value':<20}  {'module':<13}  {'func range':<25}  notes")
print("-" * 120)
for entry in walk_chain():
    idx, ra_off, ra, frange, mod, notes = entry
    if ra is None:
        print(f"  {idx:>3}  (frame 0)                                                                   {mod}: {notes}")
    else:
        rng = f"0x{frange[0]:x}..0x{frange[1]:x}" if frange else "?"
        print(f"  {idx:>3}  +0x{ra_off:04x}    0x{ra:016x}  {mod:<13}  {rng:<25}  {notes}")
