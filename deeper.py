"""Read more runtime context from the .dmp:
 - The path the dump file was opened at (built by sprintf at rsp+0x150 inside tier0+0x7ef0)
 - The work-item struct (the 'rbx' in tier0+0x1c950)
 - The tier0 callback table at runtime VA (engine.dll's static .data showed weird interleaved values)
 - The Exception stream's ExceptionInformation[15] field for any extra details
 - Survey ALL captured memory ranges (we may have missed heap regions)
"""
import struct
from pathlib import Path
import pefile

DMP = Path(r"C:\Users\Chris\Desktop\dubiousnet\bugs\gmod client crash on third party zs server 2026-05-19\gmod.exe.29108.dmp")
TIER0 = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\tier0.dll")
ENGINE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\engine.dll")
dmp = DMP.read_bytes()

# ---- streams ----
sig, ver, n_streams, dir_rva = struct.unpack_from("<IIII", dmp, 0)
streams = {}
for i in range(n_streams):
    off = dir_rva + i * 12
    stype, sz, srva = struct.unpack_from("<III", dmp, off)
    streams.setdefault(stype, []).append((sz, srva))

# ---- module bases ----
modules = {}
for sz, srva in streams.get(4, []):
    n_mods = struct.unpack_from("<I", dmp, srva)[0]
    off = srva + 4
    for _ in range(n_mods):
        base, size_img, _csum, _ts, name_rva = struct.unpack_from("<QIIII", dmp, off)
        slen = struct.unpack_from("<I", dmp, name_rva)[0]
        name = dmp[name_rva + 4:name_rva + 4 + slen].decode("utf-16-le", errors="replace")
        modules[name.split("\\")[-1].lower()] = (base, size_img, name)
        off += 108
TIER0_BASE = modules["tier0.dll"][0]
ENGINE_BASE = modules["engine.dll"][0]

# ---- memory index ----
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

def vname(va):
    for nm, (b, sz, _) in modules.items():
        if b <= va < b + sz:
            return f"{nm}+0x{va-b:x}"
    return None

def read_str(va, maxlen=512):
    raw = read_va(va, maxlen)
    if not raw: return None
    end = raw.find(b"\x00")
    if end < 1 or end > maxlen-1: return None
    sub = raw[:end]
    if all(0x20 <= c < 0x7f or c in (9, 10, 13) for c in sub):
        return sub.decode("ascii")
    return None

# 1) Read the path the dump file was opened at.
#    tier0+0x7ef0's sprintf result lives at active_rsp+0x150.
#    active_rsp of tier0+0x7ef0 = crash_rsp + 0x880.
crash_rsp = 0x000000667cd7ebd0
tier0_dump_active_rsp = crash_rsp + 0x880
path_buf_va = tier0_dump_active_rsp + 0x150
print(f"=== Dump-file path buffer (sprintf output at tier0+0x7ef0's rsp+0x150) ===")
print(f"  VA = 0x{path_buf_va:016x}")
raw = read_va(path_buf_va, 0x208)
if raw:
    end = raw.find(b"\x00")
    print(f"  composed path: {raw[:end].decode('latin-1') if end > 0 else '(empty)'}")
    print(f"  hexdump first 0x80:")
    for i in range(0, min(0x80, len(raw)), 16):
        chunk = raw[i:i+16]
        hx = " ".join(f"{c:02x}" for c in chunk)
        ax = "".join(chr(c) if 0x20 <= c < 0x7f else "." for c in chunk)
        print(f"    +0x{i:03x}: {hx:<48}  {ax}")
else:
    print("  (not in dump)")

# 2) Read the format string at tier0+0x47d80 (the sprintf format)
pe_t = pefile.PE(str(TIER0), fast_load=False)
def read_tier0_static(rva, n):
    for s in pe_t.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return pe_t.__data__[s.PointerToRawData + (rva - s.VirtualAddress):
                                  s.PointerToRawData + (rva - s.VirtualAddress) + n]
    return None

print(f"\n=== Static tier0.dll .rdata at 0x47d80 (sprintf format string) ===")
raw = read_tier0_static(0x47d80, 128)
if raw:
    end = raw.find(b"\x00")
    print(f"  string: {raw[:end].decode('ascii') if end > 0 else '(?)'}")
    print(f"  hex: {raw[:48].hex()}")

print(f"\n=== Static tier0.dll .rdata at 0x47d94 (fopen mode string) ===")
raw = read_tier0_static(0x47d94, 16)
if raw:
    end = raw.find(b"\x00")
    print(f"  string: {raw[:end].decode('ascii') if end > 0 else '(?)'}")
    print(f"  hex: {raw[:8].hex()}")

print(f"\n=== Static tier0.dll .rdata at 0x47d98 (Executable: format) ===")
raw = read_tier0_static(0x47d98, 64)
if raw:
    end = raw.find(b"\x00")
    print(f"  string: {repr(raw[:end].decode('ascii') if end > 0 else '?')}")

# 3) Read the args passed to tier0+0x7ef0 from its caller's perspective.
#    The active_rsp of tier0+0x1c950 (the worker thread) was crash_rsp + 0xc10.
#    But more directly: tier0+0x7ef0 received (rcx, rdx, r8, r9, [rsp+0x28-from-caller]).
#    These were saved at:
#      - rdx -> rsi internally; at rsp+0x18 of caller before push (but here just locals)
#    Easier: read the bytes at [rsp+0x3a0] (saved rbx in tier0+0x7ef0's frame) etc.
print(f"\n=== Args saved in tier0+0x7ef0's frame ===")
# The function did: 'mov [rsp+0x18], rbx' at entry — that's [callee_rsp_entry+0x18].
# active_rsp post-prologue = caller_rsp_at_entry - 0x388. Shadow rbx slot is at +0x18 of caller_rsp_at_entry.
# So shadow rbx slot (caller's arg 'rbx' was at [rsp+0x18] in shadow space — but this fn doesn't save rcx/rdx/r8/r9 to shadow before push.
# Per disasm: 'mov [rsp+0x18], rbx' at entry — that's saving rbx to caller's shadow space slot 2 (rdx-slot).
# But this means the CALLER's rdx shadow slot was overwritten by saved-rbx.
# Active rbx = arg2 wasn't (it was just used to read [r8] for the byte flag).
# Let's read the shadow slots from tier0+0x1c950's outgoing call setup.
# tier0+0x1c950 is the caller. Its active_rsp = crash_rsp + 0xc10. Its outgoing call area is at [rsp+0x00..0x40].
# Looking at the disassembly: it did:
#   +0x1ca07  mov rdx, [rbx+0x88]       ; rdx = arg2 = work_item[0x88]
#   +0x1ca0e  mov rcx, [rbx+0x80]       ; rcx = arg1 = work_item[0x80]
#   +0x1ca15  mov [rsp+0x28], al        ; stack arg6 (or shadow extras)
#   +0x1ca19  mov [rsp+0x20], rdi       ; arg5 = rdi
#   +0x1ca1e  call r10                  ; the call to tier0+0x7ef0
# So the outgoing args are at rsp+0x00..0x30 of tier0+0x1c950.
# active_rsp of tier0+0x1c950 = crash_rsp + 0xc10. So caller_rsp_outgoing = +0xc10.
caller_outgoing_rsp = crash_rsp + 0xc10
print(f"  worker-thread caller's outgoing-call shadow space starts at 0x{caller_outgoing_rsp:016x}")
for k in range(0, 8):
    addr = caller_outgoing_rsp + k * 8
    b = read_va(addr, 8)
    if b:
        v = struct.unpack("<Q", b)[0]
        ann = vname(v) or ""
        s = ""
        if (v >> 48) in (0x7ffc, 0x7ffe):
            ss = read_str(v, 256)
            if ss: s = f'  "{ss[:120]}"'
        print(f"    +0x{k*8:02x}: 0x{v:016x}  {ann}{s}")

# 4) Reading the work-item struct (the rbx in tier0+0x1c950).
#    The worker thread's `rbx` register held the work-item pointer.
#    The thread proc saved rbx via `push rbx` as part of its prologue.
#    tier0+0x1c950 prologue: push rbx; sub rsp, 0x30; mov [rsp+0x40], rbp...
#    So saved rbx is at [active_rsp + 0x38] (after 1 push + 0x30 alloc, the push slot is at +0x30).
#    active_rsp of tier0+0x1c950 = crash_rsp + 0xc10. So saved rbx is at +0xc10 + 0x38 = +0xc48.
#    But wait, the push rbx happens first, then sub rsp, 0x30. So saved rbx is at [entry_rsp - 8] = active_rsp + 0x30.
# Wait, also there are post-push assigns: 'mov [rsp+0x40], rbp', etc. Those put rbp at active_rsp+0x40.
# So layout:
#   [active_rsp + 0x00 .. +0x20] = outgoing-call shadow
#   [active_rsp + 0x28] = small local
#   [active_rsp + 0x30] = saved rbx (from push rbx pre-sub)
#   [active_rsp + 0x40] = saved rbp
#   [active_rsp + 0x48] = saved rsi
#   [active_rsp + 0x50] = saved rdi
worker_active_rsp = crash_rsp + 0xc10
saved_rbx_addr = worker_active_rsp + 0x30
print(f"\n=== Worker thread's saved rbx (= the work-item ptr) ===")
b = read_va(saved_rbx_addr, 8)
if b:
    work_item_ptr = struct.unpack("<Q", b)[0]
    print(f"  saved rbx @ 0x{saved_rbx_addr:016x} = 0x{work_item_ptr:016x}  {vname(work_item_ptr) or ''}")
    # Read the work item struct
    raw = read_va(work_item_ptr, 0x180)
    if raw:
        print(f"  Work-item struct hexdump (0x180 bytes):")
        for i in range(0, 0x180, 16):
            chunk = raw[i:i+16]
            hx = " ".join(f"{c:02x}" for c in chunk)
            ax = "".join(chr(c) if 0x20 <= c < 0x7f else "." for c in chunk)
            # interpret qwords
            q0 = struct.unpack_from("<Q", chunk, 0)[0]
            q1 = struct.unpack_from("<Q", chunk, 8)[0]
            ann0 = vname(q0) or ""
            ann1 = vname(q1) or ""
            print(f"    +0x{i:03x}: {hx}  {ax}")
            if i % 16 == 0 and (ann0 or ann1):
                print(f"           q[0]=0x{q0:016x} {ann0}  q[1]=0x{q1:016x} {ann1}")
    else:
        print(f"  work-item not in dump")

# 5) Survey memory ranges
print(f"\n=== Memory ranges survey (looking for heap coverage) ===")
heap_ranges = []
text_ranges = []
stack_ranges = []
for s, e, fo in mem_idx:
    sz = e - s
    high = s >> 48
    if high == 0x0000 and s < 0x000400000000000:
        # Could be heap or stack
        if s >> 32 < 0x100:
            heap_ranges.append((s, e, sz))
        else:
            stack_ranges.append((s, e, sz))
    elif high in (0x7ffc, 0x7ffe, 0x7ffd, 0x7ffb, 0x7ffa, 0x7fff):
        text_ranges.append((s, e, sz))

# Show heap range sizes
print(f"  Total ranges: {len(mem_idx)}")
print(f"  'heap-like' ranges (low VA, no module mapping): {len(heap_ranges)}")
print(f"  'text-like' (module-image VA): {len(text_ranges)}")
print(f"  Largest 10 'heap-like' ranges:")
heap_ranges.sort(key=lambda t: -t[2])
for s, e, sz in heap_ranges[:10]:
    print(f"    [0x{s:016x}..0x{e:016x})  size=0x{sz:x}")

# Specifically check if 0x0000023d0ec49f70 is covered
target = 0x0000023d0ec49f70
print(f"\n=== Coverage check for FILE* @ 0x{target:016x} ===")
hit = None
for s, e, fo in mem_idx:
    if s <= target < e:
        hit = (s, e, fo)
        break
if hit:
    s, e, fo = hit
    print(f"  COVERED by range [0x{s:016x}..0x{e:016x})  file=0x{fo:x}")
    raw = read_va(target, 0x80)
    if raw:
        print(f"  FILE struct hexdump:")
        for i in range(0, 0x80, 16):
            chunk = raw[i:i+16]
            hx = " ".join(f"{c:02x}" for c in chunk)
            ax = "".join(chr(c) if 0x20 <= c < 0x7f else "." for c in chunk)
            print(f"    +0x{i:02x}: {hx}  {ax}")
else:
    print(f"  NOT COVERED")

# Also dump the exception stream's ExceptionInformation
print(f"\n=== Exception stream ===")
for sz, srva in streams.get(6, []):
    tid = struct.unpack_from("<I", dmp, srva)[0]
    code, flags, recptr, addr, n_params = struct.unpack_from("<IIQQI", dmp, srva + 8)
    print(f"  ThreadId={tid}  ExceptionCode=0x{code:08x}  ExceptionAddress=0x{addr:016x}  NumberParameters={n_params}")
    for i in range(min(n_params, 15)):
        p = struct.unpack_from("<Q", dmp, srva + 8 + 24 + i * 8)[0]
        v = vname(p)
        print(f"    Param[{i}] = 0x{p:016x}  {v or ''}")
