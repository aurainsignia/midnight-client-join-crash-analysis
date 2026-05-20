"""Find callers of engine.dll+0x21bba0 (engine_Sys_FPrintf) and disassemble
engine.dll+0xa8170 (the get-FILE-from-selector helper). Also enumerate the
parent function of the chained funclet at 0x21a8ba via .pdata."""
import struct
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DLL = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\engine.dll")
pe = pefile.PE(str(DLL), fast_load=False)
image_base = pe.OPTIONAL_HEADER.ImageBase

TARGETS = {
    0x21bba0: "engine_Sys_FPrintf(selector, fmt, ...)",
    0x21bbf0: "engine_Sys_FPrintf_variant(int_arg, selector, fmt, ...)",
    0xa8170:  "FILE_lookup_by_selector",
}

text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
pdata_sec = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".pdata")
pdata = pe.__data__[pdata_sec.PointerToRawData:pdata_sec.PointerToRawData + pdata_sec.SizeOfRawData]


def file_of(rva):
    if text.VirtualAddress <= rva < text.VirtualAddress + max(text.Misc_VirtualSize, text.SizeOfRawData):
        return text.PointerToRawData + rva - text.VirtualAddress
    return None


funcs = []
for i in range(len(pdata) // 12):
    b, e, u = struct.unpack_from("<III", pdata, i * 12)
    if b == 0:
        break
    funcs.append((b, e, u))


def section_of(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s
    return None


def try_string(rva, maxlen=512):
    s = section_of(rva)
    if not s:
        return None
    f = s.PointerToRawData + rva - s.VirtualAddress
    raw = pe.__data__[f:f + maxlen]
    end = raw.find(b"\x00")
    if end < 2 or end > 511:
        return None
    sub = raw[:end]
    if all(0x20 <= b < 0x7f or b in (9, 10, 13) for b in sub):
        return sub.decode("ascii", errors="replace")
    return None


md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False
md2 = Cs(CS_ARCH_X86, CS_MODE_64)
md2.detail = True

# Step 1: find all callers of each target
xrefs = {t: [] for t in TARGETS}
for b, e, u in funcs:
    f = file_of(b)
    if f is None:
        continue
    raw = pe.__data__[f:f + (e - b)]
    for insn in md.disasm(bytes(raw), image_base + b):
        if insn.mnemonic in ("call", "jmp"):
            s = insn.op_str.strip()
            if s.startswith("0x"):
                try:
                    tgt = int(s, 16) - image_base
                    if tgt in xrefs:
                        xrefs[tgt].append((insn.address - image_base, b))
                except ValueError:
                    pass

# For 0x21bba0 callers we want to look for an obvious nearby format string lea
# in the same function — the format string passed via rdx tells us which log
# message is being emitted.

# Build IAT map
iat_by_rva = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode("latin-1")
    for imp in entry.imports:
        name = imp.name.decode("latin-1") if imp.name else f"ord_{imp.ordinal}"
        iat_by_rva[imp.address - image_base] = (dll, name)


def find_format_string_near(call_rva, fn_begin, look_back=64):
    """Scan up to `look_back` bytes back from the call for a `lea rdx, [rip+...]`
    that targets a string in .rdata. Returns the string or None."""
    start = max(fn_begin, call_rva - look_back)
    f = file_of(start)
    if f is None:
        return None
    raw = pe.__data__[f:f + (call_rva - start) + 8]
    last_str = None
    last_rdx_str = None
    last_rcx_str = None
    last_r8_str = None
    for insn in md2.disasm(bytes(raw), image_base + start):
        if insn.mnemonic == "lea" and len(insn.operands) == 2:
            dst, src = insn.operands
            if src.type == 3 and src.mem.base == 41:
                t = insn.address + insn.size + src.mem.disp - image_base
                sv = try_string(t)
                if sv:
                    # which dst reg?
                    reg = insn.reg_name(dst.reg)
                    if reg in ("rdx", "edx"):
                        last_rdx_str = sv
                    elif reg in ("rcx", "ecx"):
                        last_rcx_str = sv
                    elif reg in ("r8", "r8d"):
                        last_r8_str = sv
                    last_str = sv
    return last_rdx_str or last_r8_str or last_rcx_str or last_str


for t, name in TARGETS.items():
    print(f"\n#### CALLERS of engine.dll+0x{t:x} ({name})  — {len(xrefs[t])} sites")
    for call_rva, fn_begin in xrefs[t][:40]:
        fmt = find_format_string_near(call_rva, fn_begin, look_back=200) if t in (0x21bba0, 0x21bbf0) else None
        if fmt:
            fmt_repr = fmt.replace('\n', '\\n').replace('\r', '\\r')[:160]
            print(f"   call at 0x{call_rva:x}  in fn 0x{fn_begin:x}  fmt=\"{fmt_repr}\"")
        else:
            print(f"   call at 0x{call_rva:x}  in fn 0x{fn_begin:x}")


# Disassemble 0xa8170 (the FILE_lookup function) to see what it returns
print("\n\n#### Function 0xa8170 (FILE_lookup_by_selector) disassembly")
fl = None
for b, e, u in funcs:
    if b == 0xa8170:
        fl = (b, e)
        break
if fl:
    b, e = fl
    f = file_of(b)
    raw = pe.__data__[f:f + (e - b)]
    for insn in md2.disasm(bytes(raw), image_base + b):
        rva = insn.address - image_base
        annot = ""
        # RIP-rel data?
        if insn.mnemonic in ("lea", "mov", "cmp", "push"):
            for op in insn.operands:
                if op.type == 3 and op.mem.base == 41:
                    tgt = insn.address + insn.size + op.mem.disp - image_base
                    sec = section_of(tgt)
                    if sec:
                        sname = sec.Name.rstrip(b"\x00").decode("latin-1")
                        if sname == ".rdata":
                            sv = try_string(tgt)
                            if sv:
                                annot += f"  ; \"{sv[:100]}\""
                            else:
                                annot += f"  ; .rdata+0x{tgt:x}"
                        elif sname == ".data":
                            annot += f"  ; .data+0x{tgt:x}"
        # call target -> import?
        if insn.mnemonic in ("call", "jmp"):
            for op in insn.operands:
                if op.type == 3 and op.mem.base == 41:
                    tgt = insn.address + insn.size + op.mem.disp - image_base
                    if tgt in iat_by_rva:
                        annot += f"  ; -> {iat_by_rva[tgt][1]} ({iat_by_rva[tgt][0]})"
        print(f"  {rva:08x}  {insn.bytes.hex():<22} {insn.mnemonic:<8} {insn.op_str}{annot}")

# What's the parent function for the chained funclet at 0x21a8ba?
print("\n\n#### Locate parent of funclet 0x21a8ba (UNW_FLAG_CHAININFO)")
for b, e, u in funcs:
    if b == 0x21a8ba:
        # The unwind starts at u; chain info indicates pointer to parent's
        # RUNTIME_FUNCTION (at end of this unwind data). Let's just read the
        # bytes and unpack.
        sec = section_of(u)
        if sec:
            f = sec.PointerToRawData + u - sec.VirtualAddress
            # First byte: version+flags. Bit 3 onwards = flags.
            data = pe.__data__[f:f + 32]
            print(f"   funclet unwind RVA 0x{u:x}: {data.hex()}")
            # Read version_flags, sizeOfProlog, countOfCodes, framereg
            ver_flags, sz_prolog, count, fr = struct.unpack("<BBBB", data[:4])
            print(f"   ver={ver_flags & 7} flags=0x{ver_flags >> 3:x} prolog={sz_prolog} codes={count} fr=0x{fr:x}")
            # Codes use up count*2 bytes (padded to 4). After that, depending on
            # flags, may be CHAIN INFO (RUNTIME_FUNCTION) = 12 bytes.
            after_codes = 4 + count * 2
            # pad to 4
            if after_codes % 4:
                after_codes += 2
            cb, ce, cu = struct.unpack_from("<III", data, after_codes)
            print(f"   chained parent RUNTIME_FUNCTION: 0x{cb:x}..0x{ce:x}  unwind=0x{cu:x}")
        break
