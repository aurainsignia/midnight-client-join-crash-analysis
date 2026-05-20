"""Disassemble engine.dll functions 0x21bba0, 0x21bbf0, 0x21a8ba and a window
around them, with annotations including the strings table and CRT helper names.
Goal: name the engine logger function that owns these call sites."""
import struct
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DLL = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\engine.dll")
pe = pefile.PE(str(DLL), fast_load=False)
image_base = pe.OPTIONAL_HEADER.ImageBase

# Build IAT map
iat_by_rva = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode("latin-1")
    for imp in entry.imports:
        name = imp.name.decode("latin-1") if imp.name else f"ord_{imp.ordinal}"
        iat_by_rva[imp.address - image_base] = (dll, name)

KNOWN_CRT = {
    0x33b4bc: "_invalid_parameter_chain_dispatcher",
    0x33b574: "_invalid_parameter_noinfo",
    0x33b594: "_invalid_parameter_noinfo_noreturn",
    0x33b5c4: "__report_invalid_arg_fastfail",
    0x35f8b8: "_write",
    0x3647f0: "_putc_nolock",
    0x3529e4: "_write_multi_char",
    0x350f68: "_output_specifier",
    0x3500f0: "_output_state_machine",
    0x34fe48: "_vfprintf_internal",
    0x34df10: "vfprintf_lockwrapper",
    0x352ab4: "_vfprintf_outer",
}


def section_of(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s
    return None


def file_of(rva):
    s = section_of(rva)
    if s is None:
        return None
    return s.PointerToRawData + rva - s.VirtualAddress


def read_at(rva, n):
    f = file_of(rva)
    if f is None:
        return None
    return pe.__data__[f:f + n]


def try_string(rva, maxlen=512):
    raw = read_at(rva, maxlen)
    if not raw:
        return None
    end = raw.find(b"\x00")
    if end < 2 or end > 511:
        return None
    sub = raw[:end]
    if all(0x20 <= b < 0x7f or b in (9, 10, 13) for b in sub):
        return sub.decode("ascii", errors="replace")
    if end >= 4 and raw[1] == 0 and raw[3] == 0:
        end16 = 0
        while end16 + 1 < len(raw):
            if raw[end16] == 0 and raw[end16 + 1] == 0:
                break
            end16 += 2
        if 4 <= end16 <= 510:
            try:
                return "L" + raw[:end16].decode("utf-16le")
            except UnicodeDecodeError:
                pass
    return None


md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


def annotate(insn):
    annots = []
    if insn.mnemonic in ("call", "jmp"):
        if len(insn.operands) == 1:
            op = insn.operands[0]
            if op.type == 2:
                tgt = op.imm - image_base
                if tgt in KNOWN_CRT:
                    annots.append(f"-> {KNOWN_CRT[tgt]}")
                else:
                    # thunk?
                    raw = read_at(tgt, 6)
                    if raw and len(raw) == 6 and raw[0] == 0xff and raw[1] == 0x25:
                        disp = struct.unpack("<i", raw[2:6])[0]
                        ttgt = tgt + 6 + disp
                        if ttgt in iat_by_rva:
                            annots.append(f"-> {iat_by_rva[ttgt][1]} ({iat_by_rva[ttgt][0]}) [thunk]")
                        else:
                            annots.append(f"-> engine.dll+0x{tgt:x} [thunk]")
                    else:
                        annots.append(f"-> engine.dll+0x{tgt:x}")
            elif op.type == 3 and op.mem.base == 41:
                t = insn.address + insn.size + op.mem.disp - image_base
                if t in iat_by_rva:
                    annots.append(f"-> {iat_by_rva[t][1]} ({iat_by_rva[t][0]})")
                else:
                    annots.append(f"-> [engine.dll+0x{t:x}]")
    if insn.mnemonic in ("lea", "mov", "cmp", "push"):
        for op in insn.operands:
            if op.type == 3 and op.mem.base == 41:
                t = insn.address + insn.size + op.mem.disp - image_base
                sec = section_of(t)
                if sec:
                    sname = sec.Name.rstrip(b"\x00").decode("latin-1")
                    if sname in (".rdata", ".data"):
                        s = try_string(t)
                        if s:
                            annots.append(f'"{s[:200]}"')
    return "  ; " + " ; ".join(annots) if annots else ""


def disasm_func(begin, end, label):
    print(f"\n#### Function 0x{begin:x}..0x{end:x}  ({end - begin} bytes) — {label}")
    f = file_of(begin)
    raw = pe.__data__[f:f + (end - begin)]
    for insn in md.disasm(bytes(raw), image_base + begin):
        rva = insn.address - image_base
        mark = "    <<< ENTRY" if rva == begin else ""
        print(f"  {rva:08x}  {insn.bytes.hex():<24} {insn.mnemonic:<8} {insn.op_str}{annotate(insn)}{mark}")


# Look up the .pdata ranges for the functions we care about
pdata_sec = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".pdata")
pdata = pe.__data__[pdata_sec.PointerToRawData:pdata_sec.PointerToRawData + pdata_sec.SizeOfRawData]
funcs = []
for i in range(len(pdata) // 12):
    b, e, u = struct.unpack_from("<III", pdata, i * 12)
    if b == 0:
        break
    funcs.append((b, e))


def find_func_at_or_around(rva):
    """Return the func range containing rva."""
    for b, e in funcs:
        if b <= rva < e:
            return (b, e)
    return None


for rva, label in [(0x21bba0, "engine logger A (calls _vfprintf_outer)"),
                   (0x21bbf0, "engine logger B (also calls _vfprintf_outer)"),
                   (0x21a8ba, "engine logger C (RA at +0x21a8e1 on stack)"),
                   (0x387700, "around engine.dll+0x387738 (RA on stack)")]:
    f = find_func_at_or_around(rva)
    if f:
        disasm_func(f[0], f[1], label)
    else:
        print(f"No pdata for RVA 0x{rva:x}")
