"""
Disassemble the full bodies of specific functions identified via .pdata,
with rich annotations:
  - resolve CALL/JMP targets to imports (CRT, kernel32, etc.)
  - resolve RIP-relative LEA/MOV references that hit .rdata as printable strings
  - annotate the crash RA / stack chain RAs

Functions of interest (engine.dll RVA ranges):
  0x33b4bc..0x33b573   "CRT _invalid_parameter / fastfail wrapper" (callee)
  0x35f8b8..0x35f9d5   direct caller of _invalid_parameter
  0x3647f0..0x3648e7   next up (called twice in chain)
  0x364970..0x364a3b   next up
  0x3529e4..0x352ab3
  0x350f68..0x3514a0   LARGE 1336-byte function with EH+UHANDLER
  0x34fe48..0x34ff64   biggest stack frame (0x4a0 bytes)
  0x34df10..0x34df4d   tiny (61 bytes)
  0x3500f0..0x350471
  0x34da04..0x34da9f
  0x352ab4..0x352bd8
"""

import sys
import struct
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DLL = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\engine.dll")
pe = pefile.PE(str(DLL), fast_load=False)
image_base = pe.OPTIONAL_HEADER.ImageBase

FUNCS = [
    (0x33b4bc, 0x33b573, "CRT _invalid_parameter+__fastfail dispatcher"),
    (0x35f8b8, 0x35f9d5, "direct caller of _invalid_parameter (RA inside @ +0x35f958)"),
    (0x3647f0, 0x3648e7, "RA @ +0x364815 & +0x364851"),
    (0x364970, 0x364a3b, "RA @ +0x364a1f"),
    (0x3529e4, 0x352ab3, "RA @ +0x352a43"),
    (0x350f68, 0x3514a0, "LARGE 1336B fn, RA @ +0x351403, EH+UHANDLER"),
    (0x34fe48, 0x34ff64, "BIG FRAME 0x4a0 bytes, RA @ +0x34ff12, EH+UHANDLER"),
    (0x34df10, 0x34df4d, "tiny 61B, RA @ +0x34df36, UHANDLER"),
    (0x3500f0, 0x350471, "RA @ +0x350215"),
    (0x34da04, 0x34da9f, "RA @ +0x34da1c"),
    (0x352ab4, 0x352bd8, "RA @ +0x352b8e"),
]

STACK_RAS = {0x33b572, 0x35f958, 0x364851, 0x364a1f, 0xdd006e, 0x352a43,
             0x422c40, 0x351403, 0x364815, 0x34da1c, 0x350215, 0x34ff12,
             0x387738, 0x38773a, 0x34df36, 0x352b8e, 0x21bbdc, 0x21a8e1,
             0x33b5dc}

# Build IAT name table by both IAT slot RVA and thunk addresses
iat_by_rva = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode("latin-1")
    for imp in entry.imports:
        name = imp.name.decode("latin-1") if imp.name else f"ord_{imp.ordinal}"
        iat_by_rva[imp.address - image_base] = (dll, name)


def section_of(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s
    return None


def file_of(rva):
    s = section_of(rva)
    if not s:
        return None
    return s.PointerToRawData + rva - s.VirtualAddress


def read_at(rva, n):
    f = file_of(rva)
    if f is None:
        return None
    return pe.__data__[f:f + n]


def try_string(rva, maxlen=256):
    raw = read_at(rva, maxlen)
    if not raw:
        return None
    end = raw.find(b"\x00")
    if end < 2 or end > 255:
        return None
    sub = raw[:end]
    if all(0x20 <= b < 0x7f or b in (9, 10, 13) for b in sub):
        return sub.decode("ascii", errors="replace")
    # try UTF-16
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


def thunk_target(rva):
    """If the 6 bytes at this RVA encode `jmp qword ptr [rip+disp32]`, return
    the IAT name. Else None."""
    raw = read_at(rva, 6)
    if raw and len(raw) == 6 and raw[0] == 0xff and raw[1] == 0x25:
        disp = struct.unpack("<i", raw[2:6])[0]
        target = rva + 6 + disp
        if target in iat_by_rva:
            return iat_by_rva[target]
    return None


def annotate(insn):
    annots = []
    # call/jmp target resolution
    if insn.mnemonic in ("call", "jmp"):
        if len(insn.operands) == 1:
            op = insn.operands[0]
            if op.type == 2:  # IMM
                target = op.imm - image_base
                t = thunk_target(target)
                if t:
                    annots.append(f"-> {t[1]} ({t[0]}) [thunk]")
                else:
                    annots.append(f"-> engine.dll+0x{target:x}")
            elif op.type == 3 and op.mem.base == 41:  # RIP-rel
                tgt = insn.address + insn.size + op.mem.disp - image_base
                if tgt in iat_by_rva:
                    annots.append(f"-> {iat_by_rva[tgt][1]} ({iat_by_rva[tgt][0]})")
                else:
                    annots.append(f"-> [engine.dll+0x{tgt:x}]")
    # RIP-rel data reference -> string?
    if insn.mnemonic in ("lea", "mov", "cmp"):
        for op in insn.operands:
            if op.type == 3 and op.mem.base == 41:
                tgt = insn.address + insn.size + op.mem.disp - image_base
                sec = section_of(tgt)
                if sec is not None:
                    sname = sec.Name.rstrip(b"\x00").decode("latin-1")
                    if sname in (".rdata", ".data"):
                        s = try_string(tgt)
                        if s:
                            annots.append(f'"{s[:120]}"')
    return "  ; " + " ; ".join(annots) if annots else ""


def disasm_func(begin, end, label):
    print(f"\n#### Function 0x{begin:x}..0x{end:x}  ({end - begin} bytes) — {label}")
    f = file_of(begin)
    raw = pe.__data__[f:f + (end - begin)]
    for insn in md.disasm(bytes(raw), image_base + begin):
        rva = insn.address - image_base
        mark = ""
        if rva in STACK_RAS:
            mark = "    <<< STACK RA"
        if rva == 0x33b5dc:
            mark = "    <<< CRASH RIP (int 29h)"
        if rva == begin:
            mark = "    <<< ENTRY"
        print(f"  {rva:08x}  {insn.bytes.hex():<22} {insn.mnemonic:<8} {insn.op_str}{annotate(insn)}{mark}")


for begin, end, label in FUNCS:
    disasm_func(begin, end, label)
