"""Disassemble function 0x21b110 in full and report all string xrefs.
This function registers 0x21a890 as a console command callback — its body
contains the command name."""
import struct
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DLL = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\engine.dll")
pe = pefile.PE(str(DLL), fast_load=False)
image_base = pe.OPTIONAL_HEADER.ImageBase


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


pdata_sec = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".pdata")
pdata = pe.__data__[pdata_sec.PointerToRawData:pdata_sec.PointerToRawData + pdata_sec.SizeOfRawData]
funcs = []
for i in range(len(pdata) // 12):
    b, e, u = struct.unpack_from("<III", pdata, i * 12)
    if b == 0:
        break
    funcs.append((b, e))


def find_func_containing(rva):
    for b, e in funcs:
        if b <= rva < e:
            return (b, e)
    return None


md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


# Find the .pdata entry covering 0x21b110 (might start at a slightly different addr)
fn = find_func_containing(0x21b110)
print(f"Function containing 0x21b110: {fn}")
if fn:
    b, e = fn
    f = file_of(b)
    raw = pe.__data__[f:f + (e - b)]
    print(f"\n=== Function 0x{b:x}..0x{e:x} ({e - b} bytes) ===")
    for insn in md.disasm(bytes(raw), image_base + b):
        rva = insn.address - image_base
        annot = ""
        if insn.mnemonic in ("lea", "mov", "cmp", "push") and len(insn.operands) >= 1:
            for op in insn.operands:
                if op.type == 3 and op.mem.base == 41:
                    t = insn.address + insn.size + op.mem.disp - image_base
                    sec = section_of(t)
                    if sec:
                        sname = sec.Name.rstrip(b"\x00").decode("latin-1")
                        if sname == ".rdata":
                            s = try_string(t)
                            if s:
                                annot += f'  ; "{s[:120]}"'
                            else:
                                annot += f"  ; .rdata+0x{t:x}"
                        elif sname == ".data":
                            annot += f"  ; .data+0x{t:x}"
                        elif sname == ".text":
                            annot += f"  ; engine+0x{t:x}"
        if insn.mnemonic in ("call", "jmp"):
            for op in insn.operands:
                if op.type == 2:
                    annot += f"  ; -> engine+0x{op.imm - image_base:x}"
                elif op.type == 3 and op.mem.base == 41:
                    t = insn.address + insn.size + op.mem.disp - image_base
                    annot += f"  ; -> [engine+0x{t:x}]"
        print(f"  {rva:08x}  {insn.bytes.hex():<22} {insn.mnemonic:<8} {insn.op_str}{annot}")
