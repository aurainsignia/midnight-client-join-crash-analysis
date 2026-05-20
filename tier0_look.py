"""Identify what's at tier0.dll+0x7fed (the upstream caller of engine+0x21a890)."""
import struct
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DLL = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\tier0.dll")
pe = pefile.PE(str(DLL), fast_load=False)
image_base = pe.OPTIONAL_HEADER.ImageBase
print(f"tier0.dll image base: 0x{image_base:x}")

def section_of(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s
    return None

def read_at(rva, n):
    s = section_of(rva)
    if not s:
        return None
    return pe.__data__[s.PointerToRawData + (rva - s.VirtualAddress):
                       s.PointerToRawData + (rva - s.VirtualAddress) + n]

def try_string(rva, maxlen=256):
    raw = read_at(rva, maxlen)
    if not raw: return None
    end = raw.find(b"\x00")
    if end < 2: return None
    sub = raw[:end]
    if all(0x20 <= c < 0x7f or c in (9, 10, 13) for c in sub):
        return sub.decode("ascii")
    return None

# Build IAT name table
iat_by_rva = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode("latin-1")
    for imp in entry.imports:
        name = imp.name.decode("latin-1") if imp.name else f"ord_{imp.ordinal}"
        iat_by_rva[imp.address - image_base] = (dll, name)

# .pdata for function containing 0x7fed
pdata_sec = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".pdata")
pdata = pe.__data__[pdata_sec.PointerToRawData:pdata_sec.PointerToRawData + pdata_sec.SizeOfRawData]
fn = None
for i in range(len(pdata) // 12):
    b, e, u = struct.unpack_from("<III", pdata, i * 12)
    if b == 0: break
    if b <= 0x7fed < e:
        fn = (b, e)
        break

if not fn:
    print("No pdata entry for tier0+0x7fed")
else:
    b, e = fn
    print(f"Function containing tier0+0x7fed: 0x{b:x}..0x{e:x}  ({e-b} bytes)")

md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
def annotate(insn):
    annots = []
    for op in insn.operands:
        if op.type == 3 and op.mem.base == 41:
            t = insn.address + insn.size + op.mem.disp - image_base
            sec = section_of(t)
            if sec:
                sname = sec.Name.rstrip(b"\x00").decode("latin-1")
                if t in iat_by_rva:
                    annots.append(f"-> {iat_by_rva[t][1]} ({iat_by_rva[t][0]})")
                elif sname == ".rdata":
                    s = try_string(t)
                    if s:
                        annots.append(f'"{s[:120]}"')
                    else:
                        annots.append(f".rdata+0x{t:x}")
                elif sname == ".data":
                    annots.append(f".data+0x{t:x}")
    if insn.mnemonic in ("call", "jmp"):
        for op in insn.operands:
            if op.type == 2:
                annots.append(f"-> tier0+0x{op.imm - image_base:x}")
    return "  ; " + " ; ".join(annots) if annots else ""

if fn:
    raw = read_at(b, e - b)
    print()
    for insn in md.disasm(bytes(raw), image_base + b):
        rva = insn.address - image_base
        mark = "    <<< ENTRY" if rva == b else ""
        if rva == 0x7fed:
            mark = "    <<< STACK RA"
        print(f"  {rva:08x}  {insn.bytes.hex():<22} {insn.mnemonic:<8} {insn.op_str}{annotate(insn)}{mark}")
