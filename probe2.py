"""Investigate the global FILE* slot at .data+RVA 0x6c7c20, and find all
references (lea + qword constant) to engine+0x21a890."""
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


def read_at(rva, n):
    s = section_of(rva)
    if not s:
        return None
    return pe.__data__[s.PointerToRawData + rva - s.VirtualAddress:
                       s.PointerToRawData + rva - s.VirtualAddress + n]

# 1) Show the qword stored at .data+0x6c7c20 (the FILE* slot returned by 0xa8170).
ptr_bytes = read_at(0x6c7c20, 64)
print(f"Static contents of engine+0x6c7c20 (the FILE* slot 0xa8170 returns):")
print(f"  {ptr_bytes.hex()}")
qw0 = int.from_bytes(ptr_bytes[0:8], "little")
qw1 = int.from_bytes(ptr_bytes[8:16], "little")
print(f"  qword[0] = 0x{qw0:016x}")
print(f"  qword[1] = 0x{qw1:016x}")

# 2) Now show the surrounding .data layout — engine.dll might keep a small array
# of FILE pointers and constants there.
ctx = read_at(0x6c7b80, 256)
print(f"\nSurrounding .data layout (0x6c7b80 .. 0x6c7c80):")
for i in range(0, 256, 16):
    print(f"  0x6c7b80+0x{i:03x}: " + " ".join(f"{b:02x}" for b in ctx[i:i+16]) + "   " + bytes(c if 0x20 <= c < 0x7f else 0x2e for c in ctx[i:i+16]).decode("latin-1"))


# 3) Hunt for direct references to 0x21a890 — including via lea (relative).
# We need to scan ALL functions and look for `lea rax, [rip+N]` where the
# target RVA equals 0x21a890.
pdata_sec = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".pdata")
pdata = pe.__data__[pdata_sec.PointerToRawData:pdata_sec.PointerToRawData + pdata_sec.SizeOfRawData]
text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
funcs = []
for i in range(len(pdata) // 12):
    b, e, u = struct.unpack_from("<III", pdata, i * 12)
    if b == 0:
        break
    funcs.append((b, e))

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

print("\n=== LEA / relative references to engine+0x21a890 ===")
hits = []
for b, e in funcs:
    if not (text.VirtualAddress <= b < text.VirtualAddress + max(text.Misc_VirtualSize, text.SizeOfRawData)):
        continue
    f = text.PointerToRawData + b - text.VirtualAddress
    raw = pe.__data__[f:f + (e - b)]
    for insn in md.disasm(bytes(raw), image_base + b):
        if insn.mnemonic == "lea" and len(insn.operands) == 2:
            dst, src = insn.operands
            if src.type == 3 and src.mem.base == 41:
                t = insn.address + insn.size + src.mem.disp - image_base
                if t == 0x21a890:
                    reg = insn.reg_name(dst.reg)
                    hits.append((insn.address - image_base, b, reg))

print(f"  found {len(hits)} lea references")
for ra, fn, reg in hits[:20]:
    print(f"    lea {reg}, ... in fn 0x{fn:x} at 0x{ra:x}")
    # Print surrounding bytes & 'lea rcx, "name"' style nearby
    f = text.PointerToRawData + ra - 16 - text.VirtualAddress
    raw = pe.__data__[f:f + 64]
    print("      Context (-16..+48):")
    for ins2 in md.disasm(bytes(raw), image_base + (ra - 16)):
        rva2 = ins2.address - image_base
        ann = ""
        for op in ins2.operands:
            if op.type == 3 and op.mem.base == 41:
                t = ins2.address + ins2.size + op.mem.disp - image_base
                sec = section_of(t)
                if sec:
                    sname = sec.Name.rstrip(b"\x00").decode("latin-1")
                    if sname == ".rdata":
                        # try as ASCII string
                        try:
                            d = pe.get_data(t, 200)
                            end = d.find(b"\x00")
                            if 1 < end < 200 and all(0x20 <= x < 0x7f for x in d[:end]):
                                ann = f'   ; "{d[:end].decode()}"'
                        except Exception:
                            pass
        print(f"        {rva2:08x}  {ins2.mnemonic:<8} {ins2.op_str}{ann}")
