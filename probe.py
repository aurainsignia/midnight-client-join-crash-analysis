"""Probe what's at engine+0xa8170 and find references to engine+0x21a890 in .data
(to identify the ConCommand registration for condump)."""
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
    f = s.PointerToRawData + rva - s.VirtualAddress
    return pe.__data__[f:f + n]


md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# 1) Disassemble at 0xa8170 raw
print("=== Raw disasm at 0xa8170 (probably a thunk) ===")
raw = read_at(0xa8170, 32)
for insn in md.disasm(bytes(raw), image_base + 0xa8170):
    print(f"  {insn.address - image_base:08x}  {insn.bytes.hex():<22} {insn.mnemonic:<8} {insn.op_str}")
    if insn.mnemonic == "ret":
        break

# 2) Find references to 0x21a890 from .data — for ConCommand callback registration.
# In x64, a pointer to 0x21a890 stored in .data would be the literal qword
# 0x000000018021a890.
print("\n=== Search engine.dll for QWORD pointers to 0x21a890 (ConCommand callback) ===")
target_va = image_base + 0x21a890
target_bytes = struct.pack("<Q", target_va)
data_sec = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".data")
data_blob = pe.__data__[data_sec.PointerToRawData:data_sec.PointerToRawData + data_sec.SizeOfRawData]
off = 0
hits = []
while True:
    i = data_blob.find(target_bytes, off)
    if i < 0:
        break
    rva = data_sec.VirtualAddress + i
    hits.append(rva)
    off = i + 1
print(f"  found {len(hits)} 8-byte hits in .data:")
for rva in hits[:20]:
    print(f"    .data+0x{rva - data_sec.VirtualAddress:x} (RVA 0x{rva:x})")
    # Dump 96 bytes around for context — ConCommand vtable+state layout
    ctx = read_at(rva - 16, 96)
    if ctx:
        print(f"      bytes-16..+80: {ctx.hex()}")

# 3) Also try matching pointer in .rdata (might be in a constructor list)
rdata_sec = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".rdata")
rdata_blob = pe.__data__[rdata_sec.PointerToRawData:rdata_sec.PointerToRawData + rdata_sec.SizeOfRawData]
off = 0
hits_r = []
while True:
    i = rdata_blob.find(target_bytes, off)
    if i < 0:
        break
    hits_r.append(rdata_sec.VirtualAddress + i)
    off = i + 1
print(f"\n  found {len(hits_r)} 8-byte hits in .rdata:")
for rva in hits_r[:10]:
    print(f"    .rdata+0x{rva - rdata_sec.VirtualAddress:x} (RVA 0x{rva:x})")

# 4) Search for the literal "condump" string in .rdata; that gives us the
# command name registration tied to the callback.
print("\n=== Search for 'condump' literal in .rdata ===")
for needle in (b"condump\x00", b"Condump\x00", b"con_dump\x00", b"CONDUMP\x00"):
    i = rdata_blob.find(needle)
    if i >= 0:
        rva = rdata_sec.VirtualAddress + i
        print(f"  found {needle!r} at .rdata+0x{i:x}  RVA 0x{rva:x}")
        # Also search for a pointer to this string in .data
        ptr_va = image_base + rva
        ptr_bytes = struct.pack("<Q", ptr_va)
        j = data_blob.find(ptr_bytes)
        if j >= 0:
            print(f"     ptr-to-string referenced from .data+0x{j:x} (RVA 0x{data_sec.VirtualAddress + j:x})")
            ctx = read_at(data_sec.VirtualAddress + j - 32, 128)
            if ctx:
                print(f"     surrounding bytes (-32..+96): {ctx.hex()}")
