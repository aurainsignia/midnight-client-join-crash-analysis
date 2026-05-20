"""
Find all direct CALL/JMP references to specific RVAs in engine.dll .text.
Goal: locate every engine.dll function that calls _vfprintf_outer (0x352ab4),
which would be engine's printf wrapper.
"""
import struct
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DLL = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\engine.dll")
pe = pefile.PE(str(DLL), fast_load=False)
image_base = pe.OPTIONAL_HEADER.ImageBase

TARGETS = {
    0x352ab4: "_vfprintf_outer",
    0x34df10: "vfprintf_lockwrapper",
    0x34fe48: "_vfprintf_internal",
    0x350f68: "_output_specifier",
}

text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
text_data = pe.__data__[text.PointerToRawData:text.PointerToRawData + text.SizeOfRawData]

# Linear scan with capstone over .text
md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# We need to disasm .text sequentially. Some CRT-aligned regions may produce
# bad disasm; we accept some noise.
xrefs = {t: [] for t in TARGETS}

start_va = image_base + text.VirtualAddress
print(f"Scanning .text {text.VirtualAddress:08x}..{text.VirtualAddress+len(text_data):08x} (capstone)...")
# To speed up, use detail-light pass and only check call/jmp/jcond imm
md2 = Cs(CS_ARCH_X86, CS_MODE_64)
md2.detail = False
for insn in md2.disasm(bytes(text_data), start_va):
    if insn.mnemonic in ("call", "jmp"):
        # parse op_str like "0x18033b4bc"
        s = insn.op_str.strip()
        if s.startswith("0x"):
            try:
                tgt = int(s, 16) - image_base
                if tgt in TARGETS:
                    xrefs[tgt].append(insn.address - image_base)
            except ValueError:
                pass

for t, name in TARGETS.items():
    print(f"\n#### CALLERS of engine.dll+0x{t:x} ({name}):  ({len(xrefs[t])} sites)")
    for ra in xrefs[t][:50]:
        print(f"   call/jmp at engine.dll+0x{ra:x}")
