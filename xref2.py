"""
Per-function xref scanner. Iterates engine.dll's .pdata table, disassembles each
function's body, and records every call/jmp target.
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
    0x3500f0: "_output_state_machine",
    0x3529e4: "_write_multi_char",
    0x3647f0: "_putc_nolock",
    0x35f8b8: "_write",
}

text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
pdata_sec = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".pdata")
pdata = pe.__data__[pdata_sec.PointerToRawData:pdata_sec.PointerToRawData + pdata_sec.SizeOfRawData]


def file_of(rva):
    if text.VirtualAddress <= rva < text.VirtualAddress + max(text.Misc_VirtualSize, text.SizeOfRawData):
        return text.PointerToRawData + rva - text.VirtualAddress
    return None


md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False

# Walk pdata
xrefs = {t: [] for t in TARGETS}
n = len(pdata) // 12
for i in range(n):
    begin, end, unwind = struct.unpack_from("<III", pdata, i * 12)
    if begin == 0:
        break
    f = file_of(begin)
    if f is None:
        continue
    raw = pe.__data__[f:f + (end - begin)]
    for insn in md.disasm(bytes(raw), image_base + begin):
        if insn.mnemonic in ("call", "jmp"):
            s = insn.op_str.strip()
            if s.startswith("0x"):
                try:
                    tgt = int(s, 16) - image_base
                    if tgt in TARGETS:
                        xrefs[tgt].append((insn.address - image_base, begin))
                except ValueError:
                    pass

for t, name in TARGETS.items():
    print(f"\n#### CALLERS of engine.dll+0x{t:x} ({name}):  ({len(xrefs[t])} sites)")
    for ra, fn in xrefs[t][:50]:
        print(f"   call/jmp at engine.dll+0x{ra:x}  (inside func 0x{fn:x})")
