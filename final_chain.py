"""Disassemble tier0+0x1db20 (the function the main thread is currently inside)
and tier0+0x45bd0 (the function that called tier0+0x1dac0). Also identify
filesystem_stdio.dll's functions where the main thread is blocked."""
import struct
from pathlib import Path
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

TIER0 = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\tier0.dll")
FSSTDIO = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\filesystem_stdio.dll")

def disasm_func_in_dll(dll_path, rva, label, dll_label):
    pe = pefile.PE(str(dll_path), fast_load=False)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    pdata_sec = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".pdata")
    pdata = pe.__data__[pdata_sec.PointerToRawData:pdata_sec.PointerToRawData + pdata_sec.SizeOfRawData]
    funcs = []
    for i in range(len(pdata) // 12):
        b, e, u = struct.unpack_from("<III", pdata, i * 12)
        if b == 0: break
        funcs.append((b, e))

    def find_func(r):
        for b, e in funcs:
            if b <= r < e: return (b, e)
        return None

    def section_of(r):
        for s in pe.sections:
            if s.VirtualAddress <= r < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
                return s
        return None

    iat = {}
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        d = entry.dll.decode("latin-1")
        for imp in entry.imports:
            name = imp.name.decode("latin-1") if imp.name else f"ord_{imp.ordinal}"
            iat[imp.address - image_base] = (d, name)

    def try_string(r, maxlen=512):
        s = section_of(r)
        if not s: return None
        raw = pe.__data__[s.PointerToRawData + r - s.VirtualAddress:
                           s.PointerToRawData + r - s.VirtualAddress + maxlen]
        end = raw.find(b"\x00")
        if end < 1 or end > maxlen - 1: return None
        sub = raw[:end]
        if all(0x20 <= c < 0x7f or c in (9, 10, 13) for c in sub):
            return sub.decode("ascii")
        return None

    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True

    def ann(insn):
        annots = []
        for op in insn.operands:
            if op.type == 3 and op.mem.base == 41:
                t = insn.address + insn.size + op.mem.disp - image_base
                if t in iat:
                    annots.append(f"-> {iat[t][1]} ({iat[t][0]})")
                else:
                    sec = section_of(t)
                    if sec:
                        sname = sec.Name.rstrip(b"\x00").decode("latin-1")
                        if sname == ".rdata":
                            s = try_string(t)
                            if s: annots.append(f'"{s[:140]}"')
                            else: annots.append(f".rdata+0x{t:x}")
                        elif sname == ".data": annots.append(f".data+0x{t:x}")
                        elif sname == ".text": annots.append(f"{dll_label}+0x{t:x}")
        if insn.mnemonic in ("call", "jmp"):
            for op in insn.operands:
                if op.type == 2:
                    annots.append(f"-> {dll_label}+0x{op.imm - image_base:x}")
        return "  ; " + " ; ".join(annots) if annots else ""

    f = find_func(rva)
    if not f:
        print(f"\n#### {dll_label}+0x{rva:x} ({label}) — NO PDATA")
        return
    b, e = f
    print(f"\n#### {dll_label}+0x{b:x}..0x{e:x} ({e-b} bytes) — {label}")
    sec = section_of(b)
    raw = pe.__data__[sec.PointerToRawData + b - sec.VirtualAddress:
                       sec.PointerToRawData + b - sec.VirtualAddress + (e - b)]
    for insn in md.disasm(bytes(raw), image_base + b):
        rv = insn.address - image_base
        mark = "    <<< ENTRY" if rv == b else ""
        print(f"  {rv:08x}  {insn.mnemonic:<8} {insn.op_str}{ann(insn)}{mark}")


# Tier0 functions
disasm_func_in_dll(TIER0, 0x1db20, "tier0+0x1db20 (main thread is inside, before filesystem)", "tier0")
disasm_func_in_dll(TIER0, 0x45bd0, "tier0+0x45bd0 (caller of 0x1dac0)", "tier0")
disasm_func_in_dll(TIER0, 0x1dbf0, "tier0+0x1dbf0 (tail-target from 0x1dac0)", "tier0")
disasm_func_in_dll(TIER0, 0x7c90, "tier0+0x7c90 (the function wrapped by Dump_CallWinMainFunction)", "tier0")

# Filesystem_stdio functions on the main thread chain
disasm_func_in_dll(FSSTDIO, 0x89137, "filesystem_stdio+0x89137 (top of fs chain — calls WaitForSingleObject)", "filesystem_stdio")
disasm_func_in_dll(FSSTDIO, 0x8565d, "filesystem_stdio+0x8565d", "filesystem_stdio")
disasm_func_in_dll(FSSTDIO, 0x91b9d, "filesystem_stdio+0x91b9d", "filesystem_stdio")
disasm_func_in_dll(FSSTDIO, 0x9224d, "filesystem_stdio+0x9224d", "filesystem_stdio")
disasm_func_in_dll(FSSTDIO, 0xa3d9c, "filesystem_stdio+0xa3d9c", "filesystem_stdio")
