"""Disassemble the functions that LEA tier0+0x7ef0 (the crash-report writer):
0x80c0, 0x8270, 0x8430, 0x85f0, and 0x1d408 (worker thread creator).
Also disassemble lua_shared.dll+0x14c50 (the Lua dumper)."""
import struct
from pathlib import Path
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

TIER0 = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\tier0.dll")
LUA_SHARED = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\lua_shared.dll")

def disasm_pe(dll, funcs_to_dump, label):
    pe = pefile.PE(str(dll), fast_load=False)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    print(f"\n========== {label} (image_base 0x{image_base:x}) ==========")

    pdata_sec = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".pdata")
    pdata = pe.__data__[pdata_sec.PointerToRawData:pdata_sec.PointerToRawData + pdata_sec.SizeOfRawData]
    funcs = []
    for i in range(len(pdata) // 12):
        b, e, u = struct.unpack_from("<III", pdata, i * 12)
        if b == 0: break
        funcs.append((b, e))

    def find_func(rva):
        for b, e in funcs:
            if b <= rva < e: return (b, e)
        return None

    iat_by_rva = {}
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        d = entry.dll.decode("latin-1")
        for imp in entry.imports:
            name = imp.name.decode("latin-1") if imp.name else f"ord_{imp.ordinal}"
            iat_by_rva[imp.address - image_base] = (d, name)

    def section_of(rva):
        for s in pe.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
                return s
        return None

    def try_string(rva, maxlen=512):
        s = section_of(rva)
        if not s: return None
        raw = pe.__data__[s.PointerToRawData + rva - s.VirtualAddress:
                           s.PointerToRawData + rva - s.VirtualAddress + maxlen]
        end = raw.find(b"\x00")
        if end < 1 or end > maxlen-1: return None
        sub = raw[:end]
        if all(0x20 <= c < 0x7f or c in (9, 10, 13) for c in sub):
            return sub.decode("ascii")
        if end >= 4 and raw[1] == 0 and raw[3] == 0:
            # wide string
            end16 = 0
            while end16+1 < len(raw):
                if raw[end16] == 0 and raw[end16+1] == 0: break
                end16 += 2
            if 4 <= end16 <= 510:
                try: return 'L"' + raw[:end16].decode("utf-16le") + '"'
                except: pass
        return None

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
                        if s: annots.append(f'"{s[:140]}"')
                        else: annots.append(f".rdata+0x{t:x}")
                    elif sname == ".data": annots.append(f".data+0x{t:x}")
                    elif sname == ".text": annots.append(f"+0x{t:x}")
        if insn.mnemonic in ("call", "jmp"):
            for op in insn.operands:
                if op.type == 2:
                    annots.append(f"-> +0x{op.imm - image_base:x}")
        return "  ; " + " ; ".join(annots) if annots else ""

    for rva, descr in funcs_to_dump:
        f = find_func(rva)
        if not f:
            print(f"\n#### +0x{rva:x} ({descr}) — NO PDATA ENTRY")
            continue
        b, e = f
        print(f"\n#### +0x{b:x}..0x{e:x} ({e-b} bytes) — {descr}")
        sec = section_of(b)
        if not sec:
            print("  no section")
            continue
        raw = pe.__data__[sec.PointerToRawData + b - sec.VirtualAddress:
                           sec.PointerToRawData + b - sec.VirtualAddress + (e - b)]
        for insn in md.disasm(bytes(raw), image_base + b):
            rv = insn.address - image_base
            mark = "    <<< ENTRY" if rv == b else ""
            print(f"  {rv:08x}  {insn.mnemonic:<8} {insn.op_str}{annotate(insn)}{mark}")


# Tier0 functions
TIER0_TARGETS = [
    (0x80c0, "Installer A — has 2 LEAs to crash-report-writer (0x7ef0)"),
    (0x8270, "Installer B — has 2 LEAs to crash-report-writer"),
    (0x8430, "Installer C — has 2 LEAs"),
    (0x85f0, "Installer D — 1 LEA via rdx"),
    (0x1d408, "Worker thread creator (has 1 LEA to 0x1c950)"),
]
disasm_pe(TIER0, TIER0_TARGETS, "tier0.dll")


# Lua_shared callback that runs first
LUA_TARGETS = [
    (0x14c50, "Lua state dumper callback (slot[0] in tier0 table)"),
]
disasm_pe(LUA_SHARED, LUA_TARGETS, "lua_shared.dll")
