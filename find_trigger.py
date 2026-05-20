"""Find who calls the high-level crash-report entry points (0x80c0/0x8270/0x8430/0x85f0)
and the worker-thread-init (0x1d408). Also look at engine.dll's calls into tier0."""
import struct
from pathlib import Path
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

TIER0 = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\tier0.dll")
ENGINE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\engine.dll")
LUA = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\lua_shared.dll")

def scan_xrefs(dll, targets, label):
    pe = pefile.PE(str(dll), fast_load=False)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    pdata_sec = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".pdata")
    pdata = pe.__data__[pdata_sec.PointerToRawData:pdata_sec.PointerToRawData + pdata_sec.SizeOfRawData]
    funcs = []
    for i in range(len(pdata) // 12):
        b, e, u = struct.unpack_from("<III", pdata, i * 12)
        if b == 0: break
        funcs.append((b, e))
    text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")

    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
    md.skipdata = True

    results = {t: [] for t in targets}
    iat_thunks = {}  # thunk_rva -> name
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        d = entry.dll.decode("latin-1")
        for imp in entry.imports:
            name = imp.name.decode("latin-1") if imp.name else f"ord_{imp.ordinal}"
            iat_thunks[imp.address - image_base] = (d, name)

    for b, e in funcs:
        # skip if not in .text
        if not (text.VirtualAddress <= b < text.VirtualAddress + max(text.Misc_VirtualSize, text.SizeOfRawData)):
            continue
        f = text.PointerToRawData + b - text.VirtualAddress
        raw = pe.__data__[f:f + (e - b)]
        for insn in md.disasm(bytes(raw), image_base + b):
            rva = insn.address - image_base
            if insn.mnemonic in ("call", "jmp") and len(insn.operands) == 1:
                op = insn.operands[0]
                if op.type == 2:
                    t = op.imm - image_base
                    if t in targets:
                        results[t].append((rva, b, "call"))
            if insn.mnemonic == "lea" and len(insn.operands) == 2:
                src = insn.operands[1]
                if src.type == 3 and src.mem.base == 41:
                    t = insn.address + insn.size + src.mem.disp - image_base
                    if t in targets:
                        results[t].append((rva, b, "lea"))

    print(f"\n=== {label}: xrefs to specified RVAs ===")
    for t in targets:
        descr = targets[t]
        print(f"\n  -- 0x{t:x} ({descr}) -- {len(results[t])} hits")
        for rva, fn, kind in results[t][:15]:
            print(f"     {kind} at 0x{rva:x} in fn 0x{fn:x}")
    return results

# In tier0 — find who calls the high-level entry points and the init
TIER0_TARGETS = {
    0x80c0: "crash-report-writer entry A",
    0x8270: "crash-report-writer entry B",
    0x8430: "crash-report-writer entry C",
    0x85f0: "crash-report-writer entry D",
    0x1d408: "crash handler init",
    0x1c530: "post-work-item function A",
    0x1c340: "post-work-item function B",
    0x1d8a0: "post-work-item function C (called from entry D)",
}
scan_xrefs(TIER0, TIER0_TARGETS, "tier0.dll")


# Now check engine.dll — its imports from tier0 might call these
print("\n\n=== Engine.dll imports from tier0_s64.dll / tier0.dll ===")
pe_e = pefile.PE(str(ENGINE), fast_load=False)
for entry in pe_e.DIRECTORY_ENTRY_IMPORT:
    d = entry.dll.decode("latin-1").lower()
    if "tier0" in d:
        for imp in entry.imports:
            name = imp.name.decode("latin-1") if imp.name else f"ord_{imp.ordinal}"
            print(f"  {d}: {name}")


# And look at lua_shared.dll+0x14c50 (the Lua dumper)
print("\n\n========== lua_shared.dll +0x14c50 (Lua state dumper, slot[0]) ==========")
pe_l = pefile.PE(str(LUA), fast_load=False)
image_base = pe_l.OPTIONAL_HEADER.ImageBase
pdata_sec = next(s for s in pe_l.sections if s.Name.rstrip(b"\x00") == b".pdata")
pdata = pe_l.__data__[pdata_sec.PointerToRawData:pdata_sec.PointerToRawData + pdata_sec.SizeOfRawData]
funcs = []
for i in range(len(pdata) // 12):
    b, e, u = struct.unpack_from("<III", pdata, i * 12)
    if b == 0: break
    funcs.append((b, e))

def find_func(rva):
    for b, e in funcs:
        if b <= rva < e: return (b, e)
    return None

f = find_func(0x14c50)
print(f"function: {f}")
if f:
    b, e = f
    sec = next(s for s in pe_l.sections if s.Name.rstrip(b"\x00") == b".text")
    raw = pe_l.__data__[sec.PointerToRawData + b - sec.VirtualAddress:
                         sec.PointerToRawData + b - sec.VirtualAddress + (e - b)]
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
    # Build IAT
    iat = {}
    for entry in pe_l.DIRECTORY_ENTRY_IMPORT:
        d = entry.dll.decode("latin-1")
        for imp in entry.imports:
            name = imp.name.decode("latin-1") if imp.name else f"ord_{imp.ordinal}"
            iat[imp.address - image_base] = (d, name)

    def section_of(rva):
        for s in pe_l.sections:
            if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
                return s
        return None

    def try_string(rva, maxlen=512):
        s = section_of(rva)
        if not s: return None
        raw = pe_l.__data__[s.PointerToRawData + rva - s.VirtualAddress:
                            s.PointerToRawData + rva - s.VirtualAddress + maxlen]
        end = raw.find(b"\x00")
        if end < 1 or end > maxlen - 1: return None
        sub = raw[:end]
        if all(0x20 <= c < 0x7f or c in (9, 10, 13) for c in sub):
            return sub.decode("ascii")
        return None

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
                        elif sname == ".text": annots.append(f"+0x{t:x}")
        if insn.mnemonic in ("call", "jmp"):
            for op in insn.operands:
                if op.type == 2:
                    annots.append(f"-> lua_shared+0x{op.imm - image_base:x}")
        return "  ; " + " ; ".join(annots) if annots else ""

    print(f"#### lua_shared+0x{b:x}..0x{e:x} ({e-b} bytes)")
    for insn in md.disasm(bytes(raw), image_base + b):
        rv = insn.address - image_base
        mark = "    <<< ENTRY" if rv == b else ""
        print(f"  {rv:08x}  {insn.mnemonic:<8} {insn.op_str}{ann(insn)}{mark}")
