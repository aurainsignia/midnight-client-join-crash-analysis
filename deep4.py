"""Disassemble tier0+0x1d250 and tier0+0x1c430 to understand the actual
async vs sync dispatch logic, and look at the function containing main
thread's tier0+0x1daff."""
import struct
from pathlib import Path
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

TIER0 = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\tier0.dll")
pe = pefile.PE(str(TIER0), fast_load=False)
image_base = pe.OPTIONAL_HEADER.ImageBase

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

def section_of(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s
    return None

iat = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    d = entry.dll.decode("latin-1")
    for imp in entry.imports:
        name = imp.name.decode("latin-1") if imp.name else f"ord_{imp.ordinal}"
        iat[imp.address - image_base] = (d, name)

def try_string(rva, maxlen=512):
    s = section_of(rva)
    if not s: return None
    raw = pe.__data__[s.PointerToRawData + rva - s.VirtualAddress:
                       s.PointerToRawData + rva - s.VirtualAddress + maxlen]
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
                    elif sname == ".text": annots.append(f"tier0+0x{t:x}")
    if insn.mnemonic in ("call", "jmp"):
        for op in insn.operands:
            if op.type == 2:
                annots.append(f"-> tier0+0x{op.imm - image_base:x}")
    return "  ; " + " ; ".join(annots) if annots else ""


for rva, lbl in [(0x1d250, "actual dispatcher (called by post-work A/B)"),
                 (0x1c430, "prep called inside post-work-item C")]:
    f = find_func(rva)
    if not f:
        print(f"\n#### tier0+0x{rva:x} ({lbl}) — NO PDATA")
        continue
    b, e = f
    print(f"\n#### tier0+0x{b:x}..0x{e:x} ({e-b} bytes) — {lbl}")
    sec = section_of(b)
    raw = pe.__data__[sec.PointerToRawData + b - sec.VirtualAddress:
                       sec.PointerToRawData + b - sec.VirtualAddress + (e - b)]
    for insn in md.disasm(bytes(raw), image_base + b):
        rv = insn.address - image_base
        mark = "    <<< ENTRY" if rv == b else ""
        print(f"  {rv:08x}  {insn.mnemonic:<8} {insn.op_str}{ann(insn)}{mark}")


# Also find the function containing 0x1daff (which is on the main thread's stack)
print(f"\n\n=== Function containing tier0+0x1daff ===")
f = find_func(0x1daff)
print(f"Range: {f}")
if f:
    b, e = f
    print(f"\n#### tier0+0x{b:x}..0x{e:x} ({e-b} bytes)")
    sec = section_of(b)
    raw = pe.__data__[sec.PointerToRawData + b - sec.VirtualAddress:
                       sec.PointerToRawData + b - sec.VirtualAddress + (e - b)]
    for insn in md.disasm(bytes(raw), image_base + b):
        rv = insn.address - image_base
        mark = "    <<< ENTRY" if rv == b else ""
        marker = "    <<< on main thread's stack" if rv == 0x1daff else mark
        print(f"  {rv:08x}  {insn.mnemonic:<8} {insn.op_str}{ann(insn)}{marker}")
        if e - b > 400 and rv > 0x1daff + 0x30:
            break


# Also resolve functions containing all the deep stack RAs of the main thread
print(f"\n\n=== Functions containing main thread tier0 stack RAs ===")
for rva in [0x1dba5, 0x559e0, 0x1daff, 0x45be5, 0x559f8, 0x7cd9, 0x20058, 0x728d0, 0x85b4]:
    f = find_func(rva)
    if f:
        b, e = f
        # Look up exports
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name and b == exp.address:
                expname = exp.name.decode("latin-1")
                break
        else:
            expname = None
        print(f"  tier0+0x{rva:x} in fn 0x{b:x}..0x{e:x}  {'='+expname if expname else ''}")
    else:
        print(f"  tier0+0x{rva:x} — no pdata")
