"""Find who queues tier0+0x7ef0 to the worker thread, and read the runtime
callback table at tier0+0x61ef0 (where relocations are applied)."""
import struct
from pathlib import Path
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DMP = Path(r"C:\Users\Chris\Desktop\dubiousnet\bugs\gmod client crash on third party zs server 2026-05-19\gmod.exe.29108.dmp")
TIER0 = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\tier0.dll")
dmp = DMP.read_bytes()

# Streams
sig, ver, n_streams, dir_rva = struct.unpack_from("<IIII", dmp, 0)
streams = {}
for i in range(n_streams):
    off = dir_rva + i * 12
    stype, sz, srva = struct.unpack_from("<III", dmp, off)
    streams.setdefault(stype, []).append((sz, srva))

modules = {}
for sz, srva in streams.get(4, []):
    n_mods = struct.unpack_from("<I", dmp, srva)[0]
    off = srva + 4
    for _ in range(n_mods):
        base, size_img, _csum, _ts, name_rva = struct.unpack_from("<QIIII", dmp, off)
        slen = struct.unpack_from("<I", dmp, name_rva)[0]
        name = dmp[name_rva + 4:name_rva + 4 + slen].decode("utf-16-le", errors="replace")
        modules[name.split("\\")[-1].lower()] = (base, size_img)
        off += 108
TIER0_BASE = modules["tier0.dll"][0]
ENGINE_BASE = modules["engine.dll"][0]

mem_idx = []
for sz, srva in streams.get(9, []):
    n_ranges, base_rva = struct.unpack_from("<QQ", dmp, srva)
    cursor = base_rva
    for i in range(n_ranges):
        start, size = struct.unpack_from("<QQ", dmp, srva + 16 + i * 16)
        mem_idx.append((start, start + size, cursor))
        cursor += size
for sz, srva in streams.get(5, []):
    n_ranges = struct.unpack_from("<I", dmp, srva)[0]
    for i in range(n_ranges):
        off = srva + 4 + i * 16
        start, dsize, drva = struct.unpack_from("<QII", dmp, off)
        mem_idx.append((start, start + dsize, drva))
mem_idx.sort()

def read_va(va, n):
    for s, e, fo in mem_idx:
        if s <= va and va + n <= e:
            return dmp[fo + (va - s):fo + (va - s) + n]
        if s <= va < e:
            avail = e - va
            return dmp[fo + (va - s):fo + (va - s) + avail]
    return None

def vname(va):
    for nm, (b, sz) in modules.items():
        if b <= va < b + sz:
            return f"{nm}+0x{va-b:x}"
    return None


# Read the runtime callback table at tier0+0x61ef0
print("=== Runtime callback table at tier0+0x61ef0 (16 slots, relocations applied) ===")
table_va = TIER0_BASE + 0x61ef0
for i in range(16):
    addr = table_va + i * 8
    b = read_va(addr, 8)
    if b:
        v = struct.unpack("<Q", b)[0]
        ann = vname(v) or ""
        print(f"  slot[{i:2}] @ 0x{addr:016x} = 0x{v:016x}  {ann}")
    else:
        print(f"  slot[{i:2}] @ 0x{addr:016x} = (not in dump)")


# Find xrefs to tier0+0x7ef0 in tier0.dll (both call AND lea references)
pe = pefile.PE(str(TIER0), fast_load=False)
image_base = pe.OPTIONAL_HEADER.ImageBase

text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
pdata_sec = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".pdata")
pdata = pe.__data__[pdata_sec.PointerToRawData:pdata_sec.PointerToRawData + pdata_sec.SizeOfRawData]
funcs = []
for i in range(len(pdata) // 12):
    b, e, u = struct.unpack_from("<III", pdata, i * 12)
    if b == 0: break
    funcs.append((b, e))


def file_of(rva):
    if text.VirtualAddress <= rva < text.VirtualAddress + max(text.Misc_VirtualSize, text.SizeOfRawData):
        return text.PointerToRawData + rva - text.VirtualAddress
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s.PointerToRawData + rva - s.VirtualAddress
    return None

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
    return None

md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
md_quick = Cs(CS_ARCH_X86, CS_MODE_64); md_quick.detail = False

TARGETS = {0x7ef0: "tier0+0x7ef0 (CRASH-REPORT-WRITER)",
           0x1c950: "tier0+0x1c950 (WORKER THREAD MAIN)"}

print("\n=== Searching for references to tier0+0x7ef0 and 0x1c950 ===")
for target, label in TARGETS.items():
    print(f"\n  -- {label} --")
    call_xrefs = []
    lea_xrefs = []
    qword_xrefs = []
    for b, e in funcs:
        f = file_of(b)
        if f is None: continue
        raw = pe.__data__[f:f + (e - b)]
        for insn in md.disasm(bytes(raw), image_base + b):
            rva = insn.address - image_base
            if insn.mnemonic in ("call", "jmp") and len(insn.operands) == 1:
                op = insn.operands[0]
                if op.type == 2 and (op.imm - image_base) == target:
                    call_xrefs.append((rva, b))
            if insn.mnemonic == "lea" and len(insn.operands) == 2:
                src = insn.operands[1]
                if src.type == 3 and src.mem.base == 41:
                    t = insn.address + insn.size + src.mem.disp - image_base
                    if t == target:
                        dst_reg = insn.reg_name(insn.operands[0].reg)
                        lea_xrefs.append((rva, b, dst_reg))
    # Search .data / .rdata for qword pointers to tier0+image_base+target
    ptr_va = image_base + target
    ptr_bytes = struct.pack("<Q", ptr_va)
    for sec_name in (".data", ".rdata", "_RDATA"):
        sec = None
        for s in pe.sections:
            if s.Name.rstrip(b"\x00").decode() == sec_name:
                sec = s; break
        if not sec: continue
        blob = pe.__data__[sec.PointerToRawData:sec.PointerToRawData + sec.SizeOfRawData]
        off = 0
        while True:
            i = blob.find(ptr_bytes, off)
            if i < 0: break
            qword_xrefs.append((sec_name, sec.VirtualAddress + i))
            off = i + 1
    print(f"    direct CALL/JMP xrefs:  {len(call_xrefs)}")
    for rva, fn in call_xrefs[:10]:
        print(f"      call at tier0+0x{rva:x}  in fn 0x{fn:x}")
    print(f"    LEA xrefs:  {len(lea_xrefs)}")
    for rva, fn, dst in lea_xrefs[:10]:
        print(f"      lea {dst},... at tier0+0x{rva:x}  in fn 0x{fn:x}")
    print(f"    QWORD-in-data xrefs:  {len(qword_xrefs)}")
    for sec_name, rva in qword_xrefs[:10]:
        print(f"      {sec_name}+0x{rva - 0:x}  (RVA 0x{rva:x})")


# Look at calls inside tier0+0x1c950 to find caller / surrounding code
print("\n=== Find xrefs to tier0+0x1c950 (the worker main) ===")
xrefs = []
for b, e in funcs:
    f = file_of(b)
    if f is None: continue
    raw = pe.__data__[f:f + (e - b)]
    for insn in md_quick.disasm(bytes(raw), image_base + b):
        if insn.mnemonic == "lea" or insn.mnemonic in ("call", "jmp"):
            s = insn.op_str.strip()
            # Match pattern "*0x180001c950" or "[rip + ...]"
            if "0x18001c950" in s.lower():
                xrefs.append((insn.address - image_base, b, insn.mnemonic, s))
print(f"  Found {len(xrefs)} xrefs:")
for rva, fn, mnem, s in xrefs[:20]:
    print(f"    {mnem} at tier0+0x{rva:x}  in fn 0x{fn:x}  ({s})")


# Now disassemble a few small functions that might be of interest:
# - tier0+0x2959c (fopen wrapper) — but no pdata entry
# - the function containing 0x2959c
def find_func(rva):
    for b, e in funcs:
        if b <= rva < e: return (b, e)
    return None

def annotate(insn):
    annots = []
    for op in insn.operands:
        if op.type == 3 and op.mem.base == 41:
            t = insn.address + insn.size + op.mem.disp - image_base
            sec = section_of(t)
            if sec:
                sname = sec.Name.rstrip(b"\x00").decode("latin-1")
                if sname == ".rdata":
                    s = try_string(t)
                    if s: annots.append(f'"{s[:140]}"')
                elif sname == ".data": annots.append(f".data+0x{t:x}")
                elif sname == ".text": annots.append(f"tier0+0x{t:x}")
    if insn.mnemonic in ("call", "jmp"):
        for op in insn.operands:
            if op.type == 2:
                annots.append(f"-> tier0+0x{op.imm - image_base:x}")
    return "  ; " + " ; ".join(annots) if annots else ""


# Look at function containing 0x2959c
fn = find_func(0x2959c)
if fn:
    b, e = fn
    print(f"\n=== Function containing tier0+0x2959c: 0x{b:x}..0x{e:x} ===")
    raw = pe.__data__[file_of(b):file_of(b) + (e - b)]
    for insn in md.disasm(bytes(raw), image_base + b):
        rva = insn.address - image_base
        mark = "    <<< ENTRY" if rva == b else ""
        print(f"  {rva:08x}  {insn.mnemonic:<8} {insn.op_str}{annotate(insn)}{mark}")
