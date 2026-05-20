"""Parse MemoryInfoListStream (type 13) for the heap layout and check if
0x0000023d0ec49f70 is in a known heap region. Also disassemble tier0+0x1d8a0
and tier0+0x7dc0 to understand the queueing pattern and UUID generation."""
import struct
from pathlib import Path
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DMP = Path(r"C:\Users\Chris\Desktop\dubiousnet\bugs\gmod client crash on third party zs server 2026-05-19\gmod.exe.29108.dmp")
TIER0 = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\tier0.dll")
dmp = DMP.read_bytes()

sig, ver, n_streams, dir_rva = struct.unpack_from("<IIII", dmp, 0)
streams = {}
for i in range(n_streams):
    off = dir_rva + i * 12
    stype, sz, srva = struct.unpack_from("<III", dmp, off)
    streams.setdefault(stype, []).append((sz, srva))

# Parse MemoryInfoListStream (type 13)
# MINIDUMP_MEMORY_INFO_LIST:
#   ULONG32 SizeOfHeader;
#   ULONG32 SizeOfEntry;
#   ULONG64 NumberOfEntries;
# then array of MINIDUMP_MEMORY_INFO:
#   ULONG64 BaseAddress;        // +0x00
#   ULONG64 AllocationBase;     // +0x08
#   ULONG32 AllocationProtect;  // +0x10
#   ULONG32 __alignment1;
#   ULONG64 RegionSize;         // +0x18
#   ULONG32 State;              // +0x20  (MEM_COMMIT=0x1000, MEM_RESERVE=0x2000, MEM_FREE=0x10000)
#   ULONG32 Protect;            // +0x24  (PAGE_*)
#   ULONG32 Type;               // +0x28  (MEM_IMAGE=0x1000000, MEM_MAPPED=0x40000, MEM_PRIVATE=0x20000)
#   ULONG32 __alignment2;
PROTECTS = {
    0x01: "NA",
    0x02: "R",
    0x04: "RW",
    0x08: "WC",
    0x10: "X",
    0x20: "XR",
    0x40: "XRW",
    0x80: "XWC",
    0x100: "G",
}
STATES = {0x1000: "COMMIT", 0x2000: "RESERVE", 0x10000: "FREE"}
TYPES = {0x1000000: "IMAGE", 0x40000: "MAPPED", 0x20000: "PRIVATE"}

target = 0x0000023d0ec49f70
hit_region = None
all_regions = []
for sz, srva in streams.get(13, []):
    sz_hdr, sz_entry, n_ent = struct.unpack_from("<IIQ", dmp, srva)
    print(f"MemoryInfoListStream: header={sz_hdr}, entry={sz_entry}, count={n_ent}")
    for i in range(n_ent):
        off = srva + sz_hdr + i * sz_entry
        if off + sz_entry > len(dmp): break
        base, alloc_base, alloc_prot, _, rsize, state, prot, typ, _ = struct.unpack_from("<QQIIQIII I", dmp, off)
        all_regions.append((base, rsize, state, prot, typ, alloc_base, alloc_prot))
        if base <= target < base + rsize:
            hit_region = (base, rsize, state, prot, typ, alloc_base, alloc_prot)

print(f"\nTotal regions: {len(all_regions)}")

if hit_region:
    base, rsize, state, prot, typ, alloc_base, alloc_prot = hit_region
    print(f"\n=== Region containing FILE* @ 0x{target:016x} ===")
    print(f"  Base=0x{base:016x}  AllocBase=0x{alloc_base:016x}")
    print(f"  Size=0x{rsize:x}  State={STATES.get(state, hex(state))}  Protect={PROTECTS.get(prot, hex(prot))}  Type={TYPES.get(typ, hex(typ))}")
    print(f"  AllocProtect={PROTECTS.get(alloc_prot, hex(alloc_prot))}")

# Look for all PRIVATE+RW regions in the 0x0000023x... range (likely heap)
print(f"\n=== All PRIVATE+RW regions starting with 0x023x__... (likely heap) ===")
for base, rsize, state, prot, typ, alloc_base, alloc_prot in sorted(all_regions):
    if 0x0000023000000000 <= base < 0x0000023f00000000:
        if state == 0x1000 and prot in (0x04, 0x08, 0x40, 0x80):  # COMMIT + RW-like
            print(f"  [0x{base:016x}..0x{base+rsize:016x})  size=0x{rsize:x}  {PROTECTS.get(prot,hex(prot))}  {TYPES.get(typ,hex(typ))}")

# Check if 0x023d0ec49f70 falls in a captured-memory range now using the SAME index
# but considering MemoryInfoList vs Memory list distinction
print(f"\n=== Memory CAPTURE coverage for 0x{target:016x} ===")
captured = False
for sz, srva in streams.get(5, []):
    n_ranges = struct.unpack_from("<I", dmp, srva)[0]
    for i in range(n_ranges):
        off = srva + 4 + i * 16
        start, dsize, drva = struct.unpack_from("<QII", dmp, off)
        if start <= target < start + dsize:
            print(f"  COVERED: range [0x{start:016x}..0x{start+dsize:016x}) at file 0x{drva:x}")
            captured = True
            break
if not captured:
    # Look at the closest captured ranges
    print("  not directly captured. Closest captured ranges:")
    near = []
    for sz, srva in streams.get(5, []):
        n_ranges = struct.unpack_from("<I", dmp, srva)[0]
        for i in range(n_ranges):
            off = srva + 4 + i * 16
            start, dsize, drva = struct.unpack_from("<QII", dmp, off)
            d1 = abs(start - target)
            d2 = abs((start + dsize) - target)
            near.append((min(d1, d2), start, start + dsize))
    near.sort()
    for d, s, e in near[:5]:
        print(f"    distance 0x{d:x}: [0x{s:016x}..0x{e:016x})")


# Disassemble tier0+0x1d8a0 and tier0+0x7dc0
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


for rva, lbl in [(0x1d8a0, "post-work-item C (called by Dump_CreateDump)"),
                 (0x7dc0, "called by Dump_CreateDump before posting"),
                 (0x1c530, "post-work-item A"),
                 (0x1c340, "post-work-item B")]:
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
