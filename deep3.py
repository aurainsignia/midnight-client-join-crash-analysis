"""Cleaner approach: just disassemble the post-work-item functions and
identify the queueing/waiting pattern, and probe the heap region info via
peek bytes."""
import struct
from pathlib import Path
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DMP = Path(r"C:\Users\Chris\Desktop\dubiousnet\bugs\gmod client crash on third party zs server 2026-05-19\gmod.exe.29108.dmp")
TIER0 = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\tier0.dll")
dmp = DMP.read_bytes()

# Just dump first 64 bytes of stream-13 to see its layout
sig, ver, n_streams, dir_rva = struct.unpack_from("<IIII", dmp, 0)
for i in range(n_streams):
    off = dir_rva + i * 12
    stype, sz, srva = struct.unpack_from("<III", dmp, off)
    if stype == 13:
        raw = dmp[srva:srva + min(64, sz)]
        print(f"Stream 13 (size 0x{sz:x}) first 64 bytes:")
        for j in range(0, len(raw), 16):
            chunk = raw[j:j+16]
            print(f"  +0x{j:02x}: {' '.join(f'{c:02x}' for c in chunk)}")
        # Look at sizes
        h0, h1 = struct.unpack_from("<II", raw, 0)
        print(f"  Possible layout 1: 2x U32: {h0}, {h1}")
        h_hdr, h_ent, h_cnt = struct.unpack_from("<IIQ", raw, 0)
        print(f"  Possible layout 2 (3-field hdr): {h_hdr}, {h_ent}, count={h_cnt}")


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
    # try wide
    if end >= 4 and raw[1] == 0:
        end16 = 0
        while end16+1 < len(raw):
            if raw[end16]==0 and raw[end16+1]==0: break
            end16 += 2
        if 4 <= end16 <= 510:
            try: return 'L"' + raw[:end16].decode('utf-16le') + '"'
            except: pass
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
                 (0x7dc0, "called by Dump_CreateDump before posting (UUID gen?)"),
                 (0x1c530, "post-work-item A"),
                 (0x1c340, "post-work-item B"),
                 (0x1d720, "called by Dump init right after CreateThread")]:
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
