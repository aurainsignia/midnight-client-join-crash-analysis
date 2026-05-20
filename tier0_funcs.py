"""Disassemble tier0 functions of interest:
- 0x1c950..0x1ca57 (the thread proc / wrapper)
- 0x7ef0..0x8037 (the debug-dump function — full body in detail)
- 0x77e0 (tier0's printf wrapper)
- 0x2959c (whatever this is — returns a FILE*-like in rdi)
- 0x2f870 (preamble before each callback)
- 0x29224 (called at end of dump)
- 0x1fcd0 (memset-equivalent)
- 0x8780 (string-init / sprintf-like)
- 0x60d60 / 0x61f68 (apparently part of the chain heuristically)
- 0x2f701 (also heuristic)
"""
import struct
from pathlib import Path
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DLL = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\tier0.dll")
pe = pefile.PE(str(DLL), fast_load=False)
image_base = pe.OPTIONAL_HEADER.ImageBase

def section_of(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s
    return None

def read_at(rva, n):
    s = section_of(rva)
    if not s: return None
    return pe.__data__[s.PointerToRawData + (rva - s.VirtualAddress):
                       s.PointerToRawData + (rva - s.VirtualAddress) + n]

def try_string(rva, maxlen=512):
    raw = read_at(rva, maxlen)
    if not raw: return None
    end = raw.find(b"\x00")
    if end < 1 or end > 511: return None
    sub = raw[:end]
    if all(0x20 <= c < 0x7f or c in (9, 10, 13) for c in sub):
        return sub.decode("ascii")
    # try wide
    if end >= 4 and raw[1] == 0 and raw[3] == 0:
        end16 = 0
        while end16+1 < len(raw):
            if raw[end16] == 0 and raw[end16+1] == 0: break
            end16 += 2
        if 4 <= end16 <= 510:
            try: return "L\"" + raw[:end16].decode("utf-16le") + "\""
            except: pass
    return None

# Build IAT map
iat_by_rva = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode("latin-1")
    for imp in entry.imports:
        name = imp.name.decode("latin-1") if imp.name else f"ord_{imp.ordinal}"
        iat_by_rva[imp.address - image_base] = (dll, name)

# Build .pdata function list
pdata_sec = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".pdata")
pdata = pe.__data__[pdata_sec.PointerToRawData:pdata_sec.PointerToRawData + pdata_sec.SizeOfRawData]
funcs = []
for i in range(len(pdata) // 12):
    b, e, u = struct.unpack_from("<III", pdata, i * 12)
    if b == 0: break
    funcs.append((b, e))

def find_func(rva):
    for b, e in funcs:
        if b <= rva < e:
            return (b, e)
    return None

md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True

def annotate(insn):
    annots = []
    if insn.mnemonic in ("call", "jmp"):
        for op in insn.operands:
            if op.type == 2:
                tgt = op.imm - image_base
                annots.append(f"-> tier0+0x{tgt:x}")
            elif op.type == 3 and op.mem.base == 41:
                t = insn.address + insn.size + op.mem.disp - image_base
                if t in iat_by_rva:
                    annots.append(f"-> {iat_by_rva[t][1]} ({iat_by_rva[t][0]})")
                else:
                    annots.append(f"-> [tier0+0x{t:x}]")
    if insn.mnemonic in ("lea", "mov", "cmp", "push"):
        for op in insn.operands:
            if op.type == 3 and op.mem.base == 41:
                t = insn.address + insn.size + op.mem.disp - image_base
                sec = section_of(t)
                if sec:
                    sname = sec.Name.rstrip(b"\x00").decode("latin-1")
                    if sname == ".rdata":
                        s = try_string(t)
                        if s:
                            annots.append(f'"{s[:140]}"')
                        else:
                            annots.append(f".rdata+0x{t:x}")
                    elif sname == ".data":
                        annots.append(f".data+0x{t:x}")
                    elif sname == ".text":
                        annots.append(f"tier0+0x{t:x}")
    return "  ; " + " ; ".join(annots) if annots else ""


def disasm_func(rva, label):
    f = find_func(rva)
    if not f:
        print(f"\n#### tier0+0x{rva:x} ({label}) — NO PDATA ENTRY")
        return
    b, e = f
    print(f"\n#### tier0+0x{b:x}..0x{e:x} ({e-b} bytes) — {label}")
    raw = read_at(b, e - b)
    for insn in md.disasm(bytes(raw), image_base + b):
        rv = insn.address - image_base
        mark = "    <<< ENTRY" if rv == b else ""
        print(f"  {rv:08x}  {insn.bytes.hex():<22} {insn.mnemonic:<8} {insn.op_str}{annotate(insn)}{mark}")


# Functions to disassemble
TARGETS = [
    (0x1c950, "PARENT — wrapper containing call to 0x7ef0 (RA +0x1ca21 on stack)"),
    (0x7ef0,  "Debug-dump function (already partially seen)"),
    (0x2959c, "Function that returns the FILE-like context in rdi"),
    (0x77e0,  "Tier0's printf wrapper called for 'Executable: %s\\n\\n'"),
    (0x2f870, "Preamble called before each callback"),
    (0x29224, "Called at end of dump path"),
    (0x8780,  "Buffer init / string operation"),
]
for rva, lbl in TARGETS:
    disasm_func(rva, lbl)


# Also enumerate the function-pointer table at .data+0x61ef0 — the registered callbacks
print("\n\n=== Reading tier0.dll .data+0x61ef0 (16 callback slots) ===")
raw = read_at(0x61ef0, 16 * 8)
if raw:
    for i in range(16):
        v = struct.unpack_from("<Q", raw, i * 8)[0]
        if v == 0:
            print(f"  slot[{i:2}] = NULL")
        else:
            # Static .data has the static (unrelocated) value. The actual relocated
            # value would be at runtime — we'd need to read it from the dump.
            print(f"  slot[{i:2}] = 0x{v:016x} (static-image value)")


# Also: identify what tier0+0x2959c is. Look at the IAT/exports neighborhood.
# It returns a value used as a "FILE-like" stream in subsequent calls.
print("\n=== Strings near tier0+0x2959c (looking for fopen-related strings) ===")
# We'll disassemble it already above; nothing to add here.
