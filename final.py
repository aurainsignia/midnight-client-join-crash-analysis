"""Final pass:
 - Find callers of engine.dll+0x21a890 (condump impl)
 - Disassemble 0x21a890 (parent of the loop funclet at 0x21a8ba) end-to-end
 - Disassemble whatever function contains 0xa8170 (FILE-lookup)
 - Look at the .rdata bytes the FILE-lookup returns from
"""
import struct
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DLL = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\engine.dll")
pe = pefile.PE(str(DLL), fast_load=False)
image_base = pe.OPTIONAL_HEADER.ImageBase

text = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".text")
pdata_sec = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".pdata")
pdata = pe.__data__[pdata_sec.PointerToRawData:pdata_sec.PointerToRawData + pdata_sec.SizeOfRawData]


def file_of(rva):
    if text.VirtualAddress <= rva < text.VirtualAddress + max(text.Misc_VirtualSize, text.SizeOfRawData):
        return text.PointerToRawData + rva - text.VirtualAddress
    return None


def section_of(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s
    return None


funcs = []
for i in range(len(pdata) // 12):
    b, e, u = struct.unpack_from("<III", pdata, i * 12)
    if b == 0:
        break
    funcs.append((b, e))


def find_func_containing(rva):
    for b, e in funcs:
        if b <= rva < e:
            return (b, e)
    return None


iat_by_rva = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode("latin-1")
    for imp in entry.imports:
        name = imp.name.decode("latin-1") if imp.name else f"ord_{imp.ordinal}"
        iat_by_rva[imp.address - image_base] = (dll, name)


def try_string(rva, maxlen=512):
    s = section_of(rva)
    if not s:
        return None
    f = s.PointerToRawData + rva - s.VirtualAddress
    raw = pe.__data__[f:f + maxlen]
    end = raw.find(b"\x00")
    if end < 2 or end > 511:
        return None
    sub = raw[:end]
    if all(0x20 <= b < 0x7f or b in (9, 10, 13) for b in sub):
        return sub.decode("ascii", errors="replace")
    return None


md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True
md2 = Cs(CS_ARCH_X86, CS_MODE_64)
md2.detail = False


def annotate(insn):
    annots = []
    if insn.mnemonic in ("call", "jmp") and len(insn.operands) == 1:
        op = insn.operands[0]
        if op.type == 2:
            tgt = op.imm - image_base
            annots.append(f"-> engine.dll+0x{tgt:x}")
        elif op.type == 3 and op.mem.base == 41:
            t = insn.address + insn.size + op.mem.disp - image_base
            if t in iat_by_rva:
                annots.append(f"-> {iat_by_rva[t][1]} ({iat_by_rva[t][0]})")
            else:
                annots.append(f"-> [engine.dll+0x{t:x}]")
    if insn.mnemonic in ("lea", "mov", "cmp"):
        for op in insn.operands:
            if op.type == 3 and op.mem.base == 41:
                t = insn.address + insn.size + op.mem.disp - image_base
                sec = section_of(t)
                if sec:
                    sname = sec.Name.rstrip(b"\x00").decode("latin-1")
                    if sname == ".rdata":
                        s = try_string(t)
                        if s:
                            annots.append(f'"{s[:120]}"')
                        else:
                            annots.append(f".rdata+0x{t:x}")
                    elif sname == ".data":
                        annots.append(f".data+0x{t:x}")
    return "  ; " + " ; ".join(annots) if annots else ""


def disasm_func_full(begin, end, label):
    print(f"\n#### Function 0x{begin:x}..0x{end:x}  ({end - begin} bytes) — {label}")
    f = file_of(begin)
    if f is None:
        print("  (no section)")
        return
    raw = pe.__data__[f:f + (end - begin)]
    for insn in md.disasm(bytes(raw), image_base + begin):
        rva = insn.address - image_base
        mark = "    <<< ENTRY" if rva == begin else ""
        print(f"  {rva:08x}  {insn.bytes.hex():<22} {insn.mnemonic:<8} {insn.op_str}{annotate(insn)}{mark}")


# Find callers of 0x21a890
xrefs_a890 = []
for b, e in funcs:
    f = file_of(b)
    if f is None:
        continue
    raw = pe.__data__[f:f + (e - b)]
    for insn in md2.disasm(bytes(raw), image_base + b):
        if insn.mnemonic in ("call", "jmp"):
            s = insn.op_str.strip()
            if s.startswith("0x"):
                try:
                    if int(s, 16) - image_base == 0x21a890:
                        xrefs_a890.append((insn.address - image_base, b))
                except ValueError:
                    pass

print(f"\n#### CALLERS of engine.dll+0x21a890 (condump-loop-parent) — {len(xrefs_a890)} sites")
for ra, fn in xrefs_a890[:20]:
    print(f"   call at 0x{ra:x}  in fn 0x{fn:x}")

# Disassemble 0x21a890..0x21a8ba (parent of funclet) AND the funclet
disasm_func_full(0x21a890, 0x21a8ba, "condump parent (sets up loop)")

# Find function containing 0xa8170
fn_a8170 = find_func_containing(0xa8170)
print(f"\nFunction containing 0xa8170: {fn_a8170}")
if fn_a8170:
    disasm_func_full(fn_a8170[0], fn_a8170[1], "FILE-lookup-by-selector (0xa8170)")

# Also disasm any function that wraps 0x21a890 — find one direct caller
print("\n=== Disasm of callers of 0x21a890 (to find what triggers condump) ===")
for ra, fn_begin in xrefs_a890[:5]:
    fn = find_func_containing(fn_begin)
    if fn:
        disasm_func_full(fn[0], fn[1], f"caller of condump (ra=0x{ra:x})")
