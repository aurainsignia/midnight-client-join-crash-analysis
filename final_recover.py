"""Read engine.dll's static .rdata at offsets we found pointers to, plus
fully reconstruct the path string sitting on the stack of the caller of the
condump-funclet, and dump the "selector" struct that was passed to
engine_Sys_FPrintf."""
import struct
from pathlib import Path

DMP = Path(r"C:\Users\Chris\Desktop\dubiousnet\bugs\gmod client crash on third party zs server 2026-05-19\gmod.exe.29108.dmp")
DLL = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\engine.dll")

dump_data = DMP.read_bytes()
dll_data  = DLL.read_bytes()

# Static .rdata read from engine.dll on disk
import pefile
pe = pefile.PE(str(DLL), fast_load=False)
image_base = pe.OPTIONAL_HEADER.ImageBase

def read_engine_static(rva, n):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return pe.__data__[s.PointerToRawData + (rva - s.VirtualAddress):
                               s.PointerToRawData + (rva - s.VirtualAddress) + n]
    return None

def read_str_static(rva, maxlen=512):
    raw = read_engine_static(rva, maxlen)
    if not raw:
        return None
    end = raw.find(b"\x00")
    if end < 1: return None
    sub = raw[:end]
    if all(0x20 <= c < 0x7f or c in (9, 10, 13) for c in sub):
        return sub.decode("ascii")
    return None

# Memory index from dump
sig, ver, n_streams, dir_rva = struct.unpack_from("<IIII", dump_data, 0)
streams = {}
for i in range(n_streams):
    off = dir_rva + i * 12
    stype, sz, srva = struct.unpack_from("<III", dump_data, off)
    streams.setdefault(stype, []).append((sz, srva))

mem_idx = []
for sz, srva in streams.get(5, []):
    n_ranges = struct.unpack_from("<I", dump_data, srva)[0]
    for i in range(n_ranges):
        off = srva + 4 + i * 16
        start, dsize, drva = struct.unpack_from("<QII", dump_data, off)
        mem_idx.append((start, start + dsize, drva))
mem_idx.sort()

def read_dump(va, n):
    for s, e, fo in mem_idx:
        if s <= va and va + n <= e:
            return dump_data[fo + (va - s):fo + (va - s) + n]
        if s <= va < e:
            avail = e - va
            partial = dump_data[fo + (va - s):fo + (va - s) + avail]
            rest = read_dump(e, n - avail)
            return partial + (rest if rest else b"\x00" * (n - avail))
    return None

# 1) Static .rdata string at engine+0x387738
print("=== Static .rdata at engine+0x387738 (the printf format string) ===")
s = read_str_static(0x387738, 512)
print(f"  string: \"{s}\"")
# also read 64 raw bytes
raw = read_engine_static(0x387738, 64)
if raw:
    print(f"  raw 64 bytes:")
    for i in range(0, 64, 16):
        chunk = raw[i:i+16]
        hx = " ".join(f"{c:02x}" for c in chunk)
        ax = "".join(chr(c) if 0x20 <= c < 0x7f else "." for c in chunk)
        print(f"    +0x{i:02x}: {hx:<48}  {ax}")

# 2) Static .rdata neighborhood — what other strings are nearby?
print("\n=== Static .rdata 0x387700 .. 0x387900 ===")
neigh = read_engine_static(0x387700, 0x200)
# Print strings found in this region
i = 0
while i < len(neigh):
    end = neigh.find(b"\x00", i)
    if end == -1: break
    if end - i >= 3:
        sub = neigh[i:end]
        if all(0x20 <= c < 0x7f for c in sub):
            print(f"  +0x{0x387700+i:06x}: \"{sub.decode('ascii')}\"")
    i = end + 1

# 3) Reconstruct the gmod.exe path from the stack
print("\n=== Stack-resident string starting at rsp+0x8c0 ===")
crash_rsp = 0x000000667cd7ebd0
raw = read_dump(crash_rsp + 0x8c0, 0x100)
if raw:
    end = raw.find(b"\x00")
    if end > 0:
        try:
            print(f"  \"{raw[:end].decode('ascii')}\"")
        except Exception:
            pass
    # also show raw
    for i in range(0, min(len(raw), 0x100), 16):
        chunk = raw[i:i+16]
        hx = " ".join(f"{c:02x}" for c in chunk)
        ax = "".join(chr(c) if 0x20 <= c < 0x7f else "." for c in chunk)
        print(f"  +0x{i:03x}: {hx:<48}  {ax}")

# 4) Dump the "selector" struct passed as rcx to Sys_FPrintf — at stack VA 0x667cd7f460
print("\n=== Selector struct passed as arg1 (rcx) to engine_Sys_FPrintf ===")
print("  VA = 0x000000667cd7f460   (stack ptr)")
raw = read_dump(0x000000667cd7f460, 0x100)
if raw:
    for i in range(0, 0x100, 16):
        chunk = raw[i:i+16]
        hx = " ".join(f"{c:02x}" for c in chunk)
        ax = "".join(chr(c) if 0x20 <= c < 0x7f else "." for c in chunk)
        print(f"  +0x{i:03x}: {hx:<48}  {ax}")

# 5) Try to find the heap pointer 0x0000023cafdb99e0 (the "%s" argument).
# If captured anywhere in the dump it might give us the string being printed.
print("\n=== Heap ptr 0x0000023cafdb99e0 (the %s argument string) ===")
ptr_va = 0x0000023cafdb99e0
raw = read_dump(ptr_va, 0x200)
if raw is None:
    print("  not in dump")
else:
    end = raw.find(b"\x00")
    if end > 0:
        try:
            s = raw[:end].decode("ascii", errors="replace")
            print(f"  string: \"{s}\"")
        except Exception:
            pass
    for i in range(0, min(len(raw), 0x80), 16):
        chunk = raw[i:i+16]
        hx = " ".join(f"{c:02x}" for c in chunk)
        ax = "".join(chr(c) if 0x20 <= c < 0x7f else "." for c in chunk)
        print(f"  +0x{i:03x}: {hx:<48}  {ax}")

# 6) Dump function 0x35733c — that's what vfprintf_lockwrapper calls right after
# entering. If it's NOT a lock function, my interpretation needs revising.
print("\n=== Disassembly of engine.dll+0x35733c (what lockwrapper calls first) ===")
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
raw = read_engine_static(0x35733c, 0x100)
if raw:
    for insn in md.disasm(bytes(raw), image_base + 0x35733c):
        rva = insn.address - image_base
        print(f"  {rva:08x}  {insn.bytes.hex():<22} {insn.mnemonic:<8} {insn.op_str}")
        if insn.mnemonic == "ret":
            break

# 7) Find which function 0x35733c belongs to per pdata
pdata_sec = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".pdata")
pdata = pe.__data__[pdata_sec.PointerToRawData:pdata_sec.PointerToRawData + pdata_sec.SizeOfRawData]
for i in range(len(pdata) // 12):
    b, e, u = struct.unpack_from("<III", pdata, i * 12)
    if b == 0: break
    if b <= 0x35733c < e:
        print(f"\n  -> 0x35733c is inside function 0x{b:x}..0x{e:x} ({e-b} bytes)")
        # disasm the full function
        raw = read_engine_static(b, e - b)
        print("  Full function disassembly:")
        for insn in md.disasm(bytes(raw), image_base + b):
            r = insn.address - image_base
            print(f"    {r:08x}  {insn.bytes.hex():<22} {insn.mnemonic:<8} {insn.op_str}")
        break
