"""Parse the gmod.exe.29108.dmp Windows minidump and read specific virtual
addresses out of its captured memory.

Goals:
 1. Find engine.dll's runtime BaseOfImage from ModuleListStream.
 2. Compute the runtime VA of the FILE* slot:
        FILE_slot_VA = engine_base + 0x6c7c20
 3. Read 8 bytes at that VA -> the FILE* (call it FP).
 4. Follow FP -> read the FILE struct contents (first 0x60 bytes).
 5. Identify the fd field (_file, MSVC layout) and look it up in the runtime
    `__pioinfo` table — but we don't have a pointer to __pioinfo for engine's
    static CRT, so report the raw struct.
 6. Also report the FILE*s the engine has for `0x6c7c20` *and* its neighbours
    in case there's an array.
"""
import struct
import sys
from pathlib import Path

DMP = Path(r"C:\Users\Chris\Desktop\dubiousnet\bugs\gmod client crash on third party zs server 2026-05-19\gmod.exe.29108.dmp")
data = DMP.read_bytes()
print(f"Loaded {len(data):,} bytes")

# --- MINIDUMP_HEADER ---
sig, ver, n_streams, dir_rva, checksum, ts_or_flags = struct.unpack_from("<IIIIII", data, 0)
flags = struct.unpack_from("<Q", data, 24)[0]
print(f"Header signature: 0x{sig:08x} (expect 'MDMP'=0x504d444d)")
print(f"  NumberOfStreams: {n_streams}  StreamDirectoryRva: 0x{dir_rva:08x}  Flags: 0x{flags:016x}")
assert sig == 0x504d444d, "not a minidump"

# Stream types we care about
ST_THREADS = 3
ST_MODULES = 4
ST_MEMORY  = 5
ST_EXCEPTION = 6
ST_SYSTEM  = 7
ST_MEMORY64 = 9

streams = {}
for i in range(n_streams):
    off = dir_rva + i * 12
    stype, sz, srva = struct.unpack_from("<III", data, off)
    streams.setdefault(stype, []).append((sz, srva))

for st, items in sorted(streams.items()):
    for sz, srva in items:
        name = {1:"UnusedStream", 3:"ThreadList", 4:"ModuleList", 5:"MemoryList",
                6:"Exception", 7:"SystemInfo", 9:"Memory64List", 16:"HandleData",
                17:"FunctionTable", 0xffff:"Last"}
        print(f"  Stream type {st:>5} ({name.get(st,'?')}): size 0x{sz:x} at rva 0x{srva:x}")

# --- ModuleListStream ---
def find_engine_dll():
    for sz, srva in streams.get(ST_MODULES, []):
        n_mods = struct.unpack_from("<I", data, srva)[0]
        off = srva + 4
        for i in range(n_mods):
            mod = data[off:off + 108]
            base, size_img, _csum, _ts, name_rva = struct.unpack_from("<QIIII", mod, 0)
            # MINIDUMP_STRING at name_rva: U32 length (bytes), then UTF-16
            slen = struct.unpack_from("<I", data, name_rva)[0]
            sbytes = data[name_rva + 4:name_rva + 4 + slen]
            name = sbytes.decode("utf-16-le", errors="replace")
            yield (name, base, size_img)
            off += 108

print("\n=== Loaded modules ===")
modules = list(find_engine_dll())
engine_base = None
engine_size = None
for name, base, size in modules:
    short = name.split("\\")[-1]
    print(f"  {short:>30}  base=0x{base:016x}  size=0x{size:x}")
    if short.lower() == "engine.dll":
        engine_base = base
        engine_size = size

print(f"\nEngine base resolved to: 0x{engine_base:016x}  size=0x{engine_size:x}")
assert engine_base is not None


# --- Memory64ListStream ---
# Layout:
#   ULONG64 NumberOfMemoryRanges;
#   ULONG64 BaseRva;            (offset in the file where memory blob starts)
#   MINIDUMP_MEMORY_DESCRIPTOR64 ranges[];  (Start, Size each ULONG64)
# Memory pages are stored consecutively from BaseRva in the order of ranges.
def build_mem_index():
    idx = []  # list of (va_start, va_end, file_offset)
    for sz, srva in streams.get(ST_MEMORY64, []):
        n_ranges, base_rva = struct.unpack_from("<QQ", data, srva)
        cursor = base_rva
        for i in range(n_ranges):
            start, size = struct.unpack_from("<QQ", data, srva + 16 + i * 16)
            idx.append((start, start + size, cursor))
            cursor += size
    # Also classic MemoryListStream (32-bit, but locations point into the file)
    for sz, srva in streams.get(ST_MEMORY, []):
        n_ranges = struct.unpack_from("<I", data, srva)[0]
        for i in range(n_ranges):
            off = srva + 4 + i * 16
            start, dsize, drva = struct.unpack_from("<QII", data, off)
            idx.append((start, start + dsize, drva))
    idx.sort()
    return idx


mem_idx = build_mem_index()
print(f"\n=== Memory ranges captured: {len(mem_idx)} ===")
# Show coverage near engine.dll
e_lo = engine_base
e_hi = engine_base + engine_size
relevant = [r for r in mem_idx if r[1] > e_lo and r[0] < e_hi]
print(f"  ranges intersecting engine.dll image: {len(relevant)}")
total_covered = 0
for s, e, fo in relevant[:20]:
    o_s = max(s, e_lo)
    o_e = min(e, e_hi)
    total_covered += (o_e - o_s)
    print(f"    [0x{s:016x}..0x{e:016x})  file=0x{fo:x}")
print(f"  Total bytes covered in engine.dll image: 0x{total_covered:x} of 0x{engine_size:x}")


def read_va(va, n):
    """Read n bytes from process VA `va` out of the minidump memory blob."""
    for s, e, fo in mem_idx:
        if s <= va and va + n <= e:
            return data[fo + (va - s):fo + (va - s) + n]
        if s <= va < e:
            avail = e - va
            # partial — pad
            partial = data[fo + (va - s):fo + (va - s) + avail]
            rest = read_va(e, n - avail)
            return partial + (rest if rest else b"\x00" * (n - avail))
    return None


# --- Step 1: read the FILE* at engine_base + 0x6c7c20 ---
file_slot_va = engine_base + 0x6c7c20
print(f"\n=== Reading FILE* slot ===")
print(f"  engine.dll+0x6c7c20  ->  VA=0x{file_slot_va:016x}")
raw = read_va(file_slot_va, 64)
if raw is None:
    print("  *** NOT CAPTURED IN DUMP ***")
else:
    fp = struct.unpack_from("<Q", raw, 0)[0]
    qw1 = struct.unpack_from("<Q", raw, 8)[0]
    qw2 = struct.unpack_from("<Q", raw, 16)[0]
    qw3 = struct.unpack_from("<Q", raw, 24)[0]
    print(f"  qword[0] (FILE*):  0x{fp:016x}   {'(NULL)' if fp == 0 else ''}")
    print(f"  qword[1]:          0x{qw1:016x}")
    print(f"  qword[2]:          0x{qw2:016x}")
    print(f"  qword[3]:          0x{qw3:016x}")
    print(f"  raw 64 bytes: " + raw.hex())

    if fp:
        # Read the FILE struct.
        # MSVC FILE in modern static CRT (vctip/UCRT-ish layout):
        #   char* _ptr;     // +0x00
        #   char* _base;    // +0x08
        #   int   _cnt;     // +0x10
        #   int   _flag;    // +0x14   (or padded)
        #   int   _file;    // +0x18
        #   ...
        # Different CRT versions vary. We'll just dump the first 0x80 bytes
        # and let the user inspect.
        print(f"\n=== Reading FILE struct at 0x{fp:016x} ===")
        fstruct = read_va(fp, 0x80)
        if fstruct is None:
            print("  *** FILE* not captured in dump (likely heap not included) ***")
        else:
            for off in range(0, len(fstruct), 16):
                chunk = fstruct[off:off + 16]
                ascii_repr = "".join(chr(c) if 0x20 <= c < 0x7f else "." for c in chunk)
                hex_repr = " ".join(f"{c:02x}" for c in chunk)
                print(f"    +0x{off:02x}: {hex_repr:<48}  {ascii_repr}")
            # Probe candidate fields
            p_ptr = struct.unpack_from("<Q", fstruct, 0)[0]
            p_base = struct.unpack_from("<Q", fstruct, 8)[0]
            v_cnt = struct.unpack_from("<i", fstruct, 16)[0]
            v_flag = struct.unpack_from("<i", fstruct, 20)[0]
            v_file = struct.unpack_from("<i", fstruct, 24)[0]
            print(f"\n  Interpreted (UCRT-ish layout):")
            print(f"    _ptr  = 0x{p_ptr:016x}")
            print(f"    _base = 0x{p_base:016x}")
            print(f"    _cnt  = {v_cnt}")
            print(f"    _flag = 0x{v_flag:08x}")
            print(f"    _file = {v_file}  (fd)")

# --- Step 2: also try to read engine_base+0x6c7c20 surrounding window for context ---
print(f"\n=== Surrounding memory at engine+0x6c7c00..0x6c7d00 ===")
big = read_va(engine_base + 0x6c7c00, 0x100)
if big is not None:
    for off in range(0, 0x100, 16):
        chunk = big[off:off + 16]
        rva = 0x6c7c00 + off
        # Try to identify qwords that look like VAs (high-half = 0x00007ffc / 0x00007fff)
        hex_repr = " ".join(f"{c:02x}" for c in chunk)
        ascii_repr = "".join(chr(c) if 0x20 <= c < 0x7f else "." for c in chunk)
        print(f"  engine+0x{rva:06x}: {hex_repr:<48}  {ascii_repr}")

# --- Step 3: read the crash thread's CONTEXT to get exact RSP ---
print(f"\n=== Crash thread CONTEXT (from ExceptionStream) ===")
for sz, srva in streams.get(ST_EXCEPTION, []):
    # MINIDUMP_EXCEPTION_STREAM:
    #   ULONG32 ThreadId
    #   ULONG32 alignment
    #   MINIDUMP_EXCEPTION ExceptionRecord  (152 bytes)
    #   MINIDUMP_LOCATION_DESCRIPTOR ThreadContext  (8 bytes)
    tid = struct.unpack_from("<I", data, srva)[0]
    ctx_sz, ctx_rva = struct.unpack_from("<II", data, srva + 4 + 152)
    print(f"  ThreadId={tid}  ContextSize=0x{ctx_sz:x}  ContextRva=0x{ctx_rva:x}")
    # x64 CONTEXT layout — Rsp at offset 0x98, Rip at 0xf8
    ctx = data[ctx_rva:ctx_rva + ctx_sz]
    rsp = struct.unpack_from("<Q", ctx, 0x98)[0]
    rip = struct.unpack_from("<Q", ctx, 0xf8)[0]
    rax = struct.unpack_from("<Q", ctx, 0x78)[0]
    rcx = struct.unpack_from("<Q", ctx, 0x80)[0]
    rdx = struct.unpack_from("<Q", ctx, 0x88)[0]
    rbx = struct.unpack_from("<Q", ctx, 0x90)[0]
    rbp = struct.unpack_from("<Q", ctx, 0xa0)[0]
    rsi = struct.unpack_from("<Q", ctx, 0xa8)[0]
    rdi = struct.unpack_from("<Q", ctx, 0xb0)[0]
    r8  = struct.unpack_from("<Q", ctx, 0xb8)[0]
    r9  = struct.unpack_from("<Q", ctx, 0xc0)[0]
    r10 = struct.unpack_from("<Q", ctx, 0xc8)[0]
    r11 = struct.unpack_from("<Q", ctx, 0xd0)[0]
    r12 = struct.unpack_from("<Q", ctx, 0xd8)[0]
    r13 = struct.unpack_from("<Q", ctx, 0xe0)[0]
    r14 = struct.unpack_from("<Q", ctx, 0xe8)[0]
    r15 = struct.unpack_from("<Q", ctx, 0xf0)[0]
    print(f"    RIP=0x{rip:016x}  (engine+0x{rip-engine_base:x})")
    print(f"    RSP=0x{rsp:016x}")
    print(f"    RAX=0x{rax:016x}  RCX=0x{rcx:016x}  RDX=0x{rdx:016x}")
    print(f"    RBX=0x{rbx:016x}  RBP=0x{rbp:016x}  RSI=0x{rsi:016x}  RDI=0x{rdi:016x}")
    print(f"    R8 =0x{r8:016x}  R9 =0x{r9:016x}  R10=0x{r10:016x}  R11=0x{r11:016x}")
    print(f"    R12=0x{r12:016x}  R13=0x{r13:016x}  R14=0x{r14:016x}  R15=0x{r15:016x}")

    # Dump the stack near rsp — esp. the upstream args of vfprintf
    # We want to walk down to the _vfprintf_outer frame (engine+0x352ab4)
    # where rcx held the FILE*.
    print(f"\n=== Stack from RSP for 0x800 bytes ===")
    stk = read_va(rsp, 0x800)
    if stk:
        for off in range(0, 0x800, 32):
            line = []
            for i in range(4):
                qw = struct.unpack_from("<Q", stk, off + i * 8)[0]
                annot = ""
                if engine_base <= qw < engine_base + engine_size:
                    annot = f"<engine+0x{qw - engine_base:x}>"
                line.append(f"{qw:016x}{(' '+annot) if annot else ''}")
            print(f"  rsp+0x{off:04x}: {'  '.join(line)}")
