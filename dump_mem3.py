"""Read the strings & heap data referenced from the crash chain to identify
what was being logged."""
import struct
from pathlib import Path

DMP = Path(r"C:\Users\Chris\Desktop\dubiousnet\bugs\gmod client crash on third party zs server 2026-05-19\gmod.exe.29108.dmp")
data = DMP.read_bytes()

ENGINE_BASE = 0x00007ffc1f110000

# Build mem index
sig, ver, n_streams, dir_rva = struct.unpack_from("<IIII", data, 0)
streams = {}
for i in range(n_streams):
    off = dir_rva + i * 12
    stype, sz, srva = struct.unpack_from("<III", data, off)
    streams.setdefault(stype, []).append((sz, srva))

mem_idx = []
for sz, srva in streams.get(9, []):
    n_ranges, base_rva = struct.unpack_from("<QQ", data, srva)
    cursor = base_rva
    for i in range(n_ranges):
        start, size = struct.unpack_from("<QQ", data, srva + 16 + i * 16)
        mem_idx.append((start, start + size, cursor))
        cursor += size
for sz, srva in streams.get(5, []):
    n_ranges = struct.unpack_from("<I", data, srva)[0]
    for i in range(n_ranges):
        off = srva + 4 + i * 16
        start, dsize, drva = struct.unpack_from("<QII", data, off)
        mem_idx.append((start, start + dsize, drva))
mem_idx.sort()


def read_va(va, n):
    for s, e, fo in mem_idx:
        if s <= va and va + n <= e:
            return data[fo + (va - s):fo + (va - s) + n]
        if s <= va < e:
            avail = e - va
            partial = data[fo + (va - s):fo + (va - s) + avail]
            rest = read_va(e, n - avail)
            return partial + (rest if rest else b"\x00" * (n - avail))
    return None


def read_str(va, maxlen=512):
    b = read_va(va, maxlen)
    if not b:
        return None
    end = b.find(b"\x00")
    if end < 1 or end > maxlen - 1:
        return None
    if all(0x20 <= c < 0x7f or c in (9, 10, 13) for c in b[:end]):
        return b[:end].decode("ascii")
    return None


# 1) Strings at the addresses we found
for va, label in [
    (0x00007ffc1f497738, "engine+0x387738 (format-ptr saved by _vfprintf_outer)"),
    (0x0000023d0ec49f70, "saved-rdx selector (heap ptr seen as caller's r9 / saved rdx)"),
    (0x0000023cafdb99e0, "engine_Sys_FPrintf's arg2 (heap)"),
    (0x000000667cd7ee50, "engine_Sys_FPrintf's arg3 (stack ptr — likely buf)"),
]:
    print(f"\n=== {label} ===  VA=0x{va:016x}")
    s = read_str(va, 512)
    if s is not None:
        print(f'  string: "{s}"')
    raw = read_va(va, 128)
    if raw is None:
        print("  (not in dump)")
    else:
        print("  raw 128 bytes:")
        for i in range(0, 128, 16):
            chunk = raw[i:i+16]
            hx = " ".join(f"{c:02x}" for c in chunk)
            ax = "".join(chr(c) if 0x20 <= c < 0x7f else "." for c in chunk)
            print(f"    +0x{i:02x}: {hx:<48}  {ax}")


# 2) The next-up frame's RA (above engine_Sys_FPrintf) is in the chained funclet
# at engine+0x21a8ba. That funclet's parent is 0x21a890. Walk one more frame.
# 0x21a8ba has total_frame = 0 (UNW_FLAG_CHAININFO), so it doesn't unwind; we
# trace through the parent 0x21a890.
# Parent prologue: push rdi; sub rsp, 0x20. So parent's total_frame = 0x28.
# But since the funclet is chained, it's the funclet's own RIP that's saved on
# entry — not new frame. So the next "real" RA is at engine_Sys_FPrintf's
# caller offset, which we computed = +0x848 = engine+0x21a8e1.
# From the parent function 0x21a890, total_frame = 0x28 (1 push + 0x20 alloc).
# So *parent's* caller RA is at offset 0x848 + 0x28 = 0x870. Let me check.
# Actually wait — engine_Sys_FPrintf's caller IS the funclet (since RA pts there).
# The funclet's "parent" registers as 0x21a890, but in terms of RSP unwinding,
# the funclet doesn't add a frame — the parent's frame is active.
# So whoever called the parent function 0x21a890 has their RA at:
#   sys_fprintf_caller_RSP + (parent's total_frame - shared frame size)
# This needs careful handling. Let me just dump 8 qwords past +0x848 to see.

crash_rsp = 0x000000667cd7ebd0
print("\n=== Stack starting at engine_Sys_FPrintf's caller (RSP+0x848) onward ===")
print("    Walking for the parent of the chained funclet (0x21a890), then its caller.")
for k in range(0, 32):
    off = 0x848 + k * 8
    b = read_va(crash_rsp + off, 8)
    if not b:
        continue
    v = struct.unpack("<Q", b)[0]
    annot = ""
    sval = ""
    if ENGINE_BASE <= v < ENGINE_BASE + 0xe41000:
        annot = f"engine+0x{v-ENGINE_BASE:x}"
    if v >> 48 in (0x7ffc, 0x7ffe, 0x7ffb, 0x7fff):
        s = read_str(v, 100)
        if s:
            sval = f'  "{s[:80]}"'
    print(f"  rsp+0x{off:04x} = 0x{v:016x}  {annot}{sval}")


# 3) Also try following _vfprintf_internal's stack alloc to find the format-state struct
# which would contain the actual FILE* and format pointer the CRT uses internally.
# _vfprintf_internal has a 0x4b8 frame and stack-allocates the format-state. The state
# struct starts somewhere inside that frame and is referenced via rbx in subsequent
# functions. Without re-tracing in full, just dump that region for inspection.
FRAMES = [
    ("__report_failure",       0x28),
    ("chain_walker",           0x38),
    ("_write",                 0x58),
    ("_putc_nolock",           0x28),
    ("_putc_helper2",          0x28),
    ("_write_multi_char",      0x38),
    ("_output_specifier",      0x88),
    ("_output_state_machine",  0x38),
    ("_vfprintf_internal",   0x4b8),
    ("vfprintf_lockwrapper",   0x28),
    ("_vfprintf_outer",        0xc8),
    ("engine_Sys_FPrintf",     0x48),
]

def compute_active_rsp(idx):
    r = crash_rsp
    for j in range(idx):
        r += FRAMES[j][1] + 8
    return r

vfi_active = compute_active_rsp(8)
print(f"\n=== _vfprintf_internal frame (active RSP = 0x{vfi_active:016x}, size 0x4b8) ===")
# Dump first 0x100 bytes of the frame as qwords
for k in range(0, 0x100 // 8):
    off = k * 8
    b = read_va(vfi_active + off, 8)
    if not b: break
    v = struct.unpack("<Q", b)[0]
    annot = ""
    sval = ""
    if ENGINE_BASE <= v < ENGINE_BASE + 0xe41000:
        annot = f"engine+0x{v-ENGINE_BASE:x}"
    if v >> 48 in (0x7ffc, 0x7ffe, 0x7ffb, 0x7fff):
        s = read_str(v, 80)
        if s:
            sval = f'  "{s[:60]}"'
    print(f"  vfi+0x{off:03x}: 0x{v:016x}  {annot}{sval}")
