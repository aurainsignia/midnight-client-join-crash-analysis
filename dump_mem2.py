"""Second-pass minidump reader.

Goals:
 1. Correctly parse the crash thread CONTEXT (fix the prior 4-byte offset bug).
 2. Walk the saved register slots in the .pdata-derived frames to recover
    the actual FILE*-equivalent arguments passed up the call chain.
 3. Look at engine.dll's runtime __pioinfo array (if discoverable) to map the
    fd value that _write rejected back to an osfhandle (which Windows handle
    type was it?).
"""
import struct
from pathlib import Path

DMP = Path(r"C:\Users\Chris\Desktop\dubiousnet\bugs\gmod client crash on third party zs server 2026-05-19\gmod.exe.29108.dmp")
data = DMP.read_bytes()

ENGINE_BASE = 0x00007ffc1f110000
ENGINE_SIZE = 0xe41000

# ---- Parse stream directory ----
sig, ver, n_streams, dir_rva = struct.unpack_from("<IIII", data, 0)
streams = {}
for i in range(n_streams):
    off = dir_rva + i * 12
    stype, sz, srva = struct.unpack_from("<III", data, off)
    streams.setdefault(stype, []).append((sz, srva))

# ---- Build memory index ----
def build_mem_index():
    idx = []
    for sz, srva in streams.get(9, []):
        n_ranges, base_rva = struct.unpack_from("<QQ", data, srva)
        cursor = base_rva
        for i in range(n_ranges):
            start, size = struct.unpack_from("<QQ", data, srva + 16 + i * 16)
            idx.append((start, start + size, cursor))
            cursor += size
    for sz, srva in streams.get(5, []):
        n_ranges = struct.unpack_from("<I", data, srva)[0]
        for i in range(n_ranges):
            off = srva + 4 + i * 16
            start, dsize, drva = struct.unpack_from("<QII", data, off)
            idx.append((start, start + dsize, drva))
    idx.sort()
    return idx

mem_idx = build_mem_index()

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

def vname(va):
    if ENGINE_BASE <= va < ENGINE_BASE + ENGINE_SIZE:
        return f"engine+0x{va - ENGINE_BASE:x}"
    return None

# ---- Crash thread CONTEXT from ThreadList stream ----
# MINIDUMP_THREAD: ULONG32 ThreadId, ULONG32 SuspendCount, ULONG32 PriorityClass,
#                  ULONG32 Priority, ULONG64 Teb, MINIDUMP_MEMORY_DESCRIPTOR Stack (16 bytes: ULONG64 Start + LOCATION 8),
#                  MINIDUMP_LOCATION_DESCRIPTOR ThreadContext (8 bytes: U32 Size, U32 Rva)
# Sized 48 bytes per entry.
print("=== Threads (looking for thread 16236) ===")
crash_ctx = None
crash_thread_stack_start = None
crash_thread_stack_size = None
for sz, srva in streams.get(3, []):
    n_threads = struct.unpack_from("<I", data, srva)[0]
    print(f"  ThreadList has {n_threads} threads")
    off = srva + 4
    for i in range(n_threads):
        tid, suspend, pri_class, pri, teb = struct.unpack_from("<IIIIQ", data, off)
        # Stack: ULONG64 StartOfMemoryRange, ULONG32 DataSize, ULONG32 Rva
        stk_start, stk_dsize, stk_rva = struct.unpack_from("<QII", data, off + 24)
        ctx_sz, ctx_rva = struct.unpack_from("<II", data, off + 24 + 16)
        if tid == 16236:
            crash_ctx = (ctx_sz, ctx_rva)
            crash_thread_stack_start = stk_start
            crash_thread_stack_size = stk_dsize
            print(f"  *** crash thread {tid}: stack=[0x{stk_start:016x}..0x{stk_start+stk_dsize:016x})  CONTEXT size=0x{ctx_sz:x} rva=0x{ctx_rva:x}")
        off += 48

if crash_ctx is None:
    raise SystemExit("crash thread not found")
ctx_sz, ctx_rva = crash_ctx
ctx = data[ctx_rva:ctx_rva + ctx_sz]
# x64 CONTEXT layout
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

print(f"\n=== CONTEXT (crash thread) ===")
print(f"  RIP=0x{rip:016x}  ({vname(rip) or ''})")
print(f"  RSP=0x{rsp:016x}")
print(f"  RAX=0x{rax:016x}   RCX=0x{rcx:016x}   RDX=0x{rdx:016x}")
print(f"  RBX=0x{rbx:016x}   RBP=0x{rbp:016x}   RSI=0x{rsi:016x}   RDI=0x{rdi:016x}")
print(f"  R8 =0x{r8:016x}   R9 =0x{r9:016x}")


# ---- Walk the .pdata-derived call chain ----
# Frame layout: (label, total_frame, expected_RA_within_engine)
# total_frame = stack_alloc + push_count * 8
FRAMES = [
    ("__report_failure",       0x28, 0x33b572),
    ("chain_walker",           0x38, 0x35f958),
    ("_write",                 0x58, 0x364851),
    ("_putc_nolock",           0x28, 0x364a1f),
    ("_putc_helper2",          0x28, 0x352a43),
    ("_write_multi_char",      0x38, 0x351403),
    ("_output_specifier",      0x88, 0x350215),
    ("_output_state_machine",  0x38, 0x34ff12),
    ("_vfprintf_internal",   0x4b8, 0x34df36),
    ("vfprintf_lockwrapper",   0x28, 0x352b8e),
    ("_vfprintf_outer",        0xc8, 0x21bbdc),
    ("engine_Sys_FPrintf",     0x48, 0x21a8e1),
]

print(f"\n=== Walking call chain from RSP=0x{rsp:016x} ===")
print(f"{'frame':>24}  {'RA at offset':>14}  {'expected':>14}  {'actual VA':>20}  {'name':<30}")
print("-" * 110)
offs = 0
for label, total, expected_rva in FRAMES:
    ra_off = offs + total
    ra_va_bytes = read_va(rsp + ra_off, 8)
    if ra_va_bytes is None:
        print(f"  {label:>24}  +0x{ra_off:04x}      expected engine+0x{expected_rva:x}  (RSP+0x{ra_off:x} NOT IN DUMP)")
    else:
        ra_va = struct.unpack("<Q", ra_va_bytes)[0]
        ra_name = vname(ra_va) or f"0x{ra_va:x}"
        match = "OK" if (ra_va - ENGINE_BASE) == expected_rva else "MISMATCH"
        print(f"  {label:>24}  +0x{ra_off:04x}      engine+0x{expected_rva:>7x}  0x{ra_va:016x}  {ra_name:<30} [{match}]")
    offs = ra_off + 8


# ---- Now extract _vfprintf_outer's saved FILE* arg from its frame ----
# Per the disassembly:
#   _vfprintf_outer's RSP-during-execution is at: crash_RSP + 0x730
#     (sum of frames below it: 0x28+0x38+0x58+0x28+0x28+0x38+0x88+0x38+0x4b8+0x28 = wait let me recompute)
# Actually the simpler way: it's at crash_RSP + (sum of total_frame for frames below + 8 for each RA between)
# But total_frame already includes the inner func's saved RA push too? No — total_frame = alloc + nonvol pushes
# of the function itself, NOT counting the RA that the call pushed.
# So unwind: callee_RSP -> caller_RSP = callee_RSP + total_frame + 8  (the +8 for the RA we pop)
def compute_active_rsp(crash_rsp, idx):
    """Compute the active RSP for FRAMES[idx] given crash_rsp = active RSP of FRAMES[0]."""
    r = crash_rsp
    for j in range(idx):
        r += FRAMES[j][1] + 8
    return r

# Index 10 is _vfprintf_outer
vfprintf_active_rsp = compute_active_rsp(rsp, 10)
print(f"\n=== _vfprintf_outer's stack frame ===")
print(f"  active RSP during _vfprintf_outer = 0x{vfprintf_active_rsp:016x}")
# rbp during this frame = active_RSP + 0xb0 - 0x3f
# Because: sub rsp, 0xb0; lea rbp, [rsp-0x3f]... no actually: lea rbp, [rsp-0x3f] WAS DONE BEFORE the
# sub rsp, 0xb0. Let me check:
#   +0x352ab4  push rbp
#   +0x352ab6  push rbx
#   +0x352ab7  push rdi
#   +0x352ab8  lea rbp, [rsp-0x3f]         ; rbp = current_rsp - 0x3f
#   +0x352abd  sub rsp, 0xb0
# So rbp was set BEFORE the alloc. At the time of `lea`, RSP was (caller_RSP - 8 - 24) = caller_RSP - 0x20.
# rbp = caller_RSP - 0x20 - 0x3f = caller_RSP - 0x5f
# After sub rsp, 0xb0: RSP = caller_RSP - 0xd0
# So rbp - active_RSP = -0x5f - (-0xd0) = 0x71
rbp_in_vfprintf = vfprintf_active_rsp + 0x71
print(f"  rbp during _vfprintf_outer = 0x{rbp_in_vfprintf:016x}")

# Saved values:
#   [rbp+0x67] = the "FILE*" arg (originally rcx at entry)
#   [rbp+0x5f] = the "stream selector" arg (originally rdx)
#   [rbp+0x6f] = the "format" arg (originally r8)
#   [rbp+0x77] = arg5 (va_list ptr)
#   [rbp+0x7f] = original 5th arg
for offset, name in [(0x67, "saved rcx (FILE*-equivalent)"),
                     (0x5f, "saved rdx (selector / extra arg)"),
                     (0x6f, "saved r8 (format string ptr)"),
                     (0x77, "saved [rsp+0x28] (va_list ptr)"),
                     (0x7f, "original arg slot at [rbp+0x7f]")]:
    b = read_va(rbp_in_vfprintf + offset, 8)
    if b is None:
        print(f"    [rbp+0x{offset:02x}] = ???  ({name})")
        continue
    v = struct.unpack("<Q", b)[0]
    annot = vname(v) or ""
    # If it's a pointer to a string, try to read it
    sval = None
    if v and (v >> 48) == 0x7ffc or (v >> 48) == 0x7ffe:
        sb = read_va(v, 128)
        if sb:
            end = sb.find(b"\x00")
            if 1 < end < 128 and all(0x20 <= c < 0x7f or c in (9, 10, 13) for c in sb[:end]):
                sval = sb[:end].decode("ascii", errors="replace")
    extra = f"  {annot}" if annot else ""
    if sval:
        extra += f'  "{sval}"'
    print(f"    [rbp+0x{offset:02x}] = 0x{v:016x}{extra}  ({name})")


# ---- Also recover the engine_Sys_FPrintf args from its own saved registers ----
# engine_Sys_FPrintf saves its args at [rsp+0x10/0x18/0x20] before the prologue.
# In the active frame: [rsp + 0x48 + 0x10] = saved-rdx (format string) ... but actually those slots
# would have been overwritten by inner calls. The function does
#   mov [rsp+0x10], rdx   (saves rdx before prologue; this is in CALLER's shadow space)
# So the saved values are in caller's shadow space, which is still alive.
sys_fprintf_active_rsp = compute_active_rsp(rsp, 11)
print(f"\n=== engine_Sys_FPrintf's frame ===")
print(f"  active RSP = 0x{sys_fprintf_active_rsp:016x}")
# After 3 pushes (rbx,rsi,rdi) + sub rsp, 0x30: active_RSP = caller_RSP - 8 - 24 - 0x30 = caller_RSP - 0x50
# Caller's shadow space starts at caller_RSP + 0x08 (the RA), so:
# Saved rcx (arg1) -> [caller_RSP + 0x08] = [active_RSP + 0x58]
# Saved rdx (arg2) -> [caller_RSP + 0x10] = [active_RSP + 0x60]
# Saved r8  (arg3) -> [caller_RSP + 0x18] = [active_RSP + 0x68]
# Saved r9  (arg4) -> [caller_RSP + 0x20] = [active_RSP + 0x70]
for offset, name in [(0x58, "caller's arg1 (rcx - the selector)"),
                     (0x60, "caller's arg2 (rdx - format string)"),
                     (0x68, "caller's arg3 (r8 - va_arg #1)"),
                     (0x70, "caller's arg4 (r9 - va_arg #2)")]:
    b = read_va(sys_fprintf_active_rsp + offset, 8)
    if b is None:
        print(f"    [rsp+0x{offset:02x}] = ???  ({name})")
        continue
    v = struct.unpack("<Q", b)[0]
    annot = vname(v) or ""
    sval = None
    if v and ((v >> 48) in (0x7ffc, 0x7ffe, 0x7ffb, 0x7fff)):
        sb = read_va(v, 256)
        if sb:
            end = sb.find(b"\x00")
            if 1 < end < 256 and all(0x20 <= c < 0x7f or c in (9, 10, 13) for c in sb[:end]):
                sval = sb[:end].decode("ascii", errors="replace")
    extra = f"  {annot}" if annot else ""
    if sval:
        extra += f'  "{sval[:200]}"'
    print(f"    [rsp+0x{offset:02x}] = 0x{v:016x}{extra}  ({name})")


# ---- Dump 16 qwords around the boundary between vfprintf_outer's frame and sys_fprintf's ----
print(f"\n=== Stack around the vfprintf_outer/engine_Sys_FPrintf boundary ===")
boundary = vfprintf_active_rsp + 0xc8 + 8  # active sys_fprintf RSP
for k in range(-8, 24):
    addr = boundary + k * 8
    b = read_va(addr, 8)
    if not b:
        continue
    v = struct.unpack("<Q", b)[0]
    annot = vname(v) or ""
    sval = ""
    if v and ((v >> 48) in (0x7ffc, 0x7ffe, 0x7ffb, 0x7fff)):
        sb = read_va(v, 64)
        if sb:
            end = sb.find(b"\x00")
            if 1 < end < 64 and all(0x20 <= c < 0x7f or c in (9, 10, 13) for c in sb[:end]):
                sval = f'  "{sb[:end].decode()}"'
    print(f"  rsp+0x{addr-rsp:04x} = 0x{addr:016x} : 0x{v:016x}  {annot}{sval}")
