"""Scan all 81 threads in the minidump, classify each by RIP location, and
look for the thread that triggered the crash report. Also dump the
MiscInfoStream and any other interesting streams."""
import struct
from pathlib import Path

DMP = Path(r"C:\Users\Chris\Desktop\dubiousnet\bugs\gmod client crash on third party zs server 2026-05-19\gmod.exe.29108.dmp")
dmp = DMP.read_bytes()

sig, ver, n_streams, dir_rva = struct.unpack_from("<IIII", dmp, 0)
streams = {}
for i in range(n_streams):
    off = dir_rva + i * 12
    stype, sz, srva = struct.unpack_from("<III", dmp, off)
    streams.setdefault(stype, []).append((sz, srva))

# Modules
modules = []
for sz, srva in streams.get(4, []):
    n_mods = struct.unpack_from("<I", dmp, srva)[0]
    off = srva + 4
    for _ in range(n_mods):
        base, size_img, _csum, _ts, name_rva = struct.unpack_from("<QIIII", dmp, off)
        slen = struct.unpack_from("<I", dmp, name_rva)[0]
        name = dmp[name_rva + 4:name_rva + 4 + slen].decode("utf-16-le", errors="replace")
        modules.append((base, size_img, name.split("\\")[-1]))
        off += 108
modules.sort()

def vname(va):
    # bsearch
    lo, hi = 0, len(modules) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        b, s, n = modules[mid]
        if va < b: hi = mid - 1
        elif va >= b + s: lo = mid + 1
        else: return f"{n.lower()}+0x{va-b:x}"
    return None

# Memory index
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

# ThreadList stream
print(f"=== Threads ===")
for sz, srva in streams.get(3, []):
    n_threads = struct.unpack_from("<I", dmp, srva)[0]
    off = srva + 4
    rows = []
    for i in range(n_threads):
        tid, suspend, pri_class, pri, teb = struct.unpack_from("<IIIIQ", dmp, off)
        stk_start, stk_dsize, stk_rva = struct.unpack_from("<QII", dmp, off + 24)
        ctx_sz, ctx_rva = struct.unpack_from("<II", dmp, off + 24 + 16)
        ctx = dmp[ctx_rva:ctx_rva + ctx_sz] if ctx_sz else None
        if ctx and len(ctx) >= 0x100:
            rip = struct.unpack_from("<Q", ctx, 0xf8)[0]
            rsp = struct.unpack_from("<Q", ctx, 0x98)[0]
        else:
            rip = rsp = 0
        rows.append((tid, suspend, rip, rsp, stk_start, stk_dsize))
        off += 48
    # sort by tid
    rows.sort()
    for (tid, suspend, rip, rsp, stk_start, stk_dsize) in rows:
        name = vname(rip) or f"0x{rip:x}"
        marker = "  <<< CRASH THREAD" if tid == 16236 else ""
        print(f"  TID={tid:>5} sus={suspend} RIP={rip:016x} {name:<60} stack=[0x{stk_start:x}..0x{stk_start+stk_dsize:x}){marker}")

# Find threads that look "interesting" - RIP in engine, server, lua_shared, etc.
print("\n=== Threads with RIP in game-DLL code (not waiting in kernel) ===")
for sz, srva in streams.get(3, []):
    n_threads = struct.unpack_from("<I", dmp, srva)[0]
    off = srva + 4
    for i in range(n_threads):
        tid, suspend, pri_class, pri, teb = struct.unpack_from("<IIIIQ", dmp, off)
        stk_start, stk_dsize, stk_rva = struct.unpack_from("<QII", dmp, off + 24)
        ctx_sz, ctx_rva = struct.unpack_from("<II", dmp, off + 24 + 16)
        ctx = dmp[ctx_rva:ctx_rva + ctx_sz] if ctx_sz else None
        if ctx and len(ctx) >= 0x100:
            rip = struct.unpack_from("<Q", ctx, 0xf8)[0]
            rsp = struct.unpack_from("<Q", ctx, 0x98)[0]
            name = vname(rip) or ""
            # Filter: not in ntdll/kernel32/kernelbase/win32u
            kernel_mods = ("ntdll", "kernel32", "kernelbase", "win32u", "user32", "rpcrt4", "combase", "ucrtbase")
            if name and not any(name.startswith(m) for m in kernel_mods):
                marker = "  <<< CRASH THREAD" if tid == 16236 else ""
                print(f"  TID={tid:>5} RIP={rip:016x}  {name}{marker}")
                # scan stack for return addresses
                stk = read_va(rsp, 0x800) if rsp else None
                if stk:
                    seen = set()
                    for k in range(0, len(stk), 8):
                        v = struct.unpack_from("<Q", stk, k)[0]
                        n = vname(v)
                        if n and v not in seen:
                            seen.add(v)
                            print(f"           rsp+0x{k:04x}: {n}")
                            if len(seen) > 20: break
        off += 48

# Misc Info Stream
print("\n=== Misc Info Stream (type 24) ===")
for sz, srva in streams.get(24, []):
    # MINIDUMP_MISC_INFO has variable size; let's just dump 0xdc bytes
    raw = dmp[srva:srva+0xdc]
    sz_of = struct.unpack_from("<I", raw, 0)[0]
    flags1 = struct.unpack_from("<I", raw, 4)[0]
    pid = struct.unpack_from("<I", raw, 8)[0]
    print(f"  SizeOfInfo={sz_of}  Flags1=0x{flags1:x}  ProcessId={pid}")
    print(f"  hex first 0x80:")
    for i in range(0, 0x80, 16):
        chunk = raw[i:i+16]
        hx = " ".join(f"{c:02x}" for c in chunk)
        ax = "".join(chr(c) if 0x20 <= c < 0x7f else "." for c in chunk)
        print(f"    +0x{i:02x}: {hx:<48}  {ax}")

# Search dmp for the GUID we found
print("\n=== Search for the GUID '914fa858-b8e7-480e-b4a7-c05093ef0bb0' in dump ===")
ascii_target = b"914fa858-b8e7-480e-b4a7-c05093ef0bb0"
wide_target = ascii_target.decode().encode("utf-16-le")
hits_a = []
off = 0
while True:
    i = dmp.find(ascii_target, off)
    if i < 0: break
    hits_a.append(i)
    off = i + 1
hits_w = []
off = 0
while True:
    i = dmp.find(wide_target, off)
    if i < 0: break
    hits_w.append(i)
    off = i + 1
print(f"  ASCII hits: {len(hits_a)}")
for i in hits_a[:5]:
    print(f"    file offset 0x{i:x}")
print(f"  UTF-16 hits: {len(hits_w)}")
for i in hits_w[:5]:
    print(f"    file offset 0x{i:x}")
    # Find which memory range this falls in
    for s, e, fo in mem_idx:
        if fo <= i < fo + (e - s):
            va = s + (i - fo)
            print(f"      -> VA 0x{va:016x}")
            break
