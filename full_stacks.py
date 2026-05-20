"""Exhaustively scan ALL thread stacks for ANY return-address-like value
into tier0+0x1d8a0..0x1dab7 (post-work-item C with WaitForSingleObject) or
related queueing functions. Print full module RA lists for each thread."""
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

def vname(va):
    for nm, (b, sz) in modules.items():
        if b <= va < b + sz:
            return f"{nm}+0x{va-b:x}"
    return None

TIER0_BASE = modules["tier0.dll"][0]
# Look for RAs into post-work-item C (waits for worker): 0x1d8a0..0x1dab7
WAIT_LO = TIER0_BASE + 0x1d8a0
WAIT_HI = TIER0_BASE + 0x1dab7

print(f"Searching for ANY value in [0x{WAIT_LO:x}..0x{WAIT_HI:x}) on any stack...")

# Walk all threads' captured stacks
for sz, srva in streams.get(3, []):
    n_threads = struct.unpack_from("<I", dmp, srva)[0]
    off = srva + 4
    for i in range(n_threads):
        tid = struct.unpack_from("<I", dmp, off)[0]
        stk_start, stk_dsize, stk_rva = struct.unpack_from("<QII", dmp, off + 24)
        ctx_sz, ctx_rva = struct.unpack_from("<II", dmp, off + 24 + 16)
        ctx = dmp[ctx_rva:ctx_rva + ctx_sz] if ctx_sz else None
        rip = struct.unpack_from("<Q", ctx, 0xf8)[0] if (ctx and len(ctx) > 0x100) else 0
        raw = dmp[stk_rva:stk_rva + stk_dsize] if stk_dsize else None
        if not raw:
            off += 48; continue

        # Check all qwords for hit
        hits = []
        for k in range(0, len(raw), 8):
            v = struct.unpack_from("<Q", raw, k)[0]
            if WAIT_LO <= v < WAIT_HI:
                hits.append((stk_start + k, v))
        if hits:
            rip_name = vname(rip) or hex(rip)
            print(f"\n*** TID={tid} RIP={rip_name}  stack 0x{stk_start:016x}..0x{stk_start+stk_dsize:016x}")
            for addr, v in hits:
                name = vname(v) or hex(v)
                print(f"  stack[0x{addr:016x}] = {name}")
        off += 48

# Also dump full RA list of TID 27040 (the main thread) — no filter
print("\n\n=== Full RA list of TID 27040 (no filter) ===")
for sz, srva in streams.get(3, []):
    n_threads = struct.unpack_from("<I", dmp, srva)[0]
    off = srva + 4
    for i in range(n_threads):
        tid = struct.unpack_from("<I", dmp, off)[0]
        if tid != 27040:
            off += 48; continue
        stk_start, stk_dsize, stk_rva = struct.unpack_from("<QII", dmp, off + 24)
        raw = dmp[stk_rva:stk_rva + stk_dsize] if stk_dsize else None
        print(f"  stack range: 0x{stk_start:x}..0x{stk_start+stk_dsize:x}  ({stk_dsize} bytes)")
        if raw:
            for k in range(0, len(raw), 8):
                v = struct.unpack_from("<Q", raw, k)[0]
                n = vname(v)
                if n:
                    # show only top 60
                    print(f"    0x{stk_start+k:016x}: {n}")
        off += 48
        break
