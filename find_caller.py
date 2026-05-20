"""Identify the thread that triggered the dump write. The worker is mid-write,
so the triggering thread should be blocked in WaitForSingleObject (on the
worker's done-semaphore). Look for tier0+0x1d8a0 and friends on stacks."""
import struct
from pathlib import Path
import pefile

DMP = Path(r"C:\Users\Chris\Desktop\dubiousnet\bugs\gmod client crash on third party zs server 2026-05-19\gmod.exe.29108.dmp")
TIER0 = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\tier0.dll")
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
TIER0_BASE = modules["tier0.dll"][0]

def vname(va):
    for nm, (b, sz) in modules.items():
        if b <= va < b + sz:
            return f"{nm}+0x{va-b:x}"
    return None

# Get function ranges
pe_t = pefile.PE(str(TIER0), fast_load=False)
pdata_sec = next(s for s in pe_t.sections if s.Name.rstrip(b"\x00") == b".pdata")
pdata = pe_t.__data__[pdata_sec.PointerToRawData:pdata_sec.PointerToRawData + pdata_sec.SizeOfRawData]
funcs = []
for i in range(len(pdata) // 12):
    b, e, u = struct.unpack_from("<III", pdata, i * 12)
    if b == 0: break
    funcs.append((b, e))

def func_range_rva(rva):
    for b, e in funcs:
        if b <= rva < e: return (b, e)
    return None

# Functions of interest: every "post-work-item" function and waiter
TARGETS = {
    0x1c530: "post-work-item A",
    0x1c340: "post-work-item B",
    0x1d8a0: "post-work-item C",
    # widen: function CONTAINING worker-related calls
}
# Resolve ranges
search_ranges = []
for rva, name in TARGETS.items():
    rng = func_range_rva(rva)
    if rng:
        search_ranges.append((name, TIER0_BASE + rng[0], TIER0_BASE + rng[1]))

# Also include all the Dump_* and CatchAndWriteMiniDump* and WriteMiniDump exports
for exp in pe_t.DIRECTORY_ENTRY_EXPORT.symbols:
    if exp.name:
        name = exp.name.decode("latin-1")
        if name.startswith("Dump_") or "MiniDump" in name:
            rng = func_range_rva(exp.address)
            if rng:
                search_ranges.append((name, TIER0_BASE + rng[0], TIER0_BASE + rng[1]))

print(f"Searching all threads for RAs in any of {len(search_ranges)} target functions")
for name, lo, hi in search_ranges:
    print(f"  {name}: 0x{lo:x}..0x{hi:x}")

# Walk all threads
print()
for sz, srva in streams.get(3, []):
    n_threads = struct.unpack_from("<I", dmp, srva)[0]
    off = srva + 4
    matches = []
    for i in range(n_threads):
        tid = struct.unpack_from("<I", dmp, off)[0]
        stk_start, stk_dsize, stk_rva = struct.unpack_from("<QII", dmp, off + 24)
        raw = dmp[stk_rva:stk_rva + stk_dsize] if stk_dsize else None
        if raw:
            seen = []
            for k in range(0, len(raw), 8):
                v = struct.unpack_from("<Q", raw, k)[0]
                for nm, lo, hi in search_ranges:
                    if lo <= v < hi:
                        seen.append((stk_start + k, v, nm, v - lo))
                        break
            if seen:
                matches.append((tid, seen, stk_start, stk_dsize, raw))
        off += 48

    for (tid, hits, stk_start, stk_dsize, raw) in matches:
        marker = "  <<< CRASH THREAD" if tid == 16236 else ""
        print(f"TID={tid}{marker}")
        for addr, ra, name, ooff in hits[:8]:
            print(f"   stack 0x{addr:016x} = {vname(ra)}  ({name}+0x{ooff:x})")
        # Also dump module-level RAs on this thread (top 30)
        print(f"   --- module RAs on stack (top 30) ---")
        n_shown = 0
        for k in range(0, min(len(raw), 0x600), 8):
            v = struct.unpack_from("<Q", raw, k)[0]
            n = vname(v)
            if n and not n.startswith(("ntdll", "kernelbase", "kernel32", "win32u", "ucrtbase",
                                        "user32", "rpcrt4", "combase", "msvc")):
                print(f"     +0x{k:04x}: {n}")
                n_shown += 1
                if n_shown >= 30: break
        print()

# Also: check explicitly for threads with WaitForSingleObject-style top frames AND
# significant tier0 content (the trigger thread should have a deep tier0+game stack)
print("\n\n=== Threads with TIER0 RAs only (filtering noise) ===")
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
        tier0_count = 0
        for k in range(0, len(raw), 8):
            v = struct.unpack_from("<Q", raw, k)[0]
            n = vname(v)
            if n and n.startswith("tier0.dll"):
                tier0_count += 1
        # Show only threads with substantial tier0 content
        if tier0_count >= 5:
            rip_name = vname(rip)
            marker = "  <<< CRASH THREAD" if tid == 16236 else ""
            print(f"\nTID={tid} RIP={rip_name or hex(rip)} tier0_RAs={tier0_count}{marker}")
            # Print top 20 tier0/game RAs
            shown = 0
            for k in range(0, len(raw), 8):
                v = struct.unpack_from("<Q", raw, k)[0]
                n = vname(v)
                if n and not n.startswith(("ntdll", "kernelbase", "kernel32", "win32u", "ucrtbase",
                                            "user32", "rpcrt4", "combase", "msvc")):
                    print(f"   +0x{k:04x}: {n}")
                    shown += 1
                    if shown >= 25: break
        off += 48
