"""Find tier0.dll's exported Dump_CreateDump RVA, then scan all thread stacks
for return addresses pointing inside Dump_CreateDump — that thread is the
trigger."""
import struct
from pathlib import Path
import pefile

DMP = Path(r"C:\Users\Chris\Desktop\dubiousnet\bugs\gmod client crash on third party zs server 2026-05-19\gmod.exe.29108.dmp")
TIER0 = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\tier0.dll")
ENGINE = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\engine.dll")
dmp = DMP.read_bytes()

# Streams
sig, ver, n_streams, dir_rva = struct.unpack_from("<IIII", dmp, 0)
streams = {}
for i in range(n_streams):
    off = dir_rva + i * 12
    stype, sz, srva = struct.unpack_from("<III", dmp, off)
    streams.setdefault(stype, []).append((sz, srva))

# Modules
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
ENGINE_BASE = modules["engine.dll"][0]
LUA_BASE = modules["lua_shared.dll"][0]

def vname(va):
    for nm, (b, sz) in modules.items():
        if b <= va < b + sz:
            return f"{nm}+0x{va-b:x}"
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

# Find tier0's exports
pe_t = pefile.PE(str(TIER0), fast_load=False)
DUMP_FUNCS = {}  # name -> rva
for exp in pe_t.DIRECTORY_ENTRY_EXPORT.symbols:
    if exp.name:
        name = exp.name.decode("latin-1")
        if name.startswith("Dump_") or name in ("WriteMiniDump",) or name.startswith("Plat_Exit") or name.startswith("Plat_Fatal") or "MiniDump" in name:
            DUMP_FUNCS[name] = exp.address
            print(f"  tier0!{name} = +0x{exp.address:x}")

# Now build the targets: tier0+RVA + small range (functions are <500 bytes)
# We want to find return addresses INSIDE these functions on any thread stack
# (i.e. RA values that fall into [start, start+0x500) approximately).
# Better: use .pdata of tier0 to get exact ranges
pdata_sec = next(s for s in pe_t.sections if s.Name.rstrip(b"\x00") == b".pdata")
pdata = pe_t.__data__[pdata_sec.PointerToRawData:pdata_sec.PointerToRawData + pdata_sec.SizeOfRawData]
funcs = []
for i in range(len(pdata) // 12):
    b, e, u = struct.unpack_from("<III", pdata, i * 12)
    if b == 0: break
    funcs.append((b, e))

def func_range(rva):
    for b, e in funcs:
        if b <= rva < e: return (b, e)
    return None

# Build a list of (name, va_lo, va_hi) for each target function
search_targets = []
for name, rva in DUMP_FUNCS.items():
    rng = func_range(rva)
    if rng:
        b, e = rng
        search_targets.append((name, TIER0_BASE + b, TIER0_BASE + e))
    else:
        # use a default 0x200 window
        search_targets.append((name, TIER0_BASE + rva, TIER0_BASE + rva + 0x200))

print(f"\nScanning all thread stacks for RAs inside these functions...")

# Walk all threads' stacks
for sz, srva in streams.get(3, []):
    n_threads = struct.unpack_from("<I", dmp, srva)[0]
    off = srva + 4
    hits_per_thread = []
    for i in range(n_threads):
        tid = struct.unpack_from("<I", dmp, off)[0]
        stk_start, stk_dsize, stk_rva = struct.unpack_from("<QII", dmp, off + 24)
        ctx_sz, ctx_rva = struct.unpack_from("<II", dmp, off + 24 + 16)
        # We have the stack stored at stk_rva inside the dump (or via mem index)
        # The "stk_start" is the bottom of stack (highest committed VA), and the
        # stack grows down. The captured chunk starts at stk_start (which is rsp).
        # Try reading from stk_start for stk_dsize bytes.
        raw = dmp[stk_rva:stk_rva + stk_dsize] if stk_dsize else None
        if raw is None:
            off += 48
            continue
        hits = []
        for k in range(0, len(raw), 8):
            v = struct.unpack_from("<Q", raw, k)[0]
            for name, va_lo, va_hi in search_targets:
                if va_lo <= v < va_hi:
                    hits.append((stk_start + k, v, name, v - va_lo))
                    break
        if hits:
            hits_per_thread.append((tid, hits))
        off += 48
    print(f"\n=== Threads with RAs inside Dump_* functions ===")
    for tid, hits in hits_per_thread:
        marker = "  <<< CRASH THREAD" if tid == 16236 else ""
        print(f"  TID={tid}{marker}")
        for addr, ra, name, off_in_fn in hits[:6]:
            print(f"     stack 0x{addr:016x} = 0x{ra:016x}  ({name}+0x{off_in_fn:x})")


# Also scan all thread stacks for known callable RAs (anything pointing into
# engine, tier0, lua_shared) for the active (non-waiting) threads
print("\n\n=== Stack traces of threads with rich frames (more than 30 module RAs) ===")
for sz, srva in streams.get(3, []):
    n_threads = struct.unpack_from("<I", dmp, srva)[0]
    off = srva + 4
    interesting = []
    for i in range(n_threads):
        tid = struct.unpack_from("<I", dmp, off)[0]
        stk_start, stk_dsize, stk_rva = struct.unpack_from("<QII", dmp, off + 24)
        raw = dmp[stk_rva:stk_rva + stk_dsize] if stk_dsize else None
        if raw:
            seen = set()
            for k in range(0, len(raw), 8):
                v = struct.unpack_from("<Q", raw, k)[0]
                # is v inside any non-kernel module?
                for nm in ("engine.dll", "tier0.dll", "lua_shared.dll", "vstdlib.dll",
                           "menusystem.dll", "client.dll", "server.dll", "matchmaking.dll",
                           "vphysics.dll"):
                    if nm in modules:
                        b, sz_m = modules[nm]
                        if b <= v < b + sz_m:
                            seen.add(v)
            if len(seen) >= 20:
                interesting.append((tid, len(seen), stk_start, stk_dsize, raw))
        off += 48
    print(f"  Found {len(interesting)} threads with >=20 RAs into game modules")
    for (tid, count, stk_start, stk_dsize, raw) in interesting[:5]:
        marker = "  <<< CRASH THREAD" if tid == 16236 else ""
        print(f"\n  TID={tid} ({count} game RAs, stack size 0x{stk_dsize:x}){marker}")
        last_va = None
        for k in range(0, min(len(raw), 0x300), 8):
            v = struct.unpack_from("<Q", raw, k)[0]
            n = vname(v)
            if n and not n.startswith(("ntdll", "kernelbase", "kernel32", "win32u", "ucrtbase",
                                        "user32", "rpcrt4", "combase", "msvc")):
                print(f"     +0x{k:04x}: {n}")
