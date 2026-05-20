"""
Parse engine.dll .pdata (RUNTIME_FUNCTION) table and resolve which function
contains each address of interest from the crashing stack.

Layout of RUNTIME_FUNCTION on x64 (PE+):
    DWORD BeginAddress     ; RVA of function start
    DWORD EndAddress       ; RVA of one-past-end
    DWORD UnwindInfo       ; RVA of UNWIND_INFO struct

UNWIND_INFO is in .xdata (usually inside .rdata):
    BYTE Version:3, Flags:5
    BYTE SizeOfProlog
    BYTE CountOfCodes
    BYTE FrameRegister:4, FrameOffset:4
    UNWIND_CODE[CountOfCodes]  (each 2 bytes; some operations consume more codes)
    [optional handler stuff if UNW_FLAG_EHANDLER|UNW_FLAG_UHANDLER]

We just want function boundaries and (optionally) the stack-allocation
information from the unwind codes.
"""

import sys
import struct
from pathlib import Path

import pefile

DLL = Path(r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\engine.dll")
pe = pefile.PE(str(DLL), fast_load=False)
image_base = pe.OPTIONAL_HEADER.ImageBase

# Find .pdata
pdata_sec = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".pdata")
pdata = pe.__data__[pdata_sec.PointerToRawData:pdata_sec.PointerToRawData + pdata_sec.SizeOfRawData]

n = len(pdata) // 12
funcs = []
for i in range(n):
    begin, end, unwind = struct.unpack_from("<III", pdata, i * 12)
    if begin == 0:
        break
    funcs.append((begin, end, unwind))

print(f".pdata parsed: {len(funcs)} functions")

# All RAs of interest from the crashing stack (heuristic-scanned)
RAS = [
    ("lua_shared+0x6c1a7 (return target)", None),
    ("engine+0x33b572", 0x33b572),
    ("engine+0x35f958", 0x35f958),
    ("engine+0x364851", 0x364851),
    ("engine+0x364a1f", 0x364a1f),
    ("engine+0xdd006e", 0xdd006e),
    ("engine+0x352a43", 0x352a43),
    ("engine+0x422c40", 0x422c40),
    ("engine+0x351403", 0x351403),
    ("engine+0x364815", 0x364815),
    ("engine+0x34da1c", 0x34da1c),
    ("engine+0x422c40 (2)", 0x422c40),
    ("engine+0x350215", 0x350215),
    ("engine+0x34ff12", 0x34ff12),
    ("engine+0x387738/3a", 0x387738),
    ("engine+0x34df36", 0x34df36),
    ("engine+0x352b8e", 0x352b8e),
    ("engine+0x387738", 0x387738),
    ("engine+0x21bbdc", 0x21bbdc),
    ("engine+0x21a8e1", 0x21a8e1),
]


def find_func(rva):
    lo, hi = 0, len(funcs) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        b, e, u = funcs[mid]
        if rva < b:
            hi = mid - 1
        elif rva >= e:
            lo = mid + 1
        else:
            return (b, e, u)
    return None


def section_of(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s
    return None


def read_at(rva, n):
    s = section_of(rva)
    if not s:
        return None
    return pe.__data__[s.PointerToRawData + rva - s.VirtualAddress:
                       s.PointerToRawData + rva - s.VirtualAddress + n]


# Map unwind-code op
UWOP_NAMES = {
    0: "PUSH_NONVOL",
    1: "ALLOC_LARGE",
    2: "ALLOC_SMALL",
    3: "SET_FPREG",
    4: "SAVE_NONVOL",
    5: "SAVE_NONVOL_FAR",
    8: "SAVE_XMM128",
    9: "SAVE_XMM128_FAR",
    10: "PUSH_MACHFRAME",
}


def parse_unwind(unwind_rva):
    raw = read_at(unwind_rva, 4)
    if not raw:
        return None
    ver_flags, sz_prolog, count_codes, fr_reg_off = struct.unpack("<BBBB", raw)
    version = ver_flags & 7
    flags = ver_flags >> 3
    code_bytes = read_at(unwind_rva + 4, count_codes * 2)
    codes = list(struct.unpack(f"<{count_codes}H", code_bytes))
    out = {
        "version": version,
        "flags": flags,
        "size_prolog": sz_prolog,
        "count_codes": count_codes,
        "frame_reg": fr_reg_off & 0xf,
        "frame_off": (fr_reg_off >> 4) & 0xf,
        "ops": [],
    }
    # decode codes
    i = 0
    stack_alloc = 0
    while i < count_codes:
        c = codes[i]
        off = c & 0xff
        op = (c >> 8) & 0xf
        info = (c >> 12) & 0xf
        name = UWOP_NAMES.get(op, f"OP_{op}")
        size = 1
        extra = ""
        if op == 0:  # PUSH_NONVOL
            extra = f"reg={info}"
        elif op == 1:  # ALLOC_LARGE
            if info == 0:
                amt = codes[i + 1] * 8
                size = 2
            else:
                amt = (codes[i + 1] | (codes[i + 2] << 16))
                size = 3
            stack_alloc += amt
            extra = f"alloc=0x{amt:x}"
        elif op == 2:  # ALLOC_SMALL
            amt = (info + 1) * 8
            stack_alloc += amt
            extra = f"alloc=0x{amt:x}"
        elif op == 3:
            extra = f"fpreg_set"
        elif op == 4:  # SAVE_NONVOL
            sl = codes[i + 1] * 8
            size = 2
            extra = f"reg={info} slot=0x{sl:x}"
        elif op == 5:
            sl = (codes[i + 1] | (codes[i + 2] << 16)) * 8
            size = 3
            extra = f"reg={info} slot=0x{sl:x}"
        elif op == 8:
            sl = codes[i + 1] * 16
            size = 2
            extra = f"xmm{info} slot=0x{sl:x}"
        elif op == 9:
            sl = (codes[i + 1] | (codes[i + 2] << 16)) * 16
            size = 3
            extra = f"xmm{info} slot=0x{sl:x}"
        out["ops"].append((off, name, extra))
        i += size
    # push count
    push_count = sum(1 for (_, n_, _) in out["ops"] if n_ == "PUSH_NONVOL")
    out["stack_alloc"] = stack_alloc
    out["push_count"] = push_count
    out["total_frame"] = stack_alloc + push_count * 8
    return out


print()
print("=== Functions containing crash-chain return addresses ===")
for label, rva in RAS:
    if rva is None:
        print(f"  {label:>40}  (not engine)")
        continue
    f = find_func(rva)
    if not f:
        print(f"  {label:>40}  *** no .pdata entry — possibly data ***")
        continue
    b, e, u = f
    print(f"  {label:>40}  func 0x{b:08x}..0x{e:08x}  size={e-b:>5} bytes  unwind=0x{u:x}")
    uw = parse_unwind(u)
    if uw:
        print(f"      stack_alloc=0x{uw['stack_alloc']:x}  push_count={uw['push_count']}  total_frame=0x{uw['total_frame']:x}  GS?={'yes' if uw['flags']&0x4 else 'unknown(see handler)'}")
        # if has exception handler, print
        if uw["flags"] & 0x3:
            print(f"      flags=0x{uw['flags']:x} (handler bits set)")
