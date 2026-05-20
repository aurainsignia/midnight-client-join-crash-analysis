"""
engine.dll targeted disassembler for the 2026-05-19 crash.

Goals:
 1. Disassemble the function spanning engine.dll+0x33b572 .. +0x33b5dc and beyond,
    so we can read what code lives at the faulting RIP.
 2. Identify imported CRT / security functions and check whether any of them are
    invoked from inside the crashing function — that tells us *which* fast-fail
    class this is (stack cookie vs invalid-parameter vs heap corruption).
 3. Walk back to the function entry, find the prologue and the local-buffer size
    if the function uses a stack frame.
 4. Pull out near-by string xrefs (rip+disp32 -> .rdata) so we have a chance of
    naming the function from its format strings or error literals.

Usage:
    python disasm.py <engine.dll> [start_rva_hex] [length_bytes]

Defaults: start_rva = 0x33b500 (a bit before the function entry), length = 0x400.
"""

import sys
import re
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CsError

DLL = Path(sys.argv[1] if len(sys.argv) > 1 else r"C:\Program Files (x86)\Steam\steamapps\common\GarrysMod\bin\win64\engine.dll")
START_RVA = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x33b500
LENGTH = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x400

CRASH_RVA = 0x33b5dc
FUNC_ENTRY_RVA = 0x33b572

# Engine.dll RVA offsets of frames on the crashing stack, from oldest to newest
# (annotated from the README stack scan).
STACK_RVAS = [
    0x21a8e1, 0x21bbdc, 0x387738, 0x352b8e, 0x34df36, 0x387738,
    0x387738, 0x38773a, 0x34ff12, 0x350215, 0x351403, 0x422c40,
    0x34da1c, 0x422c40, 0x364815, 0x352a43, 0xdd006e, 0x364851,
    0x364a1f, 0x35f958, 0x33b572, 0x33b5dc,
]

pe = pefile.PE(str(DLL), fast_load=False)
image_base = pe.OPTIONAL_HEADER.ImageBase
print(f"Image base:   0x{image_base:016x}")
print(f"Sections:")
for s in pe.sections:
    name = s.Name.rstrip(b"\x00").decode("latin-1")
    print(f"  {name:>10}  VA=0x{s.VirtualAddress:08x}  Vsize=0x{s.Misc_VirtualSize:08x}  RawPtr=0x{s.PointerToRawData:08x}")


def section_of(rva):
    for s in pe.sections:
        if s.VirtualAddress <= rva < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s
    return None


def rva_to_file(rva):
    s = section_of(rva)
    if not s:
        return None
    return s.PointerToRawData + (rva - s.VirtualAddress)


def read_rva(rva, n):
    s = section_of(rva)
    if not s:
        return None
    return pe.get_data(rva, n)


# Build an import resolution map keyed by RVA of the IAT slot.
print("\n=== Imports of interest ===")
iat_by_rva = {}
imp_interest = ("__report_gsfailure", "_invalid_parameter", "_invalid_parameter_noinfo",
                "__fastfail", "__failfast", "_CxxThrowException",
                "_security_check_cookie", "__security_check_cookie",
                "memcpy", "memmove", "memset", "strcpy", "strncpy",
                "strcat", "strncat", "sprintf", "vsprintf", "snprintf", "vsnprintf",
                "sprintf_s", "vsprintf_s", "_snprintf", "_vsnprintf",
                "strcpy_s", "strncpy_s", "strcat_s", "wcscpy_s", "wcsncpy_s",
                "lua_pcall", "lua_call", "lua_pushstring", "lua_tolstring",
                "lua_tostring", "lua_pushlstring", "luaL_error", "lua_error",
                "_chkstk")
imp_addrs = {}  # name -> IAT VA
if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode("latin-1")
        for imp in entry.imports:
            name = imp.name.decode("latin-1") if imp.name else f"ord_{imp.ordinal}"
            iat_by_rva[imp.address - image_base] = (dll, name)
            imp_addrs[name] = imp.address - image_base
            if any(needle in name for needle in imp_interest):
                print(f"  {dll:>20} :: {name}  IAT_RVA=0x{imp.address - image_base:08x}")

# Some compilers compile-in __security_check_cookie / __report_gsfailure as
# local exported/non-imported helpers. Try to find them by export table.
print("\n=== Suspicious exports (security/CRT helpers) ===")
if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name:
            n = exp.name.decode("latin-1")
            if any(needle in n for needle in imp_interest):
                print(f"  {n}  RVA=0x{exp.address:08x}")

# Resolve a target of a CALL or JMP that uses rip+disp32 form.
def resolve_call(insn):
    """Given an insn, if it is a call/jmp with a single op that is a memory or
    immediate target, return ('direct', target_rva) or ('indirect-iat',
    iat_rva, (dll, name)) or None."""
    mn = insn.mnemonic
    if mn not in ("call", "jmp"):
        return None
    if len(insn.operands) != 1:
        return None
    op = insn.operands[0]
    if op.type == 2:  # IMM
        target = op.imm - image_base
        return ("direct", target)
    if op.type == 3:  # MEM
        # rip-relative?
        if op.mem.base == 41 and op.mem.index == 0:  # RIP base in capstone x86
            target_va = insn.address + insn.size + op.mem.disp
            target_rva = target_va - image_base
            if target_rva in iat_by_rva:
                return ("indirect-iat", target_rva, iat_by_rva[target_rva])
            return ("indirect-mem", target_rva)
    return None


# Resolve a string at a given RVA (returns ASCII string with NUL-terminator).
def try_string(rva, maxlen=200):
    s = section_of(rva)
    if not s:
        return None
    try:
        raw = pe.get_data(rva, min(maxlen, s.SizeOfRawData))
    except pefile.PEFormatError:
        return None
    end = raw.find(b"\x00")
    if end < 4 or end > 200:
        return None
    sub = raw[:end]
    if all(0x20 <= b < 0x7f or b in (9, 10, 13) for b in sub):
        return sub.decode("ascii", errors="replace")
    return None


md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True


def disasm_window(rva, length, label=""):
    file_off = rva_to_file(rva)
    if file_off is None:
        print(f"[no section for RVA 0x{rva:x}]")
        return
    data = pe.__data__[file_off:file_off + length]
    print(f"\n=== Disassembly @ engine.dll+0x{rva:x} ({label}) ===")
    addr_va = image_base + rva
    for insn in md.disasm(bytes(data), addr_va):
        insn_rva = insn.address - image_base
        marker = ""
        if insn_rva == CRASH_RVA:
            marker += "   <<< CRASH RIP"
        if insn_rva == FUNC_ENTRY_RVA:
            marker += "   <<< caller-return target / func entry"
        # Identify call/jmp targets
        annot = ""
        r = resolve_call(insn)
        if r:
            if r[0] == "direct":
                target = r[1]
                # is the target itself an indirect jmp to an IAT slot?
                tgt_file = rva_to_file(target)
                if tgt_file is not None:
                    snip = pe.__data__[tgt_file:tgt_file + 6]
                    if len(snip) == 6 and snip[0] == 0xff and snip[1] == 0x25:
                        # jmp qword ptr [rip+disp32]  -- thunk
                        disp = int.from_bytes(snip[2:6], "little", signed=True)
                        thunk_target = target + 6 + disp
                        if thunk_target in iat_by_rva:
                            annot = f"  ; thunk -> {iat_by_rva[thunk_target][1]} ({iat_by_rva[thunk_target][0]})"
                        else:
                            annot = f"  ; thunk -> 0x{thunk_target:x}"
                    else:
                        annot = f"  ; -> engine.dll+0x{target:x}"
                else:
                    annot = f"  ; -> 0x{target:x}"
            elif r[0] == "indirect-iat":
                annot = f"  ; -> {r[2][1]} ({r[2][0]})"
            elif r[0] == "indirect-mem":
                annot = f"  ; -> [engine.dll+0x{r[1]:x}]"

        # rip-relative LEA / MOV referencing .rdata -- look up as string
        if insn.mnemonic in ("lea", "mov") and len(insn.operands) == 2:
            for op in insn.operands:
                if op.type == 3 and op.mem.base == 41:  # RIP-rel mem
                    tgt = insn.address + insn.size + op.mem.disp - image_base
                    sec = section_of(tgt)
                    if sec is not None:
                        sname = sec.Name.rstrip(b"\x00").decode("latin-1")
                        if sname in (".rdata", ".data"):
                            sval = try_string(tgt)
                            if sval:
                                annot += f"   ; \"{sval}\""

        print(f"  {insn.address:016x}  {insn.bytes.hex():<24} {insn.mnemonic:<8} {insn.op_str}{annot}{marker}")


# 1) The function around the crash
disasm_window(START_RVA, LENGTH, label="around the crash; entry +0x33b572, RIP +0x33b5dc")

# 2) The two immediate-caller frames
for rva in [0x35f958, 0x364a1f, 0x364851, 0x364815, 0x352a43, 0x35f000, 0x422c40,
            0x351403, 0x350215, 0x34ff12, 0x34df36, 0x352b8e, 0x387738, 0x34da1c]:
    disasm_window(rva - 0x30, 0x80, label=f"stack frame engine.dll+0x{rva:x}")

# 3) Try to find the function ENTRY by walking backwards from 0x33b572 to nearest
#    INT3 / RET that precedes a typical x64 prologue (sub rsp / push rbp / mov rsp).
print("\n=== Backward walk to detect true function entry ===")
# Read 0x200 bytes before
back_start = 0x33b572 - 0x200
back_file = rva_to_file(back_start)
back_data = pe.__data__[back_file:back_file + 0x200]
last_ret_or_int3 = None
for insn in md.disasm(bytes(back_data), image_base + back_start):
    if insn.mnemonic in ("ret", "retf", "int3"):
        last_ret_or_int3 = insn.address - image_base + insn.size
print(f"  last ret/int3 before 0x33b572 ended at: 0x{last_ret_or_int3:x}" if last_ret_or_int3 else "  (none found)")
