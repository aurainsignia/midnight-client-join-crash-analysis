# GMod client crash on third-party ZS server — 2026-05-19

## Symptom

Aura was playing on a third-party Zombie Survival server (not our dev
local) earlier on 2026-05-19. Client crashed; Windows wrote a full
process minidump to `C:\Users\Aura Insignia\AppData\Local\CrashDumps\`.

This is unrelated to our gamemode work — different server, different
build of someone else's ZS. Investigation is about understanding the
crash class in case the same pattern can reach our own deploy.

## Crash dump

- Path: `C:\Users\Aura Insignia\AppData\Local\CrashDumps\gmod.exe.29108.dmp`
- Size: ~92 MB (full process minidump)
- Created: 2026-05-19 10:43:00
- Process: `gmod.exe` (client), Windows 11 build 26100, x64

## Diagnostic process

Same as the vphysics-crash workflow under `bugs/vphysics crashes/` — no
cdb/windbg locally, so the analysis is done by a PowerShell minidump
parser (`analyze_crash.ps1` in this folder) that pulls the exception
record, the module list, the crashing thread's CONTEXT, and walks the
stack memory looking for values that fall inside a loaded module
(probable return addresses).

Engine binary identifying info captured for the build at crash time:

- `bin/win64/engine.dll` version `2026.04.29`
- SHA-256 `0946EAE8C2313D1207A68D0B3F09A684D0FB2C7EAA29891A6DEB43726016AE4C`

These will pin the +offset analysis to a specific binary in case we
ever cross-reference an engine.dll PDB / symbol set later.

## Exception

```
ThreadId   = 16236
ExcCode    = 0xc0000409   (STATUS_STACK_BUFFER_OVERRUN / FAST_FAIL_FATAL_APP_EXIT)
ExcAddress = 0x00007ffc1f44b5dc   (engine.dll + 0x33b5dc)
```

`0xc0000409` is **NOT** a regular access violation. It's MSVC's
fast-fail path — the program is calling `__fastfail()` on itself
because it has detected something unrecoverable. Causes that produce
this exception in Source modules:

- **Stack cookie / `/GS` security check failed** — function overran a
  local stack buffer past the cookie that the compiler injected to
  detect overruns. Most common.
- **CRT `_invalid_parameter_handler`** — calling a CRT function
  (`sprintf_s`, `strcpy_s`, `vsnprintf`, etc.) with arguments the CRT
  considers invalid (NULL format string, length out of range, etc.).
- **Heap corruption detected by Windows heap manager**.
- **`std::terminate()` from C++ unhandled exception**.

The faulting offset within engine.dll (`+0x33b5dc`) is **0x6a (106)
bytes after** the address `engine.dll+0x33b572` that appears on the
stack as a return address (i.e. the caller of the crashing frame put
that as the return target before the call). That makes
`engine.dll+0x33b572` the start (or very near the start) of the same
function that crashed.

## Crashing thread register state

```
RIP = 0x00007ffc1f44b5dc   engine.dll+0x33b5dc
RSP = 0x000000667cd7ebd0
RBP = 0x0000000000000000
RAX = 0x0000000000000001
RCX = 0x0000000000000005
RDX = 0x0000000000000000
R8  = 0x0000000000000000
R9  = 0x0000000000000000
```

`RBP = 0` means the function uses frame-pointer omission (typical for
release builds — `/Oy`). RAX=1, RCX=5, RDX/R8/R9=0 — looks like a
small bounded loop counter or boolean state rather than a pointer
context. Can't say much without symbols.

## Stack scan — caller chain (annotated)

The full chain top-down (oldest at bottom of stack, newest at top):

```
  ntdll.dll+0x427c                     thread base / RtlUserThreadStart
  kernel32.dll+0x2e957                 BaseThreadInitThunk
  tier0.dll+0x1ca21                    tier0 thread bootstrap
  tier0.dll+0x7fed                     Source tier0 (CThreadProc)
  engine.dll+0x21a8e1                  engine thread loop
  engine.dll+0x21bbdc                  engine thread dispatch
  tier0.dll+0x60d60, 0x61f68           CCommandLine / utility funcs
  engine.dll+0x387738   (REPEATED)     looks like a common dispatcher
  tier0.dll+0x2f701                    tier0 logging or assertion
  engine.dll+0x352b8e                  engine handler
  engine.dll+0x34df36
  engine.dll+0x387738
  lua_shared.dll+0x984d8               <- LUA INTERFACE CALL
  tier0.dll+0x39b7c, 0x3a308           tier0 utility
  lua_shared.dll+0x96c20  (REPEATED)   Lua VM execution
  lua_shared.dll+0x87da                Lua function (likely main loop)
  lua_shared.dll+0x6070e               Lua VM
  lua_shared.dll+0x6056a               Lua VM
  lua_shared.dll+0x96c20               Lua VM
  lua_shared.dll+0x1b80e               Lua handler
  libcef.dll+0x16a0002                 (probably coincidental address)
  lua_shared.dll+0x1b1df               Lua
  KERNELBASE.dll+0x3885f               Windows API
  lua_shared.dll+0xbf6c0               Lua VM
  engine.dll+0x38773a                  engine
  engine.dll+0x34ff12
  lua_shared.dll+0x6bab5               <- LUA->C TRANSITION
  engine.dll+0x350215
  engine.dll+0x351403
  engine.dll+0x422c40
  engine.dll+0x34da1c
  engine.dll+0x422c40
  engine.dll+0x364815
  engine.dll+0x352a43
  engine.dll+0xdd006e                  far offset (vftable or jump table?)
  engine.dll+0x364851
  engine.dll+0x364a1f
  engine.dll+0x35f958                  closer to crash
  lua_shared.dll+0x6db9b               (Lua interop call)
  engine.dll+0x33b572                  caller of the crashing func (entry +0x6a away)
  lua_shared.dll+0x6c1a7               (Lua interop)
  RIP: engine.dll+0x33b5dc             *** CRASH ***
```

The shape is: **gamemode Lua running → Lua makes a call into a C
binding in lua_shared.dll → lua_shared dispatches into engine.dll →
engine function trips the fast-fail security check ~106 bytes into
its body**.

Two `lua_shared+0x6c1a7` / `lua_shared+0x6db9b` / `lua_shared+0x6bab5`
addresses on the stack are interesting: those are likely
`lj_state_call` / `lua_call` / `lua_pcall` / the C-call wrappers
that lua_shared uses to invoke registered C functions. They appear
right above the engine-side frames — i.e. the Lua VM invoked an
engine-registered C function via a lua_shared dispatcher, and the
engine function then crashed.

## What this looks like in plain terms

A client-side Lua script (gamemode or addon code) called an
engine-side C function. The C function then either:

1. Used a small fixed-size local buffer (e.g. `char name[256]`) and
   `sprintf`'d into it from data the Lua side passed in, without
   length checking. Long input from Lua → stack overrun → `/GS`
   cookie clobbered → fast-fail.
2. Or called a CRT-validated function (`sprintf_s`, `strcpy_s`) with
   bad arguments (NULL, oversize), tripping
   `_invalid_parameter_handler`.

Both classes produce 0xc0000409 and both cluster at "early in the
function body" (the cookie check / bounds check happens after the
prologue, ~30–200 bytes in).

## Likely engine.dll function classes (without symbols)

Without a PDB we can't name the function. Patterns of engine.dll
Lua-callable C bindings that historically hit 0xc0000409 in Facepunch
issues:

- `CSurface::DrawText` / `surface.DrawText` long-string overflows.
- `CClientNetMessage::Set*String` setters used by `usermessage` /
  `net` library handlers.
- `Player:SendLua` content reception — server sends a Lua string,
  client engine `RunStringEx` allocates a buffer for it. Malformed
  or oversized strings have hit this.
- `Entity:SetKeyValue` / `IServerTools` ent-key setters when key
  string is too long.
- HUD text printing (`draw.SimpleText`-style) downstream when font
  metrics fail.

The fact that this is a client crash on a third-party ZS server where
random other server code is firing makes any of the above plausible.
ZS gamemodes traditionally use `Player:SendLua` for chat / HUD
sync, which is the highest-risk category.

## Mitigations on our side

We don't control the third-party server. The things to verify in
**our** gamemode so the same crash class is closed on our deploy:

1. **No unbounded server→client strings via `Player:SendLua`.** Grep
   for `:SendLua(` and verify any strings we send have bounded length
   and properly-escaped contents (no untrusted player input
   concatenated into a SendLua string).
2. **Net messages with `ReadString` on the client** — verify the
   server side `WriteString` calls have bounded content. Source's
   net library caps strings at network MTU, but logic-side
   concatenation can still build pathological payloads.
3. **Custom HUD draw calls** — any `draw.SimpleText` /
   `surface.DrawText` fed from networked content should be length-
   capped before render.

These are all good-hygiene items regardless of this crash. None of
them are urgent for our deploy (we control the server and don't ship
pathological payloads), but worth a once-over.

## Next-step options (not done yet, awaiting decision)

1. **Visual Studio "Debug with Native Only"** on the .dmp file. With
   Microsoft's public symbol server (`srv*https://msdl.microsoft.com/download/symbols`)
   loaded, it'll resolve OS DLLs (kernel32, ntdll, KERNELBASE, ucrt)
   and may give names for the CRT fast-fail wrapper, which would
   identify *which* CRT function tripped the handler. Engine.dll
   itself has no public PDB, so `engine.dll+0x33b5dc` will stay
   anonymous unless Facepunch ships symbols (they don't).
2. **Search Facepunch/garrysmod-issues for `0xc0000409` engine.dll**
   to find matching reports. The crash class is well-trodden; a
   matching offset would surface the function name from any thread
   where someone with WinDbg posted the resolved stack. (Requires
   internet from the work machine — not done in this writeup.)
3. **Capture a second crash from the same third-party server** to
   confirm reproducibility / determine whether the exact same call
   site is firing each time. If `+0x33b5dc` reappears it's a
   specific bug in that server's gamemode payload; if the offset
   varies, it's a class of payloads (likely SendLua).

## Reverse engineering update (2026-05-19, second pass)

Disassembled `engine.dll` (`bin/win64/engine.dll`, SHA256 verified to
match the crashing binary byte-for-byte) using `pefile` + `capstone` to
parse the PE, walk the `.pdata` unwind table, and disassemble the
specific functions on the crashing call chain. Five short Python
helpers in this folder (`disasm.py`, `unwind.py`, `funcs.py`, `xref.py`,
`probe*.py`) drive that pass; output is captured in
`*_output.txt`. Highlights below.

### Crash class — REVISED

The first-pass write-up above interpreted `0xc0000409` as a **stack
cookie / `/GS` overrun**. Disassembly shows that is **wrong**. The
actual sequence at the crash RIP is:

```
engine.dll+0x33b5c4  sub  rsp, 0x28
engine.dll+0x33b5c8  mov  ecx, 0x17                    ; PF_FASTFAIL_AVAILABLE
engine.dll+0x33b5cd  call IsProcessorFeaturePresent
engine.dll+0x33b5d3  test eax, eax
engine.dll+0x33b5d5  je   +0x33b5de
engine.dll+0x33b5d7  mov  ecx, 5                       ; FAST_FAIL_INVALID_ARG
engine.dll+0x33b5dc  int  0x29                         ; <<< crash
engine.dll+0x33b5de  ...  RaiseException(0xC0000417) → TerminateProcess
```

`ECX = 5` is **`FAST_FAIL_INVALID_ARG`** (winnt.h), *not*
`FAST_FAIL_STACK_COOKIE_CHECK_FAILURE` (which is 2). The crash CONTEXT
in the .dmp confirms `RCX = 5` and `RAX = 1` (the return from
`IsProcessorFeaturePresent`). This rules out the stack-cookie / buffer
overrun interpretation. It's a CRT **`_invalid_parameter`** trip —
some CRT-validated function was called with arguments the CRT
considers unrecoverable.

### Full call chain — named via disassembly

Walking the .pdata unwind table from the crash RSP gives the real
return chain (heuristic scan in the first-pass write-up included some
noise; this is the authoritative version). Every layer below is the
statically-linked MSVC CRT inside `engine.dll`:

| RVA range | Total frame | Identity |
|---|---|---|
| `0x33b5c4..0x33b60a` | 0x30 | `__report_fastfail` — calls `int 29h` |
| `0x33b4bc..0x33b573` | 0x38 | `_invalid_parameter_handler_chain_walker` — decodes the encoded-pointer chain of registered handlers via `__security_cookie`, calls each one, then falls through to `__report_fastfail(5)` |
| `0x35f8b8..0x35f9d5` | 0x58 | **`_write(int fd, void* buf, unsigned int cnt)`** — validates `fd` against `__pioinfo[fd>>6][fd&0x3f].osfile & FOPEN`; on failure sets `errno = 9 (EBADF)` and calls `_invalid_parameter` |
| `0x3647f0..0x3648e7` | 0x28 | `_putc_nolock` / `_fputc_nolock` — falls through to `_write(fd, &byte, 1)` when the FILE buffer is full |
| `0x3529e4..0x352ab3` | 0x38 | `_write_multi_char` — emits N copies of a char (printf padding) |
| `0x350f68..0x3514a0` | 0x88 | **`_output`** — the printf format-specifier dispatcher. Switches on `[format_state+0x39]` against the canonical printf set `d/i/x/X/o/u/c/s/p/f/e/g/A/E/F/G/S/Z/a` |
| `0x3500f0..0x350471` | 0x38 | `_output`'s field-width / precision / flag-character state machine |
| `0x34fe48..0x34ff64` | **0x4b8** | `_vfprintf_internal` — sets up the 0x4a0-byte format-state struct on the stack |
| `0x34df10..0x34df4d` | 0x28 | `vfprintf_lock_wrapper` — acquires FILE's lock around the internal call |
| `0x352ab4..0x352bd8` | 0xc8 | **`_vfprintf_s_l`** outer wrapper — first validates `fmt != NULL`; this is the entry that engine code calls into |

Above the printf chain in the stack are engine.dll's own frames:

| RVA | Identity |
|---|---|
| `0x21bba0..0x21bbe4` (68 bytes) | **`Sys_FPrintf(int stream_selector, const char* fmt, ...)`** — engine's printf wrapper. Calls `engine+0xa8170` to fetch a `FILE**` for the selector, dereferences to get `FILE*`, then calls `_vfprintf_s_l`. Has exactly 2 callers in engine.dll. |
| `0xa8170..0xa8177` (7 bytes) | `lea rax, [rip + 0x61faa9]; ret` — returns a constant pointer to the global at `.data+0x6c7c20`. In the on-disk image this global is zero (uninitialized); at runtime it holds the FILE* engine logs into. |
| `0x21a890..0x21a8b9` (parent) + `0x21a8ba..0x21a8f9` (chained funclet) | The **console-buffer dump implementation**. Prints the literal header `"-Console Buffer-\n================\n"`, then walks a 32-byte-stride array starting at `engine+0x4e0898`, reading each entry's name via `engine+0x2aad90` and printing it with `"%s"`. Terminator is a `0xffff` word at offset +0x18 in each entry. |
| `0x21b110..0x21b2a1` (Sys_Init) | Registers `0x21a890` as a callback during engine init. Body contains the literals `"Sys_Init()"`, `"Sys_Shutdown()"`, `"Sys_InitMemory()"`, `"Host_Init( s_bIsDedicated )"`, `"Sys_InitAuthentication()"`. So this is engine's `Sys_Init`, and the dump callback is registered alongside the rest of subsystem init. |

The chain crosses into `tier0.dll` between the `Sys_Init`-registered
callback frames (`engine+0x21a8e1`, `engine+0x21bbdc`) and the
`_vfprintf_s_l` outer wrapper. `tier0.dll+0x2f701` and
`tier0.dll+0x60d60` sit in that gap — those are tier0's Spew/Log
dispatch (where Source's `Msg()` / `Warning()` / `DevMsg()` routes
through whatever `SpewOutputFunc` is currently installed). I didn't
disassemble tier0 in this pass (different binary, lower priority), but
the shape is unambiguous: a tier0 log call dispatched to the engine's
registered spew sink, which is the `0x21a890`-family dump path.

### What the bug actually is

**An engine logger tried to write a byte to a FILE* whose underlying
file descriptor is invalid** (closed, `-2`, or out of range — `_write`
sets `errno = 9 (EBADF)` for all three before invoking
`_invalid_parameter`). The chain of CRT calls is conventional
`fprintf(file, fmt, ...)` — no buffer overrun, no format-string
exploit, no heap corruption involved.

The global `FILE*` slot at `engine.dll+0x6c7c20` is statically zero
and gets assigned at runtime. Most likely candidates for what it
points to during the crash:

- A `FILE*` opened around `fopen("console.log", ...)` for `con_logfile`
- A `FILE*` redirected from stdout/stderr at engine boot to capture
  Source's spew
- A `FILE*` wrapping a pipe handle used to talk to the dedicated server
  console window or the Steam overlay

Whichever of those it is, the underlying fd became invalid between
when the FILE was opened and when this `Sys_FPrintf` call ran.
Conditions that produce that pattern in real-world Source crashes:

1. Engine opened a logfile, then somebody called `_close(file->_file)`
   directly (e.g. through an addon binary module) without going through
   `fclose`, so the FILE struct is dangling.
2. Steam overlay / EAC / antivirus injected hooks rewrote the fd table
   underneath the CRT.
3. The FILE was for stdout/stderr at a moment those weren't valid
   (e.g. a hosted GMod window with no console attached, after Steam
   detached the pipe).
4. Engine itself re-opened the logfile and orphaned the previous
   FILE*, but a Sys_FPrintf with a stale FILE* pointer fired before
   the global got updated.

### Connection to the crash trigger

The chained funclet `0x21a8ba` printed at least one `"%s"` line via
`Sys_FPrintf` before the bad fd was reached (proved by the funclet
return address +0x21a8e1 sitting on the stack — the loop had iterated
at least once). The dump source is the 32-byte-stride array at
`.data+0x4e0898`, which by shape (32-byte structs with a `0xffff`
terminator at offset +0x18) is most consistent with the developer-
console history buffer. So this is the engine's "dump console buffer
to file" command path — `condump`-style.

That fits the lua_shared frames in the chain too. The third-party ZS
server can drive console commands on a connected client over the wire
in several ways (`Player:ConCommand`, `Player:SendLua` →
`RunConsoleCommand`, debug helpers). If the server queued a `condump`
or equivalent against the client, the client's engine would walk this
exact path. The crash would happen if that command runs at a moment
the engine's logging FILE* is in the bad-fd state described above.

### What changed vs. the first-pass mitigations

The mitigations in the previous section (cap unbounded `:SendLua`,
bound `WriteString`/`ReadString`, length-cap HUD draw input) are still
good general hygiene but they do **not** address this bug class. The
trigger here isn't a payload that's "too long"; it's a Lua/concommand
path that exercises engine logging at a moment the logging FILE* is
stale. The closer-to-the-bone mitigations:

1. **Block server-side concommand injection of `condump` and any other
   command that opens an output FILE** (engine's `con_logfile` setter,
   `record` for demos, etc.). Server code on a third-party box should
   not be able to force a client to perform file I/O on demand.
2. **Audit any module that calls `_close()` on a fd that the engine's
   CRT thinks is still owned by a FILE struct.** Most likely culprits
   are Lua binary modules (gm_lua_file, custom socket libs) and any
   third-party DLL the host loads (overlays, AVs, EAC).
3. **For our own gamemode**: nothing on the Lua side directly mitigates
   this — the bug is upstream of Lua, in engine logging. The only
   useful thing on our side is to refuse to honour server-driven
   `ConCommand` requests on the client that we don't expect.

### What this pass did not establish

- The exact identity of the FILE* (would need to inspect the .dmp's
  memory dump at engine+0x6c7c20 at crash time; the static image is
  zero, so the runtime value isn't recoverable without reading the
  minidump's memory). Visual Studio "Debug with Native Only" against
  the .dmp would resolve this in seconds.
- The exact tier0 caller. tier0.dll+0x2f701 / +0x60d60 are real return
  addresses on the stack but I didn't disassemble tier0 — different
  binary, separate analysis.
- Whether the dump was server-triggered or coincidental. The lua_shared
  frames in the chain strongly suggest server-driven (Lua-issued
  ConCommand), but a deterministic reproducer would require capturing
  the exact concommand queue state at crash time.

## Minidump memory readout (2026-05-19, third pass)

The thin minidump captures ~9.5 MB inside engine.dll's image plus the
crash thread's stack. Parsed it with a Python reader (`dump_mem*.py` in
this folder) — getting actual runtime values from saved-register slots
on the stack required walking each frame's `.pdata`-derived layout.
The second-pass write-up above had two specific wrong calls; the
findings below correct them.

### Two important corrections to the second-pass narrative

**Correction 1.** `engine.dll+0xa8170` is *not* a FILE-pointer getter.
The runtime value at `engine.dll+0x6c7c20` is `0x0000000000000024` —
a tiny integer that looks like a corrupted pointer, but it's actually
the MSVC CRT's *printf options bitmask* (`__local_stdio_printf_options`
storage). `0x24` decodes as
`_CRT_INTERNAL_PRINTF_FORMAT_VALIDATION | _CRT_INTERNAL_PRINTF_LEGACY_MSVCRT_COMPATIBILITY`
— a healthy default for the static CRT. The accessor is just
`lea rax, [&_OptionsStorage]; ret`, and engine code feeds the
dereferenced value as the *first* argument to `__stdio_common_vfprintf`,
which is `(unsigned __int64 options, FILE* stream, char const* format,
_locale_t locale, va_list arglist)`.

**Correction 2.** The function at `engine+0x352ab4` is therefore
**`__stdio_common_vfprintf`** (or its `_s` variant), not `_vfprintf_s_l`,
and the FILE pointer is the *second* argument. Reading the saved-rbx
slot in `_vfprintf_outer`'s stack frame at `RSP+0x7e8` (where x64
`push rbx` lands) gives the actual FILE pointer at crash time:

```
FILE* = 0x0000023d0ec49f70   (heap-allocated, content not captured)
```

This same pointer also appears at `[RSP+0x800]` (saved rdx in the same
frame), at offsets +0x00 / +0x28 of the "selector struct" sitting on
the stack at `0x000000667cd7f460`, and at `[RSP+0x870]` and
`[RSP+0x888]` (further-up frames' saved values). Consistent
throughout — this is a real, single heap object being passed by
reference up and down the call chain, not a corrupted scalar.

### The actual caller — it's not `condump`

The cleaner interpretation comes from disassembling **`tier0.dll+0x7ef0`**,
which contains the return address `tier0+0x7fed` that sits at
`RSP+0x878` (the immediate caller of `engine+0x21a890`). Its body:

```
+0x7f9e  call GetModuleFileNameA(NULL, &buf2, 0x104)
+0x7fad  lea rdx, "Executable: %s\n\n"
+0x7fb7  call tier0+0x77e0          ; tier0's printf wrapper
+0x7fc2  lea r14, [.data+0x61ef0]   ; a 16-slot function-pointer table
+0x7fc9  loop ebx=0..15:
+0x7fd9    if (table[ebx] == NULL) skip
+0x7fe2    call tier0+0x2f870(rdi)  ; preamble
+0x7feb    call qword ptr [rsi]     ; <<< calls engine+0x21a890 via table[ebx]
+0x7fed    jmp continue              ; <<< STACK RA
```

This is the engine's **debug-state-dump collection routine**. It
writes an `"Executable: <path-to-gmod.exe>\n\n"` header (which is how
the `gmod.exe` full path ends up sitting on the caller's stack at
`RSP+0x8c0..+0x908` — `GetModuleFileNameA`'s output buffer), then
iterates a registered callback table of up to 16 subsystem dumpers
and invokes each one. Engine.dll registered its console-buffer dumper
(`engine+0x21a890`) into that table during init. So this is **not
`condump`** — it's a *crash-info / state-snapshot collector* iterating
registered subsystems.

That changes the read on what triggered this crash. The chain isn't
"server-driven `condump`"; it's "engine called its internal debug-dump
routine, the dump-writer's FILE handle is bad, dump-writer crashes
while writing". Whatever triggered the *dump itself* is the upstream
root cause; tier0 frames above `+0x7ef0` (`tier0+0x61f68`,
`tier0+0x60d60`, `tier0+0x2f701`) are the path to it. Those most
likely correspond to an SEH filter or assertion handler invoking
`Plat_AddExtraDebugMinidumpInformation` / `LoggingSystem_Log` / a
similar entry point, but I did not chase them in this pass.

### Confirmed register/state at crash time (from the .dmp CONTEXT)

```
RIP = 0x00007ffc1f44b5dc  (engine+0x33b5dc — `int 29h`)
RSP = 0x000000667cd7ebd0
RAX = 1                       (return value of IsProcessorFeaturePresent)
RCX = 5                       (FAST_FAIL_INVALID_ARG)
RDX/R8/R9/RBX/RBP/RSI/RDI = 0 (volatile registers wiped by the wrapper)
```

`.pdata`-driven unwind walks the stack cleanly — every expected
return address matched byte-for-byte:

| Frame | RA on stack | engine RVA |
|---|---|---|
| `__report_failure` | `RSP+0x028` | `engine+0x33b572` ✓ |
| `_invalid_parameter_handler_chain_walker` | `RSP+0x068` | `engine+0x35f958` ✓ |
| `_write` | `RSP+0x0c8` | `engine+0x364851` ✓ |
| `_putc_nolock` | `RSP+0x0f8` | `engine+0x364a1f` ✓ |
| `_putc_helper2` | `RSP+0x128` | `engine+0x352a43` ✓ |
| `_write_multi_char` | `RSP+0x168` | `engine+0x351403` ✓ |
| `_output_specifier` | `RSP+0x1f8` | `engine+0x350215` ✓ |
| `_output_state_machine` | `RSP+0x238` | `engine+0x34ff12` ✓ |
| `_vfprintf_internal` | `RSP+0x6f8` | `engine+0x34df36` ✓ |
| `vfprintf_lockwrapper` | `RSP+0x728` | `engine+0x352b8e` ✓ |
| `__stdio_common_vfprintf` (was "_vfprintf_outer") | `RSP+0x7f8` | `engine+0x21bbdc` ✓ |
| `engine_Sys_FPrintf` | `RSP+0x848` | `engine+0x21a8e1` ✓ |
| (parent of funclet) | `RSP+0x878` | `tier0+0x7fed` ✓ |

### Arguments recovered at the `__stdio_common_vfprintf` frame

Walked saved-register slots within `engine+0x352ab4`'s 0x4a0-byte stack
frame (`rbp = active_RSP + 0x71`):

```
[rbp+0x67] = 0x0000000000000024            ; saved rcx = options
[rbp+0x5f] = 0x0000023d0ec49f70            ; saved rdx = FILE*
[rbp+0x6f] = 0x00007ffc1f497738            ; saved r8  = engine+0x387738 = "%s"
[rbp+0x77] = 0x000000667cd7f430            ; saved arg5 = va_list ptr
```

Confirmed against the static .rdata read — engine.dll's on-disk bytes
at RVA `0x387738` are `25 73 00` = `"%s"`. And the neighbourhood at
`0x38773c..0x3878c4` is full of sound-system cvar definitions
(`snd_cull_duplicates`, `snd_mute_losefocus`, `volume_sfx`, ...),
which is just a coincidence of `.rdata` packing — the `"%s"` is the
isolated short string we care about.

### Why `_write` crashed

`_write`'s fd path (engine+0x35f8b8) at crash time:

1. `_putc_nolock` calls `_write(fd, &c, 1)` to flush one byte
2. `_write` checks `fd == -2` → no
3. `_write` checks `fd >= 0 && fd < _nhandle` → fail (or `FOPEN` bit
   clear in `__pioinfo[fd>>6][fd&0x3f].osfile`)
4. `_write` sets the FILE's errno slot to **`9` (EBADF)** —
   `mov dword [r9+0x2c], 9` is observable in the disassembly
5. `_write` calls `_invalid_parameter(NULL, NULL, NULL, 0, 0)`
6. `_invalid_parameter` walks the encoded-pointer chain of registered
   handlers (none catch), falls through to `__fastfail(5)`
7. `int 29h` with `ECX=5` = `FAST_FAIL_INVALID_ARG` → CRASH

The FILE struct at `0x0000023d0ec49f70` lives on a heap that this
minidump did *not* capture (the dump is ~92 MB but mostly
engine.dll image pages, not heap), so we can't read its `_file` /
`_flag` fields directly. Confirmed by attempting the read:

```
=== Heap ptr 0x0000023d0ec49f70 (the FILE struct) ===
  not in dump
```

### Where this leaves the diagnosis

What we know for sure:

- The instruction is `int 29h` with `RCX=5` → `FAST_FAIL_INVALID_ARG`.
  Confirmed from the .dmp CONTEXT and from disassembling
  `engine+0x33b5c4..+0x33b60a`.
- The path to it is the standard MSVC CRT `__stdio_common_vfprintf` →
  `_output` → `_write_multi_char` → `_putc_nolock` → `_write` chain.
  Confirmed by walking every return address against `.pdata`.
- The FILE struct passed in is heap-allocated at
  `0x0000023d0ec49f70`. Same pointer appears in multiple register
  slots up the chain. Confirmed by reading `_vfprintf_outer`'s saved
  `rbx` slot in the dump.
- The engine path that triggered the printf is `tier0+0x7ef0` —
  the debug-state-dump collector — iterating its registered subsystem
  callbacks. Confirmed by disassembling tier0.dll on disk.
- The "Executable: %s\n\n" header buffer with `gmod.exe`'s full path
  is sitting on the stack at `RSP+0x8c0..+0x908`. Confirmed by raw
  reading the dump's stack memory.

What we still cannot answer from this dump alone:

- The contents of the FILE struct (heap not captured). With it we
  could distinguish "fd field is `-2` / sentinel" vs "fd is in range
  but `FOPEN` bit clear" vs "FILE struct itself is freed memory and
  the heap allocator just happened to leave the fields plausible".
- What triggered the *call into* `tier0+0x7ef0`. The chain above it
  goes through `tier0+0x61f68` / `tier0+0x60d60` / `tier0+0x2f701`,
  which I did not disassemble. That would identify whether this was
  an SEH filter writing a crash report, a `Plat_FatalError`-style
  intentional dump, or something else.
- Why the FILE was set up with a bad fd. Two plausible mechanisms,
  in priority order: (a) the dump-writer's output target is a Windows
  HANDLE wrapped into a stdio FILE via `_open_osfhandle`, and the
  underlying Windows HANDLE was closed in the moments before the dump
  ran (e.g. an SEH/AV/EAC hook closed it as part of teardown); (b) the
  dump-writer always uses stdout, but a non-console-attached gmod.exe
  hosted under Steam doesn't have a real stdout, so the fd is `-2`.

### Updated mitigation guidance

This is a debug-dump-collector failing on a closed log target. None
of the original mitigations (cap SendLua, bound network strings, etc.)
apply. The closer-to-the-bone items:

1. **Audit who's invoking the engine's debug-state-dump path.**
   The `tier0+0x7ef0` family is reached from SEH filters and from
   explicit `Plat_AddExtraDebugMinidumpInformation` / `LoggingSystem_*`
   entry points. If a third-party server can put the client into a
   state that trips an SEH filter (e.g. by sending malformed payloads
   that cause a Lua C-function to fault), the client will try to run
   this dump path. Hardening any net-handler bindings against
   payload-induced faults helps.
2. **The dump path itself should not crash on a bad FILE handle.**
   That's a Facepunch bug — the engine's spew sink should null-check
   / fd-validate before letting the CRT do it. We can't fix engine.dll
   directly, but we can avoid the *original* fault that triggers the
   dump.
3. **Symbols would unblock the rest of this.** Microsoft's public
   symbol server resolves the OS-side CRT names we recognized
   structurally; engine.dll has no public PDB. A `cdb -z` /
   `WinDbg -z` session against the .dmp with Microsoft symbols
   loaded would print most of the resolved frame names directly.

## Final: end-to-end diagnosis (2026-05-19, fourth pass)

This pass walked the chain into tier0.dll and identified every relevant
function by name via tier0's exported symbol table. Result: a complete
top-to-bottom story.

### Tier0's exported `Dump_*` API

Tier0.dll exports a public crash-reporting API (resolved via the export
table, not guesswork):

```
tier0!Dump_AddCallback                 = +0x8060   register a subsystem dumper
tier0!Dump_RemoveCallback              = +0x8750   unregister
tier0!Dump_CallFunction                = +0x80c0   run fn(), SEH-wrap, dump on exception
tier0!Dump_CallMainFunction            = +0x8270   same, for main()
tier0!Dump_CallWinMainFunction         = +0x8430   same, for WinMain()
tier0!Dump_CreateDump                  = +0x85f0   write a crash report on demand
tier0!Dump_EnableCrashingOnCrashes     = +0x86d0   enable second-level fastfail visibility
tier0!Dump_EnableFullDumps             = +0x8740
tier0!WriteMiniDump                    = +0xbf20
tier0!WriteMiniDumpUsingExceptionInfo  = +0xbf50
tier0!CatchAndWriteMiniDump{,Ex,ExForVoidPtrFn,ExReturnsInt,ForVoidPtrFn}
                                       = +0xbce0..+0xbe50
tier0!Plat_ExitProcess                 = +0xc940
tier0!Plat_ExitProcessWithError        = +0xc960
```

`engine.dll`'s imports from tier0 confirm it uses `WriteMiniDump`,
`Dump_AddCallback`, `Dump_CreateDump`, and `Dump_EnableCrashingOnCrashes`.

### The crashing thread is the crash-report-writer worker

`tier0+0x1c950` is the worker thread main loop. Its prologue/init at
`tier0+0x1d408`:

```
+0x1d412  InitializeCriticalSection
+0x1d42a  CreateSemaphoreW × 2          (work + done semaphores)
+0x1d480  CreateThread(..., tier0+0x1c950, work_state, ...)
+0x1d494  LoadLibraryW(L"dbghelp.dll")
+0x1d4b0  GetProcAddress(..., "MiniDumpWriteDump")
+0x1d4c4  LoadLibraryW(L"rpcrt4.dll")
+0x1d4e0  GetProcAddress(..., "UuidCreate")
+0x1d523  call tier0+0x1d720             (pre-generate first UUID)
```

Unambiguous: this is the crash-report subsystem creating its dedicated
writer thread. **TID 16236 is that worker thread.**

The worker's main loop (`tier0+0x1c950`):

```
+0x1c970  WaitForSingleObject(work_sem, INFINITE)
+0x1c986  check shutdown flag
+0x1c995..+0x1c9bb  call primary callback work_item[0]
+0x1c9fb  if secondary callback work_item[8] non-null:
+0x1ca1e    call r10 (= work_item[8])     ; <<< THIS CALL CRASHED
+0x1ca21    RA returned here              ; <<< on our stack
+0x1ca35  ReleaseSemaphore(done_sem)
+0x1ca3b  loop back to wait
```

The work-item's secondary callback `r10` was `tier0+0x7ef0` — the
**`WriteCrashReport` body**, which:

```
+0x7f5e  swprintf_s(buf, 0x103, L"%s/%s.txt", path1, path2)
+0x7f72  fopen-like (tier0+0x2959c)(buf, L"w")  → FILE*
+0x7f9e  GetModuleFileNameA(NULL, exepath, 0x104)
+0x7fb7  fprintf-like writes "Executable: %s\n\n" + exe path
+0x7fc2  iterate registered callbacks at .data+0x61ef0:
+0x7feb    call qword ptr [rsi]            ; <<< per-subsystem dumper
+0x7fed    RA returned here                ; <<< on our stack
+0x8006  cleanup / fclose-like
```

The registered subsystem dumpers at runtime (slots in `.data+0x61ef0`):

```
slot[ 0] = lua_shared.dll+0x14c50   "  Client/Server/MenuSystem" + "-Lua Stack Traces-" — completed
slot[1..14] = NULL
slot[15] = engine.dll+0x21a890       "-Console Buffer-" + per-line "%s"  — crashed inside
```

Only two callbacks are registered. Lua's runs first (and apparently
succeeded — its writes went into the FILE's 4 KB internal buffer).
Engine's runs last. Engine's dumper writes enough data to fill the
buffer, triggering an actual `_write(fd, ...)` syscall, which discovers
the bad fd and fast-fails.

### The dump file the worker was writing

The composed path (from the worker's stack at `RSP+0x150`, UTF-16
decoded):

```
crashes/914fa858-b8e7-480e-b4a7-c05093ef0bb0.txt
```

That's a v4 UUID generated via `rpcrt4!UuidCreate` (the proc pointer is
stored at `work_state[+0xb8]`). The "crashes" prefix is a per-process
constant set at `Dump_CallWinMainFunction` startup — see below. fopen
mode is `L"w"` (read from tier0 static `.rdata+0x47d94`).

### The trigger: main thread (TID 27040)

Initially I couldn't find the triggering thread. Looking at the full
call chains of all 81 threads with no kernel-module filter found it:

```
TID=27040  RIP=ntdll!NtWaitForSingleObject  (suspended at syscall)

  innermost:
    kernelbase!WaitForSingleObjectEx
    filesystem_stdio.dll+0x89137      (caller of Wait)
    filesystem_stdio.dll+0x8565d
    tier0+0x1dba5     [inside fn 0x1db20]   <-- inner wait-for-worker function
    tier0+0x559e0
    tier0+0x1daff     [inside fn 0x1dac0]   <-- "perform dump-write" front-end
    tier0+0x45be5     [inside fn 0x45bd0]   <-- a 33-byte thunk
    tier0+0x559f8
    tier0+0x7cd9      [inside fn 0x7c90]    <-- Dump_CallWinMainFunction inner
  outermost:
    tier0+0x85b4      [= Dump_CallWinMainFunction+0x184]
    launcher.dll+0x3780
    (gmod.exe entry)
```

`tier0+0x7c90` is what `Dump_CallWinMainFunction` invokes; its body
shows:

```
+0x7cb3  lea rcx, "crashes"
+0x7cba  call CreateDirectoryA            ; create the crashes/ dir at startup
+0x7cd6  call r14                          ; <<< invoke the user's main fn
```

So the main thread's chain goes:

1. `launcher.dll` calls into the engine
2. `tier0!Dump_CallWinMainFunction` SEH-wraps the actual main function
3. `tier0+0x7c90` runs `CreateDirectoryA("crashes")` then calls the
   user's `LauncherMain` via the saved `r14`
4. Inside `LauncherMain`, normal game code runs (lots of frames)
5. Eventually the main thread reaches `tier0+0x1dac0` — the
   on-demand crash-report front-end
6. Which calls `tier0+0x1db20` (the inner "post work and wait"
   function — disassembled, contains
   `ReleaseSemaphore + WaitForSingleObject(done_sem, INFINITE)`)
7. The Wait drops into filesystem_stdio.dll (Source's filesystem
   wrapper used by tier0's I/O paths)
8. filesystem_stdio.dll's chain ends in `kernelbase!WaitForSingleObjectEx`

So the main thread **did call into the crash-report subsystem**,
signaled the worker, and is now blocked on the done-semaphore (via
filesystem_stdio's queue). The worker, doing the actual write, is the
one that crashed.

### Why was the main thread asking for a crash report?

I didn't reach all the way up to the exact call site of `Dump_*` in
the main thread's chain (the upper game-code frames are not in tier0
or engine, they're in client.dll / launcher.dll / unidentified
helpers). What we can say for sure from the stack:

- The main thread is INSIDE `LauncherMain`, not inside an SEH filter
  (no `__C_specific_handler` / `RtlUnwindEx` on the stack).
- So this is **not** "the main thread crashed, SEH filter is running
  the dump." It's an *explicit* `Dump_CreateDump` (or equivalent) call
  from inside the running game.
- The most common reason for a running game to explicitly call
  `Dump_CreateDump` is a tripped *assertion* — `AssertMsg` in Source
  routes through `LoggingSystem_LogAssert` (also imported by engine)
  which can trigger a crash dump. Other reasons include `Sys_Error` /
  `Plat_FatalError`-style routes.

This fits the third-party ZS server context: a server-side Lua action
made the client invoke an engine path that hit an assertion, which
called `Dump_CreateDump`, which signaled the worker, which crashed.
Without the heap and without symbols for engine.dll, I cannot identify
the specific assertion that fired.

### Why the FILE's fd is bad

The thin minidump does **not** capture the heap region containing the
FILE struct at `0x0000023d0ec49f70`. (Confirmed: 6758 ranges in
MemoryListStream, 98 PRIVATE-RW low-VA ranges, none cover that
address.) So I can't read the FILE struct's `_file` / `_flag` fields
directly.

Two facts are still solid:

- The dump file path was constructed and opened by **tier0+0x2959c**
  (`fopen`-equivalent) via Source's filesystem layer.
- That function returned a non-null FILE pointer (else
  `__stdio_common_vfprintf` would have rejected it at the early
  `test rcx, rcx`-style null check — but it didn't; it ran the whole
  printf chain).

So `fopen` succeeded enough to return a FILE struct, but the fd inside
is invalid. The most plausible mechanisms, in priority order:

1. **Source's `filesystem_stdio.dll` intercepts CRT I/O** and returns
   FILE wrappers with internal sentinel fds. The fd value isn't a real
   OS handle index but a custom token. The CRT's `_write` doesn't know
   that, validates it as a CRT fd against `__pioinfo`, fails, and
   trips `_invalid_parameter`. This is a **mismatch between Source's
   filesystem layer and the CRT's I/O internals** — basically a Source
   bug where the layered I/O doesn't survive being routed through
   straight `vfprintf`. (Note the main thread is **also** blocked in
   filesystem_stdio at the time of crash; the filesystem layer is
   clearly involved.)
2. The fd was valid at fopen time but has since been `_close`d by
   another module (overlay / EAC / AV hook).
3. The FILE struct itself is freed memory whose contents happen to
   look almost-FILE-shaped, but `_file` lands on garbage. Less likely
   given the chain reached `_write` cleanly.

### Concrete final answer

```
                ┌─────────────────────────────────────────────┐
                │  Process start                              │
                │  launcher.dll → gmod.exe → LauncherMain     │
                │  wrapped by tier0!Dump_CallWinMainFunction  │
                │  which CreateDirectoryA("crashes") and      │
                │  spawned the crash-writer worker thread.    │
                └────────────────┬────────────────────────────┘
                                 │
                       (game runs normally)
                                 │
   ┌─────────────────────────────▼────────────────────────────┐
   │  Main thread (TID 27040):  some engine code path,        │
   │  most likely an assertion or `Sys_Error`, calls into     │
   │  the crash-dump subsystem.                               │
   │                                                          │
   │  → tier0+0x7c90 → ... → tier0+0x1dac0 → tier0+0x1db20    │
   │  → ReleaseSemaphore(work_sem)                            │
   │  → WaitForSingleObject(done_sem, INFINITE)               │
   │  → (path uses filesystem_stdio.dll's queue, eventually   │
   │     blocks in kernelbase!WaitForSingleObjectEx)          │
   └─────────────────────────────┬────────────────────────────┘
                                 │
                          [semaphore signal]
                                 │
   ┌─────────────────────────────▼────────────────────────────┐
   │  Worker thread (TID 16236, kernel32!BaseThreadInitThunk  │
   │                              → tier0+0x1c950 loop):      │
   │                                                          │
   │  Wakes from WaitForSingleObject(work_sem), dispatches    │
   │  work_item[8] = tier0+0x7ef0 (WriteCrashReport body)     │
   │                                                          │
   │  tier0+0x7ef0:                                           │
   │    swprintf_s(buf, L"%s/%s.txt", "crashes",              │
   │              "914fa858-b8e7-480e-b4a7-c05093ef0bb0")     │
   │    fp = fopen(buf, L"w")          ; via tier0+0x2959c    │
   │    fprintf(fp, "Executable: %s\n\n", "C:\...\gmod.exe")  │
   │    for cb in dump_callbacks[0..15]:                      │
   │       if cb: cb(fp)                                      │
   │                                                          │
   │  Callback 0 = lua_shared!LuaDumper          (succeeded)  │
   │  Callback 15 = engine!ConsoleBufferDumper   (crashes)    │
   │                                                          │
   │  engine!ConsoleBufferDumper:                             │
   │    fprintf(fp, "-Console Buffer-\n=...\n")               │
   │    for line in console_history:                          │
   │       fprintf(fp, "%s", line)        ; loop body         │
   │                                                          │
   │  Eventually the 4 KB FILE buffer fills; _putc_nolock     │
   │  invokes _flsbuf -> _write(fd, &c, 1).                   │
   │  fd is invalid in __pioinfo (FOPEN bit clear or out of   │
   │  range). EBADF (9) set; _invalid_parameter called;       │
   │  __fastfail(FAST_FAIL_INVALID_ARG=5) → int 29h → CRASH.  │
   └──────────────────────────────────────────────────────────┘
```

The visible crash is the **secondary failure inside the crash-report
writer**. It is not the bug that prompted the report — the bug that
prompted it is an assertion / Sys_Error / similar event on the main
thread (which is now suspended waiting for the worker to finish, and
will hang forever).

The mechanism that makes the dump writer itself fail is **a mismatch
between Source's `filesystem_stdio.dll` FILE-wrapper layer and the
MSVC CRT's `_write` internals**: when tier0's dump writer goes through
its layered I/O, the resulting FILE struct survives initial use (the
Lua callback's writes go into the in-FILE buffer fine) but on the
first `_write` flush call, the fd field is rejected by `__pioinfo`
and the CRT terminates the process. This is the same `filesystem_stdio`
layer the main thread is currently stuck waiting inside.

### What "bottom of it" means in this case

The dump file `crashes/914fa858-b8e7-480e-b4a7-c05093ef0bb0.txt` would
normally contain `Executable: ... gmod.exe` followed by a Lua state
dump and a console buffer dump. That file was never actually flushed
to disk — the crash happened mid-write, with the data still in the
FILE's buffer. The buffer was on the heap that wasn't captured, so
the contents can't be recovered from this minidump either.

To get more, the next steps would be:

1. **Find the file `crashes/914fa858-b8e7-480e-b4a7-c05093ef0bb0.txt`
   on disk in the GarrysMod install.** It probably doesn't exist
   (because the buffered writes never flushed), but if it does, that's
   the Lua stack trace.
2. **Reproduce on the same third-party ZS server with `+sv_logfile 1`
   on the client side or with `developer 2`** to capture the
   pre-assertion engine state.
3. **Get a full-memory minidump** (not the thin one in this folder)
   via Procdump's `-ma` mode for the next occurrence, which will
   capture the heap and let us read the FILE struct and the buffered
   Lua dump.
4. **WinDbg with MS public symbols** would print most of the OS-side
   frame names natively, saving the reverse-engineering pass.

### Files added in this pass

- `walk_up.py` — programmatic chain walk through engine.dll AND
  tier0.dll `.pdata` to walk above the original engine frames.
- `tier0_funcs.py` — disassembly of the tier0 functions on the chain
  (worker loop, dump writer, fopen, sprintf, etc.).
- `deeper.py` — minidump reads of the composed dump-file path
  (UTF-16-decoded), the selector struct, and a survey of memory
  ranges to confirm the heap isn't captured.
- `threads.py` — scan of all 81 threads with classification by RIP
  location; finds TID 27040 as the only other thread with significant
  game-DLL frames.
- `trigger.py` / `trigger2.py` / `find_trigger.py` / `trigger_thread.py`
  / `find_caller.py` / `full_stacks.py` — successive passes to find
  the triggering thread by searching for return addresses inside the
  `Dump_*` and post-work-item functions.
- `deep3.py` / `deep4.py` / `final_chain.py` — disassembly of the
  remaining tier0 functions (post-work-item dispatchers, the
  WriteCrashReport front-ends, the Dump_CallWinMainFunction inner
  body that creates `crashes/` and calls LauncherMain).
- `*_output.txt` — captured stdout from each helper above.

### Files added in this pass

- `disasm.py` — targeted disassembler around the crash RIP and adjacent
  stack-chain RVAs. Reports CRT-helper identities and string xrefs.
- `unwind.py` — parses engine.dll's `.pdata`, resolves each stack-chain
  RA to the function range that contains it, and reports `stack_alloc`
  / `push_count` / `total_frame` / unwind-handler flags.
- `funcs.py` — full-function disassembly of every CRT-helper function
  named in the table above.
- `funcs2.py` — full-function disassembly of the engine-side wrappers
  (`Sys_FPrintf`, the funclet at 0x21a8ba, etc.).
- `xref.py` / `xref2.py` / `xref3.py` — per-`.pdata`-function scanners
  that find every direct call/jmp/lea reference to target RVAs.
- `probe.py` / `probe2.py` / `probe3.py` — small ad-hoc probes (FILE*
  slot contents, `condump` registration site, `Sys_Init` body).
- `*_output.txt` — captured stdout from each helper.

Everything in this pass is offline — only the local engine.dll, no
network, no Facepunch source, no symbol server access. The "do I need
their codebase" answer from the original question is **no**: the call
chain resolves to standard MSVC CRT shapes (printf dispatcher,
`_write`, `_invalid_parameter` handler chain) and the only engine
identifiers we needed were derivable from the literals already
present in the binary (`"-Console Buffer-\n================\n"`,
`"Sys_Init()"`, `"Host_Init( s_bIsDedicated )"`, etc.).

## Files in this folder

- `analyze_crash.ps1` — PowerShell minidump parser, x64-aware, pulls
  exception, module list, crashing thread CONTEXT, and a return-
  address-pattern stack scan.
- `analysis_output.txt` — captured output of running the analyzer
  against `gmod.exe.29108.dmp`.
- `disasm.py`, `unwind.py`, `funcs.py`, `funcs2.py`, `xref.py`,
  `xref2.py`, `xref3.py`, `probe.py`, `probe2.py`, `probe3.py`,
  `final.py` — disassembly / reverse-engineering helpers; outputs in
  matching `*_output.txt` files.
- `README.md` — this file.
