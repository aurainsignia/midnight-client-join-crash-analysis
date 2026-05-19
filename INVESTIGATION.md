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

## Files in this folder

- `analyze_crash.ps1` — PowerShell minidump parser, x64-aware, pulls
  exception, module list, crashing thread CONTEXT, and a return-
  address-pattern stack scan.
- `analysis_output.txt` — captured output of running the analyzer
  against `gmod.exe.29108.dmp`.
- `INVESTIGATION.md` — this file.
