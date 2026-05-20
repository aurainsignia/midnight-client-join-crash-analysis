# GMod client crash on third-party ZS server — 2026-05-19

## What happened

Aura was playing on a third-party Zombie Survival server on 2026-05-19. The
GMod client crashed at 10:43. Windows wrote a 92 MB OS-level minidump to
`C:\Users\Aura Insignia\AppData\Local\CrashDumps\gmod.exe.29108.dmp` (a
copy is in this folder). Source also wrote its own crash report at the
same moment to the GMod install:

- `<GarrysMod>/crashes/914fa858-b8e7-480e-b4a7-c05093ef0bb0.txt` (470 B, Lua state)
- `<GarrysMod>/crashes/914fa858-b8e7-480e-b4a7-c05093ef0bb0.dmp` (633 KB, native minidump)

## Cause

**Access violation in `client.dll` while setting up bones on a
clientside model created by the Pointshop addon.**

The Source `.dmp` (which is the authoritative dump for this crash) shows:

```
ThreadId        = 27040  (main thread)
ExceptionCode   = 0xC0000005  (ACCESS_VIOLATION)
ExceptionAddr   = client.dll+0x184eec  (read of 0x0000023cbd4e283a)
```

The instruction at the crash address:

```
client.dll+0x184e72  function entry (animation/bone walker)
   ...
   movsx rax, word ptr [r15 + rax*2]   ; load a 16-bit offset from a
                                       ; studio-anim data block
   test  ax, ax
   jle   skip_if_zero
   mov   rdx, rax
   add   rdx, rbx                      ; rdx = block_base + offset
   je    skip_if_zero
client.dll+0x184eec  movzx ecx, byte ptr [rdx + 1]   ; <<< CRASH
```

This is Source's animation-blend code — the inner loop of
`Studio_*`/`CalcBoneQuaternion`/`SetupBones` that walks the variable-
length offset table inside `mstudioanim_t`. The 16-bit offset it just
loaded was malformed: `rdx + 1` lands on an unmapped page
(`0x0000023cbd4e283a`).

The Lua side of the crash (from the Source `.txt` report):

```
Client
    0. SetupBones - [C]:-1
      1. RebuildItems - addons/pointshop/lua/pointshop/cl_init.lua:1
        2. (null) - addons/pointshop/lua/pointshop/cl_init.lua:1
          3. (null) - addons/sparkwerk/lua/core/sh_customhooks.lua:1

  Server
    Lua Interface = NULL
```

Server's Lua is `NULL` — server-side Lua isn't involved at all. The
trigger is purely client-side Lua executing Pointshop code that was
sent down from the server (Pointshop is *not* installed locally;
those `addons/pointshop/...` paths are the virtual paths GMod uses for
the server-downloaded files in `garrysmod/cache/lua/`).

`Sparkwerk`'s `sh_customhooks.lua` hooked a periodic event,
`Pointshop`'s `RebuildItems` rebuilt the item-list (which constructs
clientside `Entity`s for the preview models), and called `:SetupBones()`
on one of those entities. The model's animation data has a corrupted
offset, and Source's bone walker dereferences unmapped memory.

## Why we have two dumps (Source `.dmp` vs Windows OS `.dmp`)

After the initial access violation, Source's `UnhandledExceptionFilter`
ran. The filter's dump-writer worker thread (TID 16236) successfully
wrote the `914fa858-...txt` and `914fa858-...dmp` files. While the
worker was *also* iterating its registered "dump extra info" callbacks
(the same flow that writes the `-Console Buffer-` section to the .txt),
something inside the engine's console-buffer-dumper hit a CRT
`_invalid_parameter` and tripped `__fastfail(FAST_FAIL_INVALID_ARG=5)`.
Windows captured the 92 MB OS-level minidump for that secondary failure
— that's `gmod.exe.29108.dmp` in this folder.

So:

- `crashes/914fa858-...dmp`  → original crash on main thread (the bug)
- `gmod.exe.29108.dmp`       → second crash inside the dump-writer (red herring; not the bug)

## How to reproduce / mitigate

This is **not** something our gamemode causes or can fix in
engine.dll. It is a known class of bug where a clientside-built model
in Pointshop has invalid `.mdl`/`.ani` data and the engine's bone walker
crashes on it.

Mitigations that actually apply:

1. **On our deploy: don't ship Pointshop or anything that uses
   `RebuildItems`-style frame-by-frame model rebuilds.** Our gamemode
   already doesn't.
2. **If a player reports this crash on our server:** check whether they
   joined our server with a stale Pointshop/Sparkwerk cache from a
   previous server. Clearing `garrysmod/cache/lua/` and
   `garrysmod/cache/workshop/` will force a fresh fetch.
3. **For the third-party server:** the affected model in their Pointshop
   item list is corrupted or references a missing animation. They'd
   need to identify which item triggers the rebuild crash and re-pack
   or remove that model.

## Files in this folder

- `gmod.exe.29108.dmp` — the 92 MB Windows OS minidump for the
  secondary fastfail (kept for record; not the primary bug evidence).
- `analyze_crash.ps1` — PowerShell parser used in the initial
  investigation to walk the OS dump's exception, modules, and stack
  scan.
- `analysis_output.txt` — captured output from that script.
- `README.md` — this file.

The authoritative crash files are in the GMod install at
`<GarrysMod>/crashes/914fa858-b8e7-480e-b4a7-c05093ef0bb0.{txt,dmp}`.
