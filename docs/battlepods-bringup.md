# Star Wars Battle Pods — bring-up notes

Everything needed to reproduce the current state, and why each item is needed.
None of this is in the repo as data: the game dump is not redistributable, and
these are changes to a local copy of it.

## The target

`SWArcGame-Win64-Shipping.exe` — Unreal Engine 3, PE32+ x86-64, image base
`0x140000000`, 15.5 MB of `.text`, 609 imports across 34 DLLs.

It is the first 64-bit target in this toolbox, which is why `lift64_cpu.py`,
`generate64.py`, `difftest64.py` and `src/runtime64` exist at all.

## Catalog

`.pdata` is **not** a function list, in either direction — see the note in
`generate64.py`. Use a real disassembler:

    idat.exe -A -Sida_dump.py -Lida.log swarc.exe      # 90,818 functions

then

    py -3.11 generate64.py swarc.exe ida_funcs.txt <outdir>

which adds 412 stored code pointers found through `.reloc` and closes the
catalog over its own dispatch targets in six rounds, reaching 92,331 entries.

## Building

The generated translation units must be compiled with the TODO reporter forced
in, or an unexpressed instruction aborts with no output at all:

    ml64 /nologo /c thunk64.asm
    cl /nologo /c /Od /W3 /MP12 /FIes3_todo.h recomp_funcs_*.c recomp_dispatch.c recomp_imports.c
    cl /nologo /c /Od /W3 dispatch64.c loader64.c trace64.c main64.c
    link /nologo /OUT:battlepods.exe *.obj kernel32.lib user32.lib

`/FI` and not `/D`: MSVC silently ignores function-like macro definitions on
the command line, so `/D"RECOMP_TODO(va,text)=..."` compiles, links, and leaves
the `abort()` default in place.

## Running

    battlepods.exe SWArcGame-Win64-Shipping.exe --game-args "-seekfreeloadingpcconsole"

`-seekfreeloadingpcconsole` is the switch this build parses; `-seekfreeloading`
is not. It selects `CookedPCConsole` over `CookedPC` for the content path.

Once the junctions below are in place it stops mattering: with them, all three
of `-seekfreeloadingpcconsole`, `-seekfreeloading` and no switch at all reach
exactly the same point. Recorded because it was believed to be load-bearing for
several rounds, and it was only the path resolution underneath it that was.

## Changes to the game data

These are all environment or dump-completeness problems, not emulation gaps.

### 1. Junctions for the game-root-relative paths

    cd Binaries\Win64
    mklink /J SWArcGame ..\..\SWArcGame
    mklink /J Engine    ..\..\Engine

The async IO thread resolves package paths relative to the GAME ROOT
(`SWArcGame\CookedPCConsole\Core.upk`) while the main thread uses `..\..\`
relative to `Binaries\Win64`. Both appear in a file trace, a few lines apart,
one succeeding and one failing. Without these the async open fails, the read is
skipped, the request is still marked complete, and UE3 reports a bad package
tag — five levels of indirection from the cause.

### 2. `Engine\Config\BaseEngine.ini` — `[PlatformInterface]`

The shipped section has three keys, all empty, and is missing the analytics
one entirely. UE3 calls `StaticLoadClass` on each and throws
`Failed to find object 'Class None.'` when one is empty. Fill all of them with
the engine's own base classes:

    [PlatformInterface]
    CloudStorageInterfaceClassName=Engine.CloudStorageBase
    CloudStorageInterfaceFallbackClassName=Engine.CloudStorageBase
    FacebookIntegrationClassName=Engine.FacebookIntegration
    FacebookIntegrationFallbackClassName=Engine.FacebookIntegration
    InGameAdManagerClassName=Engine.InGameAdManager
    InGameAdManagerFallbackClassName=Engine.InGameAdManager
    MicroTransactionInterfaceClassName=Engine.MicroTransactionBase
    MicroTransactionInterfaceFallbackClassName=Engine.MicroTransactionBase
    TwitterIntegrationClassName=Engine.TwitterIntegrationBase
    TwitterIntegrationFallbackClassName=Engine.TwitterIntegrationBase
    AnalyticEventsInterfaceClassName=Engine.AnalyticEventsBase
    AnalyticEventsInterfaceFallbackClassName=Engine.AnalyticEventsBase

The exact section and key names were read out of the binary, not guessed.

### 3. `Engine\Config\BaseEngine.ini` — shader compilation

    bAllowMultiThreadedShaderCompile=False
    bPromptToRetryFailedShaderCompiles=False

`ShaderCompileWorker.exe` is **not in this dump**, so out-of-process shader
compilation never completes: the workers write
`Engine\Shaders\WorkingDirectory\SWArc\<pid>\{0..10}\WorkerInputOnly.in`, poll
for a `.out` that never appears, raise, and the main thread spins in
`appSeconds()` waiting for them.

### 4. Delete the generated configs after changing the above

    del SWArcGame\Config\SWArc*.ini

UE3 writes its effective configuration to `SWArc*.ini` and reads those in
preference to `Base`/`Default`. They are regenerated on the next run.

## Where it gets to

Sixteen packages load — Core, Engine, GameFramework, GFxUI, IpDrv,
OnlineSubsystemPC, WinDrv, Startup, Startup_LOC_INT, SWArcGame,
SWArcGame_LOC_INT, SWArcFonts, AkAudio, GuidCache, RefShaderCache and
**SWArc_SplashScreen**. `Direct3DCreate9` succeeds and returns a live
interface, 28 guest threads run, and `Startup.upk` is read in full — 1,437
reads reaching exactly its 90,877,289 bytes.

It then stops on a content reference:

    Failed to find object 'DistributionFloat PlayerCustomisation.AngularAccelCurve'

29 frames deep inside `UObject` serialisation. `PlayerCustomisation` is listed
in `[Engine.StartupPackages]` in `DefaultEngine.ini`.

All 18 packages named in `[Engine.StartupPackages]` - including the stock
`EngineMaterials`, `EngineSounds` and `EngineFonts` - are absent as files and
merged into `Startup.upk`, which is what seek-free console cooking does. The
dump is complete: `PlayerCustomisation` is not in `PCConsoleTOC.txt` (so no
file is expected) but is named in `GuidCache.upk` (so it is a known cooked
package).

`Startup.upk` is read in full and correctly - 1,437 reads reaching exactly its
90,877,289 bytes, first four bytes `C1 83 2A 9E`. Its flags say
StoreCompressed but not StoreFullyCompressed, which matches
`bFullyCompressStartupPackages=FALSE` in the config.

The engine probes the filesystem for a bare `PlayerCustomisation` and fails,
and it probes for NONE of the other startup packages - so they were never
requested rather than successfully loaded. That points at the startup packages
not being registered out of the blob at all, with `PlayerCustomisation` simply
being the first one anything references. Which mechanism does that
registration, and why it is not running, is the open question - and it is a UE3
content-loading question rather than a recompilation one.

## Diagnostics

All off by default. `--trace` also enables the lifted call stack.

    --trace                  dispatch ring (1M entries) + call stack
    --trace-files            every file operation, and the guest's own log
    --limit N                stop after N dispatches
    --game-args "..."        the guest's command line (it gets its own)
    --watch-alloc N          catch an allocation of N bytes, dump the stack
    --watch-serialize VA     arm on a caller, report the next FArchive read
    --watch-reader VA        print an FBufferReader's Data/Pos/contents
    --log-call VA[,...]      report a function whenever it runs, with args
    --log-callees-of VA      every function a named function calls, resolved
    --swallow-raise          DIAGNOSTIC ONLY — drop guest RaiseException

A fault reports the guest PC, because the lifter maintains `c->rip` per basic
block and at every call return point. Without the return points a fault in a
caller is attributed to whatever the callee last executed — which for a
one-instruction IAT thunk reads as "the crash is in memset", and is both wrong
and convincing.
