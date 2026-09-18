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

It boots. The engine initialises, creates a real D3D9 HAL device, loads a map
and runs: `SWArc_Attract01` renders at a sustained ~43 fps, streaming textures
out of `Textures.tfc` and its Wwise banks for BGM and dialogue, for as long as
it is left alone.

What it draws is the machine's own error screen:

    03-01 I/O PCB ERROR

on the arcade's curved-screen projection, with FREE PLAY in the corner. That is
the game working, and saying that the cabinet it expects is not here.

Left to itself - no map on the command line - it boots `SWArc_SplashScreen`
and then `SWArc_TestMode`, which is what an arcade board does when its I/O is
absent. Naming the map on the guest command line goes straight to attract:

    battlepods.exe SWArcGame-Win64-Shipping.exe         --game-args "SWArc_Attract01 -seekfreeloadingpcconsole"

### What is left

The I/O PCB. The game enumerates it with setupapi/CM_* and talks to it over
USB; nothing in this runtime answers, so `SWArcWinViewport` reports 03-01 and
holds the attract sequence behind the error. That is the last thing between
here and attract actually playing, and it is arcade hardware emulation rather
than recompilation.

### The dongle, which is done

System ES3 carries a Sentinel USB HASP key, and without it the same screen also
showed `19-21 USB DONGLE ERROR 1`. The game imports four functions from
`hasp_windows_x64_100610.dll` **by ordinal** - `hasp_login` (13),
`hasp_logout` (14), `hasp_read` (15), `hasp_decrypt` (2) - so the runtime's
name-matched intercept table cannot see them; they are bound by ordinal against
the DLL name instead.

The check reads one 0x40-byte licence record (file `0xfff0`, offset `0xd00`),
decrypts it in place, and tests exactly two things:

* `~record[0x3E] == record[0x3F]`, a complement pair; get this wrong and the
  screen says `19-23 USB DONGLE ERROR 3`;
* `record[0..4]` against the title id, which the caller has just assembled in
  its own frame at `+0x34`.

So the id does not have to be known or hard-coded: the intercept reads it back
out of the caller's frame, which `es3_native_call` leaves addressable because
it consumes the return address before the interceptions run. For this dump it
is `27432`.

### Things that were believed and are not true

Recorded because each one cost a day and each one was convincing.

* **"The startup packages are never registered."** The engine stopped on
  `Failed to find object 'DistributionFloat PlayerCustomisation.AngularAccelCurve'`
  and `PlayerCustomisation` was never requested from disk, which read as a
  package-loading gap. It was not. `--find-string AngularAccelCurve` found the
  name in guest memory 56 times: `Startup.upk` had decompressed correctly all
  along. The object genuinely is absent - it lives in the gameplay maps, not in
  `Startup.upk` - and the engine is *supposed* to fail that lookup and carry
  on. What it could not do was carry on, because the throw had nowhere to land.
* **"LZO decompression is mislifting."** `Startup.upk` is LZO, not zlib, and
  the guest decompresses it in lifted code, which made a lifter bug the obvious
  suspect. Inflating the package independently with python-lzo and comparing
  ruled it out: all 155,615,758 bytes are right.
* **"The optimiser broke it."** A CMake build died early with a guest
  `RaiseException(1)`; the working build used `/Od` and that one used `/O2`, so
  the flag was the obvious suspect and it got written down as a finding.
  Rebuilding at `/Od` died the same way, and so did the binary that had run
  twenty minutes earlier. `Direct3DCreate9` had started reporting **zero
  adapters** - the display device on this machine comes and goes - and UE3
  raises a fatal error on that before it loads a single package, which in the
  log looks nothing like a display problem. Three builds, one environment, and
  a build flag took the blame. `[d3d9] N adapter(s)` is printed every run now,
  and a run reporting zero should be thrown away rather than diagnosed.

* **"The frames are the UnrealScript VM, so this is config."** Two of the
  frames referenced `.ini` and `GetConfigName`, which said `LoadConfig`. That
  attribution came from disassembling a fixed number of bytes per frame and
  running off the end of the function into its neighbour. With the extents from
  `.pdata` the same frames say `"Attempt to assign variable through None"` and
  `"Accessed None '%s'"` - the script interpreter.

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
    --eh-trace               every guest throw, the frames it walks,
                             and where it lands
    --find-string TEXT       scan committed guest memory for TEXT
    --capture N              write frame N out as es3_frame_N.png

A fault reports the guest PC, because the lifter maintains `c->rip` per basic
block and at every call return point. Without the return points a fault in a
caller is attributed to whatever the callee last executed — which for a
one-instruction IAT thunk reads as "the crash is in memset", and is both wrong
and convincing.
