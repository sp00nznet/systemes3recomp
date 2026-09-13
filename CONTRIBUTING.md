# Contributing to systemes3recomp

This toolkit turns a Namco System ES3 game's Win32 executable into native C.
Anything that gets a real title closer to running is welcome.

## Where the gaps are

Real, scoped, and measured against *Mario Kart Arcade GP DX* v1.00.32 — 495
imports, 27 DLLs. None of them need permission to start.

### Done, for reference

The import table went from 449 of 495 stack purges derivable to **489 of 495**,
by teaching [pcrecomp](https://github.com/sp00nznet/pcrecomp)'s
`stdcall_argc.py` to read the count out of the callee's own `ret N` rather than
off a name. That is the shape a good contribution here takes: measure first,
fix it in the one place that serves every target, leave a test behind.

### Still open here

| Area | What is missing | Difficulty |
|---|---|---|
| **A full boot** | The runtime builds and its self-checks pass, but no title has been lifted and run end to end yet. The first run will name whatever is wrong, and finding out what that is is the single most valuable thing anyone can do to this repo. | Medium |
| **Callbacks** | A forwarded library function that calls back into game code — a window procedure, a `qsort` comparator, a D3D callback — hands the host a guest VA, and the original bytes are still mapped, so it silently runs the *unlifted* original. pcrecomp's `hybrid_thunk()` is the fix and is already in the submodule; it needs wiring in. The first one to bite will be the window procedure. | Medium |
| **JVS input** | Coins, wheel, pedals, buttons. Nothing is playable until this works, and the report layout has not been measured. See [docs/board-io.md](docs/board-io.md). | Medium |
| **The card reader** | `bngrw.dll`, 11 imports. An honest "no card present" first — and finding out what the game does with it. | Medium |
| **OKAO Vision** | 40 imports, by ordinal, undocumented. An honest "no face found" should let the game proceed; that is a belief, not a measurement. | Large |
| **The QR encoder** | `Nbam_QR_Code.dll`, 6 imports, pure computation with no hardware behind it. The easiest of the board DLLs and the least likely to block anything. | Small |
| **Another ES3 title** | Everything here is title-agnostic by construction, and exactly one title has ever been through it. A second one is the real test of that claim. | Varies |

### Still open upstream, in pcrecomp

| Job | Why it lands there | Difficulty |
|---|---|---|
| **Function recovery precision** | The binary is stripped, so the function list is recovered by recursive descent and the data-pointer probe. Every false start lifts to garbage and every miss is an unresolved dispatch at run time. `score_recovery.py` exists to measure this against a reference; ES3 has no linker map to score against, which makes a scoring method for stripped binaries its own open problem. | Large |
| **Packed SSE and MMX** | Deliberately left unlifted rather than guessed at: they need per-lane code, and a plausible-looking wrong lane is worse than an honest `abort()`. | Medium |
| **The six unresolvable purges** | `d3dx9_43`'s math exports are `jmp dword ptr [...]` CPU-dispatch thunks whose slot is filled at DLL init. Nothing static can follow one. They do not currently need solving — those imports are forwarded and the real callee unwinds — but a project that wants to reimplement D3DX rather than forward it would. | Medium |

## The rules of the house

**Fix it upstream when upstream is where it belongs.** One PE parser, one x86
lifter, one function-recovery pass, shared with every PC-era target. Forking
any of them to fix one game is how you end up maintaining four.

**Measure, do not assume.** Every number in this repo's documentation came out
of a run against a real binary, and says which one. If you cannot measure it,
say that instead.

**An honest abort beats a plausible stub.** A handler that returns 0 lets the
game past the call and breaks it somewhere else an hour later. This is why
`hle_board.c` binds nothing.

**Leave one runnable check.** `ctest --test-dir build -C Release` and
`py -3.11 tools\recomp\test_driver.py` are the whole suite; add to them.

## Running the checks

```powershell
py -3.11 tools\recomp\test_driver.py
py -3.11 pcrecomp\tools\pe\stdcall_argc.py --selftest
cmake -S . -B build -A Win32
cmake --build build --config Release
ctest --test-dir build -C Release
```
