# Contributing to systemes3recomp

This toolkit turns a Namco System ES3 game's Win32 executable into native C.
Anything that gets a real title closer to running is welcome.

## Where the gaps are

Real, scoped, and measured against *Mario Kart Arcade GP DX* v1.00.32 — 28,597
recovered functions, 2.1 million lines of lifted C at 99.97% instruction
coverage, 495 imports from 27 DLLs. None of them need permission to start.

### Done, for reference

Seven fixes, all of them upstream in
[pcrecomp](https://github.com/sp00nznet/pcrecomp), all of them found by running
the pipeline over a whole game rather than by reading the code. The two worth
knowing about:

* function extents were not clamped to the next function start, so the catalog
  claimed **89.5 MB of bodies out of a 4.3 MB code range** and the lift came
  out at 1.9 GB of C — the same code twenty times over
* `fucompp` and `fucomp` were **81% of every instruction the lifter could not
  express**, because only the ordered `fcom` forms were listed and `fucom` is
  the same comparison

That is the shape a good contribution here takes: measure first, fix it in the
one place that serves every target, leave a test behind.

### Still open here

| Area | What is missing | Difficulty |
|---|---|---|
| **CreateWindowExW returns ERROR_NOT_ENOUGH_MEMORY** | **The one thing between here and a picture.** The game boots, stays up, registers its window class with a working thunked window procedure, and both of its `CreateWindowExW` calls return NULL with error 8. The class fields are sane and the procedure is genuinely called during creation - with `ES3_NO_WNDPROC_THUNK=1` the call never returns at all, because USER32 runs the unlifted original. Two suspects, neither proven: the first window passes the *guest* image base as `hInstance`, which is not a module this process loaded; and `es3_teb_cover()` leaves NT_TIB spanning both stacks with unmapped space between, which USER32 does look at. `ES3_TRACE_CALLS`, `ES3_NO_WNDPROC_THUNK` and `ES3_NO_TEB_COVER` are there for isolating it. | Medium |
| ~~Thread-safe lifted->real~~ (done) | **This is the one thing between here and a running game.** The image boots, spawns fourteen engine threads and runs its task loop for 13,373 guest calls before two of them fault at once. pcrecomp's hybrid is reentrant but not thread-safe in the lifted->real direction: the marshalling block is file-scope, so two threads calling a forwarded import together hand each other's registers to each other's target. `__declspec(thread)` does not work and the file says why. The fix is to park the host esp in a TEB slot - no registers needed - and recover the guest's final esp with `xchg esp, fs:[0x14]`. Forty lines of assembly in code three other projects use, so it wants its own pass and its own testing. | Medium |
| **Rendering** | Once there is a window: every D3D9/D3D10/D3DX import is already forwarded to the host's real DirectX and the game has already started D3DX10's thread pump, so the next unknown is whatever device creation does. Nobody has seen a frame yet. | Medium |
| **Recovery precision** | 7,050 of 28,596 lifted bodies end in a fallthrough transfer rather than a return, which is what a function cut short by a false-positive start next door looks like. 6,832 of those land on another lifted function and carry on; 218 abort. A quarter of the image is reached by a path that should not have been needed. | Large |
| **More callbacks** | `_initterm`/`_initterm_e` are walked here, and `_onexit`, `atexit`, `signal`, `qsort`, `SetUnhandledExceptionFilter`, `RegisterClass*`, `SetWindowLong*`, `CreateThread` and `_beginthreadex` are thunked. Anything else that stores a guest function pointer will fault on an import sentinel, and `crash.c` names it when it does - that is the signature to look for. | Small each |
| **JVS input** | Coins, wheel, pedals, buttons. Nothing is playable until this works, and the report layout has not been measured. See [docs/board-io.md](docs/board-io.md). | Medium |
| **The card reader** | `bngrw.dll`, 11 imports. An honest "no card present" first — and finding out what the game does with it. | Medium |
| **OKAO Vision** | 40 imports, by ordinal, undocumented. An honest "no face found" should let the game proceed; that is a belief, not a measurement. | Large |
| **The QR encoder** | `Nbam_QR_Code.dll`, 6 imports, pure computation with no hardware behind it. The easiest of the board DLLs and the least likely to block anything. | Small |
| **Another ES3 title** | Everything here is title-agnostic by construction, and exactly one title has ever been through it. A second one is the real test of that claim. | Varies |

### Still open upstream, in pcrecomp

| Job | Why it lands there | Difficulty |
|---|---|---|
| **Function recovery precision** | The binary is stripped, so the function list is recovered by recursive descent and the data-pointer probe. Every false start lifts to garbage and truncates its neighbour; every miss is an unresolved dispatch at run time. `score_recovery.py` exists to measure this against a reference, and ES3 has no linker map to score against — which makes a scoring method for stripped binaries its own open problem. The 180 `hlt`/`cli`/`into`/`iretd` lines in the lifted output are the visible tip: those instructions do not appear in compiled user-mode code, so each one is data that a scan called a function. | Large |
| **Packed SSE and MMX** | Deliberately left unlifted rather than guessed at: they need per-lane code, and a plausible-looking wrong lane is worse than an honest `abort()`. About 60 lines of the remaining 560. | Medium |
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
py -3.11 pcrecomp\tools\disasm\disasm32.py --selftest
cmake -S . -B build -A Win32
cmake --build build --config Release
ctest --test-dir build -C Release
```
