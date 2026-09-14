# systemes3recomp

```
  ###  #   #   ###  #####  ###  #   #     ###  ####   ####
 #      #   # #       #   #     ## ##    #     #      #
  ###    # #   ###    #   ###   # # #    ###   ####   ###
     #    #       #   #   #     #   #       #      #     #
  ###     #   ####    #    ###  #   #    ###   ####   ####

 Static Recompilation Toolkit for Namco System ES3 Arcade Games
```

> A System ES3 is a 2013 PC in an arcade cabinet. The game is a 32-bit Windows
> executable that calls kernel32 and Direct3D. So don't emulate the board —
> recompile the executable and hand it the libraries it already wanted.

**[Join the sp00nznet recomp Discord](https://discord.gg/CRpzGWZFcu)** — the
community hub for sp00nznet's recomp projects.

**Current version: v0.1.0.** The pipeline runs end to end against *Mario Kart
Arcade GP DX* at **99.99% instruction coverage**. The whole game builds to a
32.8 MB native executable and **boots and stays up** — 47 million guest calls,
27 threads, its config read, D3DX10's thread pump started, its window class
registered — with **all 495 imports** answered by real DLLs, the cabinet's own
camera and JVS libraries included. One Win32 call stands between that and a
picture. See [Status](#status) and
[Where it stops](#where-it-stops-exactly).

---

## What is this?

Namco's System ES3 (2013) is what happened after Sega's Lindbergh: an arcade
board that is a commodity Intel desktop, a commodity NVIDIA card, and Windows
Embedded running a Win32 application that Visual Studio 2010 built. See
[docs/hardware.md](docs/hardware.md).

That makes it an unusually good static recompilation target, for a reason worth
saying out loud: **the host is the machine.** There is no CPU to model — the
desktop you are reading this on is the same x86-32. There is no GPU to
emulate — the game wants Direct3D 9 and 10, and those still exist. There is no
operating system to reimplement — `CreateFileW` is `CreateFileW`.

What is left is the game's own code, which is what a static recompiler is for,
and four pieces of arcade hardware that a desktop does not have. Those four are
the honest remainder and they are [documented](docs/board-io.md) rather than
hand-waved.

This toolkit is **title-agnostic**. Everything it knows about a game it learns
from that game's executable.

## The pipeline

```
        YOUR GAME TREE
              |
              v
   +----------------------+   PE32 sections, entry point, the IAT, the
   |  1. Read the PE      |   relocations. pcrecomp's tools/pe/.
   +----------------------+                           WORKS
              |
              v
   +----------------------+   The binary is stripped. Recursive descent from
   |  2. Find the         |   the entry point, plus prologue and data-pointer
   |     functions        |   scans. pcrecomp's tools/disasm/.     WORKS
   +----------------------+   Slow, and the least exact step. 28,597 found.
              |
              v
   +----------------------+   x86-32 -> C, one C statement per instruction,
   |  3. Lift to C        |   reloc-aware so absolute addresses survive.
   +----------------------+   pcrecomp's tools/lift/.             WORKS
              |
              v
   +----------------------+   Derive the stack purge for every import, from
   |  4. Resolve the      |   the SDK, the mangling, or the callee's own
   |     imports          |   `ret N`. pcrecomp's tools/pe/.       WORKS
   +----------------------+                            489 of 495
              |
              v
   +----------------------+   Map the image where it was linked, point the
   |  5. Link the runtime |   IAT at us, hand the rest to Windows.
   +----------------------+   src/runtime/         455 of 495 answered
              |
              v
        NATIVE EXECUTABLE
```

### Almost none of this is ours

Steps 1 to 4 are [**pcrecomp**](https://github.com/sp00nznet/pcrecomp), the
shared PC toolbox, vendored here as a git submodule. One PE parser, one x86-32
lifter, one function-recovery pass — shared with every PC-era target rather
than forked per platform, so a fix to `adc` helps System ES3 and *Fury³* at
once.

There is no lifter subclass in this repo at all, which is one fewer than
[lindberghrecomp](https://github.com/sp00nznet/lindberghrecomp) needed. A Linux
ELF reaches its libraries through PLT stubs and the lifter cannot see through
those, so Lindbergh had to teach it. A PE reaches them through the IAT — an
indirect call through a data slot — and the stock lifter already emits exactly
the right thing:

```c
{ uint32_t _ct = rd32(GVA(0x0081D068)); push32(c, 0x004A12C7u); dispatch(c, _ct); }
```

So the boundary is drawn at load time instead. `guest_load()` writes a sentinel
address into every IAT slot and `dispatch()` routes that range to `hle_call()`.
That is not just less code — it catches every way an import can be reached, not
only a direct `call [__imp_X]`: the `jmp [__imp_X]` thunks MSVC emits, a
pointer copied out of the IAT and called much later (the CRT does this), and
the vtables Direct3D and the OKAO libraries hand back. A lifter-side pattern
match sees the first and misses the rest.

### What we gave back

This project is the first thing to run pcrecomp's whole PC pipeline over a
whole stripped game, and that found a lot. All of it was fixed **upstream in
[pcrecomp](https://github.com/sp00nznet/pcrecomp)** rather than here, which is
the shape a good change to any of these projects takes.

**A function's extent was not clamped to the next function.** `func.end` comes
out of recursive descent as `max(block.end)`, and descent follows unconditional
jumps — so one `jmp` to a shared epilogue puts the end far past the body and
everything in between is counted as part of this function. The lifter then
reads `size` bytes *linearly*, so it lifts all of them, inside this function,
again. Measured here: **28,597 functions claiming 89.5 MB of bodies for a
4.3 MB code range**, 271 of them over 64 KB and one at 1.3 MB, which lifted to
1.9 GB of C. That is not a coverage problem, it is the same code twenty times
over, and no compiler will take it. `clamp_extents()` brings the claim to
6.7 MB and the output to 2.1 million lines.

**And a body cut mid-function returned instead of transferring.** Falling off
the end of a lifted extent is a real control transfer on x86; the generated C
reached its closing brace and returned, skipping the `ret` that never ran and
leaving esp four bytes low. Nothing faults and every value the caller reads
afterwards is one slot out. Now it emits `dispatch(c, <end>); return;`, which
is what the fallthrough *is* — dead code in a correctly-sized function, and the
reason clamping is safe.

**`fucom` was 81% of the remaining gap.** Of 50,555 instructions the lifter
could not express, 40,796 were `fucompp` and 7,450 more were `fucomp` — one
mnemonic was most of it. They were missing because only `fcom`/`fcomp`/`fcompp`
were listed, and `fucom` is the *same comparison*: the two differ only in which
NaNs raise an invalid-operation exception, which this model does not raise at
all. Which made the omission worse than it looks, because the unordered forms
are the common ones — MSVC emits `fucompp; fnstsw ax; test ah` for an ordinary
float comparison in C. Coverage went from 99.73% to **99.97%**.

**Three instructions killed the lift outright**, each ending the whole run with
a traceback: `repz ret` (AMD's branch-prediction idiom for a plain `ret`, which
MSVC puts at every branch target that returns), `jmp fword ptr` far pointers,
and `fld tbyte` / `fldenv`, which were silently read as 64-bit doubles.

**Reading a stack purge off the callee's own `ret N`.** Every shim has to pop
exactly what the real function popped; get one wrong and the guest stack
silently desynchronises. Every existing strategy read the count off a *name*,
and names run out exactly where an arcade port gets interesting: OKAO Vision
exports by ordinal only, and its DLLs exist nowhere but in a game tree. But the
count is also in the callee — so `stdcall_argc.py` now disassembles the export
and reads it. Checked against the Windows SDK import libraries over every
export where both have an answer: **1,307 agree, 2 disagree.** On this import
table it took 449 of 495 resolved to **489 of 495**.

**Moving the x87 stack across the lifted/real boundary.** `hybrid_regs` is the
integer registers, which is the whole ABI for almost every call — except that a
function returning `float` returns it in `st(0)`, and MSVC's `_CIpow` /
`_CIsqrt` / `_CIsin` family takes its arguments in `st(0)`/`st(1)` and nothing
on the stack at all. *Mario Kart* imports nine of those. `hybrid_fpu_push` /
`pop` / `depth` / `clear`, and the depth is what lets the *result* side need no
table of which functions return floats: a callee that returned one is exactly a
callee that left the stack one deeper than it found it.

## Status

**The whole pipeline has been run against a real game binary.** *Mario Kart
Arcade GP DX* v1.00.32 — 5.8 MB, PE32, `i386`, image base `0x00400000`, entry
`0x007CB996`, built 2013-04-23 — goes in.

| | |
|---|---|
| PE parsing | **Works.** Verified against four *Mario Kart Arcade GP DX* builds spanning 2013–2022. Sections, entry, 495 imports across 27 DLLs, 108,414 relocations. |
| Function recovery | **26,075 real ones.** A first pass found 28,597; 2,526 of those were addresses inside instructions and 237 more only showed up once the catalog was complete. 2,586 branch targets then had to be *added*, because clamping a function at a shared epilogue leaves its second half unreachable. |
| Lifting | **Works.** 31,096 functions lift to **2,633,954 lines of C** in 78 translation units. Not one fails outright. The count grew past the catalog's own because the driver now closes what the *generated text* dispatches to, round after round, until nothing is left open - which is a thing the catalog cannot know, because some of those addresses are the lifter's own arithmetic. |
| Instruction coverage | **99.966%.** 886 emitted lines out of 2.6 million are unlifted, and the game has now executed none of them: the ones it used to reach - `lock xadd`, `lock cmpxchg`, `cvtdq2ps` - went upstream this round. What is left is overwhelmingly data the recovery pass mistook for code. |
| Compiles | **Yes.** The largest translation unit — 108 MB of C, before the split was made size-aware — builds to a clean 70 MB object with MSVC, no warnings. |
| Import resolution | **489 of 495** stack purges derived. The six left are `d3dx9_43` CPU-dispatch thunks, which need no purge — they are forwarded, and the real callee unwinds. |
| Runtime | **Boots, opens a window, brings up both renderers, loads its data.** The full lifted image creates its `mkart3` window, gets a working window procedure through it, brings up Direct3D 9Ex and Direct3D 10, loads its shader effects with D3DX10, opens DirectInput 8, and runs a real frame loop - five million guest calls, twenty-nine threads, the game's own `*INF*` and `*ERR*` lines in the log, and D3DX10's thread pump calling the game's own `ID3DX10DataLoader` methods as lifted code. The window is still black, and a thread D3DX10 created runs out of real stack - see below. |
| Imports, from the game tree | **495 of 495.** Run from a real tree and every import resolves against a real DLL, the cabinet ones included: the OKAO Vision camera and `JVSEmuMK.dll` ship with the game, so `hle_native.c` forwards to the actual board libraries. |
| The board | **Not started, on purpose.** The 40 remaining imports: JVS, the card reader, the camera, authentication. See [docs/board-io.md](docs/board-io.md). |

### Getting from a window that would not open to a window that runs

Five things were in the way, and only the first was about windows.

**The callback arena.** `hybrid`'s per-thread arena was reserved *and*
committed whole. Seventeen threads at 64 MB is most of a 32-bit address space,
and the thread that lost the race got no arena - then returned 0 from every
callback, silently. A window procedure answering 0 to `WM_NCCREATE` is
`CreateWindowExW` returning NULL and setting `ERROR_NOT_ENOUGH_MEMORY`, which
is true and about the wrong thing entirely. Fixed upstream: reserve whole,
commit a frame at a time, and say so out loud when it fails.

**A jump table one arm short.** The window procedure's message switch has ten
arms; the lifter stopped walking the table at the first entry outside the
current function, and arm nine - `WM_NCCREATE` - was past a neighbour that
recovery had called a function of its own. So the procedure reached `abort()`
for the one message that decides whether a window exists.

**An extent ending mid-instruction.** Clamping a recovered function against a
false start cuts an instruction in half, and the fall-through address then
lands *inside* a real one. `74 5B` is a two-byte `je`; read from its second
byte it is `pop ebx`. No fault, and the guest stack one slot out from then on.

**The guest's own HINSTANCE.** An MSVC image knows its base as a link-time
constant and hands it to Windows wherever a module handle is wanted. Here that
is `0x00400000` - a region `VirtualAlloc` handed out, which the loader has
never heard of. `DirectInput8Create` returned `E_INVALIDARG`, the input
initialiser returned false, and every subsystem open after it was skipped;
that surfaced thirty thousand calls later as a task updating through a null
singleton. The runtime now substitutes its own module handle, in the libraries
where a module handle is the only thing that argument can be.

**Real code calling guest code.** The window procedure and the thread entry are
*arguments*, so they can be thunked. A COM interface the game implements is
not: Mario Kart hands D3DX10's thread pump an `ID3DX10DataLoader` whose vtable
is seven guest addresses, and D3DX10 calls them on its own worker threads -
running the original bytes, into an IAT full of sentinels, faulting on an
import nobody called.

The answer generalises, so it is worth stating plainly: **the guest image is
mapped without execute.** Any pointer to guest code that reaches a real library
unthunked now arrives as an execute violation at the address that was called,
with the caller's registers in the `CONTEXT` and its return address on the
stack - which is everything a dispatch needs. `crash.c` builds a CPU from the
context, runs the lifted function, and resumes at the return address. One
handler covers every unthunked callback there will ever be, including the ones
nobody has found yet.

### Where it stops now

The window is real, framed, 1280x720, and black. Everything up to drawing works:

* `006AB300`, the function that brings the game up, **returns 1**. It returned
  0 all through the previous round, and everything after it was skipped.
* `004042C0` opens every subsystem, including the input one whose singleton a
  task used to read while it was still null.
* **Direct3D 9Ex creates its device and returns S_OK**, windowed.
* The game loads its data, prints its own `*INF*` and `*ERR*` lines, and runs
  its frame loop.

It then asks DXUT for a Direct3D device and is told there is none, which on
this machine is correct: measured in-process, `Direct3DCreate9` reports **0
adapters**, `Direct3DCreate9Ex` returns **`D3DERR_NOTAVAILABLE`**, and DXGI
enumerates **6 adapters with 0 outputs** between them. That is a remote
session, not a port that does not work, and `es3_report_display()` now says so
in one line before the guest starts rather than letting the game hang in a
modal box nobody is going to click.

Getting that far took two x87 fixes in the lifter, both upstream in pcrecomp.
`fxch` was lifted as a swap of `st(0)` with itself - capstone reports
`fxch st(1)` with *both* registers, `st(0)` first - and the popping arithmetic
(`faddp st(1)` is `st(1) += st(0)`) wrote its result into the slot the next
`fpop` discards. The first one turned the game's fixed-timestep accumulator
into an infinite loop: it subtracted the step from the wrong register, the step
came out negative, and the thread carrying the whole call graph never finished
a frame. 24,268 `fxch` and ~80,000 popping sites in one image.

What is left is speed, and it is not a detail.

| | |
|---|---|
| dispatches per second | **2.4 million** |
| per dispatch | about **400 ns** |
| frame steps in 30 seconds | **2 to 14**, depending on the run |
| guest calls per frame | about **35 million** - it is still loading |

Four hundred nanoseconds per guest call is the whole problem. The hottest
function in a sampled window was `0041EAA0`, called ninety-seven thousand
times: it is `fabsf`, two instructions, and every one of those calls went
through `es3_note_dispatch`, a watch check, an import-range check, a thunk
check, a table lookup and an indirect call into a C function that sets up a CPU
frame.

**The fix is that a direct call should be a direct call.** The lifter emits
`push32(c, ret); dispatch(c, 0x0041EAA0u);` for `call 0x41eaa0`, and the driver
knows - after the fact, from its own output - that `0041EAA0` is one of the
functions it lifted. Emitting `push32(c, ret); L_0041EAA0(c);` instead removes
the lookup entirely for the overwhelming majority of calls. That needs a
generated header of declarations and one pass over the emitted text.

Two things that were tried and measured and did **not** help, recorded so they
are not tried again:

* **An address-indexed dispatch table** in place of the binary search. Seventeen
  megabytes of pointers, one load instead of fifteen probes: 2.38 million
  dispatches a second, against 2.7 before. The search was not the cost.
* **Bigger thread stacks.** Lifted code really does overflow 16 MB after about
  four minutes of loading (C00000FD, on a thread that then cannot handle its
  own overflow) - but a stack is a *reservation* and this game has twenty-nine
  threads. 64 MB each ran the address space out in fifteen seconds; 32 MB moved
  the failure somewhere else again. The answer is for lifted code to use less
  real stack per guest frame, not for every thread to reserve more.

### Seeing a death that has no handler

`ES3_DEBUG=1` relaunches the process as its own debuggee and reports every
exception the child takes - code, address, thread, first or second chance, the
module it happened in, and whether the memory it touched was committed,
reserved or free. That is the only way to see a fault the kernel could not
dispatch, and it is how the stack overflow above was found at all.

It works because parent and child are the same image at the same base
(`/BASE:0x20000000`, `/DYNAMICBASE:NO`), so `dispatch_owner()` in the parent
turns the child's host address straight back into a guest function.

```
[debug] first chance C0000005 access violation at 037B7A52 on thread 62332
        in private memory at 03720000; target region 00000000 FREE (writing 7F81FDC0)
[debug] SECOND chance C0000005 access violation at 776F911C on thread 62332
        in ntdll.dll; target region 00000000 FREE (reading 7F81FDA4)
```

The second line is ntdll failing to *read* the stack it was trying to push an
exception frame onto. That is what an unreportable death looks like from
outside.

### What is in the runtime for the next round

| | |
|---|---|
| `ES3_DEBUG=1` | run as our own debuggee; every exception, named, with its module |
| `ES3_TRACE_IMPORTS=1` | the first call to each import, in order |
| `ES3_TRACE_CALLS=Name,Name` | every call to those, with arguments - strings shown as strings - result and last error |
| `ES3_WATCH_VA=6ab300,4042c0` | when those guest functions are entered, from where, on which thread, and what they returned |
| `es3_trail.bin` | every dispatch of the whole boot, a million entries, `py -3.11 -m tools trail` |
| `[game]` lines | the game's own `OutputDebugString`, which on the cabinet went to a kernel debugger nobody was watching |
| `ES3_NO_HINSTANCE_FIX`, `ES3_GUEST_EXECUTABLE`, `ES3_NO_TEB_COVER`, `ES3_NO_WNDPROC_THUNK` | turn each fix off and watch its symptom come back |

### How it got this far

```
=== the guest faulted ===
  guest image at 0x00400000, 18 dispatches so far
  last 16 dispatches (oldest first):
    E5300130  import LoadLibraryW (KERNEL32.dll)      <- the JVS injection stub
    007CC173  inside the guest image                  <- mainCRTStartup
    E53000F8  import GetSystemTimeAsFileTime          <- __security_init_cookie
    E53000C8  import GetCurrentProcessId
    E53000CC  import GetCurrentThreadId
    E53000FC  import GetTickCount
    E530014C  import QueryPerformanceCounter
    007CB99B  inside the guest image
    007CB70B  inside the guest image
    007CBEB0  inside the guest image
    E53000F0  import GetStartupInfoW                  <- __tmainCRTStartup
    E5300108  import HeapSetInformation
    E5300114  import InterlockedCompareExchange
    007CC142  inside the guest image
    E53002FC  import _initterm_e (MSVCR100.dll)       <- and here
  E5300298 could not be executed   an IMPORT SENTINEL

  That address is the import sentinel for __set_app_type (MSVCR100.dll).
```

Every one of these was found by running it, and each one moved the boot:

| what was wrong | got to |
|---|---:|
| `mainCRTStartup` was past `.text`'s VirtualSize, so the scan never saw it | 0 |
| `_initterm_e` ran the initialiser table as native code | 18 |
| `_fmode` is a variable, and its IAT slot held a sentinel | 21 |
| `0x0081C100` is the third byte of an `fld` and lifted to `hlt` | 111 |
| a false start's neighbour was clamped onto it and fell into nothing | 637 |
| a shared epilogue cut a function whose branch targets then had no body | 1,171 |
| SEH cannot work on a stack the TEB has never heard of | 2,015 |
| 32 KB is not a stack for a worker thread running the game's call graph | 13,373 |

### The binary is stripped

Worth saying on its own, because it is the one place this platform is *harder*
than Lindbergh. A Lindbergh ELF ships its full symbol table — 31,752 named,
sized functions, no discovery problem at all. An ES3 executable ships nothing:
the PDB path survives in the debug directory (`D:\work\MK3\repos\branches\
Master_1st\Bin\Final\MK_AGP3_FINAL.pdb`) and the PDB does not.

So the function list is recovered, not read, and recovery is the slow and
fallible step — half an hour on this binary, and the result has to be treated
as a strong signal rather than ground truth. The number that says so:
**7,050 of the 28,596 lifted bodies end in a fallthrough transfer** rather than
a return, which is what a function cut short by a false-positive start next
door looks like. 6,832 of those transfers land on another lifted function and
carry on correctly; the other 218 abort naming the address they wanted, which
is how you find them.

That is a quarter of the image reached by a path that should not have been
needed. It works, and it is not right, and it is the most valuable thing in
this repo to improve.

### The graphics are two APIs at once

Not a detail: the same binary imports from **both** `d3d9.dll` and
`d3d10.dll`, plus `d3dx9_43` and `d3dx10_43`, and chooses at run time. Any port
has to answer both, or find out which one the cabinet actually took.

## Use

```powershell
git clone --recursive https://github.com/sp00nznet/systemes3recomp
cd systemes3recomp

# what the executable asks the board for
py -3.11 -m tools pe MK_AGP3_FINAL.exe

# recover its functions. Half an hour on a 4 MB .text - run it once and keep
# the catalog; every later step reads it.
py -3.11 -m tools scan MK_AGP3_FINAL.exe catalog.json

# lift it - minutes, not hours
py -3.11 -m tools recomp MK_AGP3_FINAL.exe catalog.json gen\

# the checks
py -3.11 tools\recomp\test_driver.py
py -3.11 pcrecomp\tools\pe\stdcall_argc.py --selftest
py -3.11 pcrecomp\tools\disasm\disasm32.py --selftest
cmake -S . -B build -A Win32; cmake --build build --config Release
ctest --test-dir build -C Release
```

Needs Python 3.11 with `capstone` and `pefile`, and a 32-bit MSVC toolchain.

Neither the 32-bit part nor the MSVC part is negotiable. The CPU model is flat
— a guest register holds a real host address — and the game maps at
`0x00400000`, which only exists as an address in a 32-bit process. MSVC because
the lifted/real boundary is x86 `__asm`, and because handing the game the
host's own kernel32 needs a Windows host to hand it. The CMake refuses both
rather than let you find out later.

## Layout

```
tools/
  pcrecomp.py   load the shared toolbox out of the submodule
  recomp/       the ES3 end: catalog -> lifted C, and the generated headers
src/runtime/
  guest.c       map the PE where it was linked, point the IAT at us
  dispatch.c    original address -> lifted function, sentinels on the way past
  hle.c         the import registry and the stack unwind
  hle_native.c  forward to the host's own DLL - which is most of the table
  hle_board.c   the parts of the cabinet that are not a PC
pcrecomp/       the PE tools, the lifter and the boundary (git submodule)
docs/
  hardware.md   what a System ES3 is, read off the binaries
  board-io.md   JVS, the card reader, the camera, authentication - measured
```

## Legal

MIT, and original work throughout. **No game data, no keys, and no
circumvention of anything.** The tools here read a PE's own headers and
translate x86 machine code you supply. System ES3 titles are © their
publishers; this is an independent, non-commercial preservation project.
