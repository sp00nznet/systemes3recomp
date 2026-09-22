# Mario Kart Arcade GP DX: toolkit-side notes

What getting the first ES3 title running cost the toolkit, as opposed to what
it cost that game. Split out of the toolkit README, which had accumulated two
hundred lines about one binary.

The game's own bring-up story lives in its project:
https://github.com/sp00nznet/mariokartdx-systemes3-recomp/blob/main/docs/bringup.md

---

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

It does not stop. *Mario Kart Arcade GP DX* boots through the cabinet's whole
startup sequence and draws its attract mode, and the run ends when you end it.

What the toolkit learned getting there is worth more than the milestone, and
almost none of it was about the CPU.

**A cabinet check that fails is a black screen, not a warning.** Six different
errors — no I/O board, no dongle, no camera, no steering, no drive board, a
card reader answered in the wrong protocol — each set a mode whose entry in the
game's own table makes the frame loop skip the **entire task tick**. Any one of
them, alone, means no scene is ever built. A recompiled arcade title will not
say "the camera is missing"; it will draw nothing, and the reason will be five
levels down.

**Answer the question the hardware would answer, at the place it is asked.**
Every fix here is a pre-hook on the guest function that asks — is a board on the
bus, is the dongle readable, is the camera fitted — returning what a cabinet
would say. Not a poke held down from a watchdog: the boot evaluates each of
these *once*, a few seconds in, and a poke that resolves a heap chain at ten
hertz loses that race every time. `es3_bind_guest()` is the whole mechanism and
a handler that returns 0 lets the original run afterwards.

**Read the whole exit code.** A death that reached no vectored handler, no
unhandled-exception filter, no `ExitProcess`, no `TerminateProcess`, no
`NtTerminateProcess` and left no Windows Error Reporting record was chased for
days as "exit code 6". Through `cmd.exe` the code is `0x40010006` —
`DBG_PRINTEXCEPTION_C`, the exception `OutputDebugString` raises. MSYS was
printing the low byte. A process whose exit code *is* an exception code died of
that exception, and the vectored handler had been declining it every time. It
is informational and continuable; `es3_veh` now continues it, which is exactly
what `OutputDebugString`'s own `__try` does.

**And it was hiding three instructions.** `cvtps2pd`, then `fldln2`, then
`fyl2x` — each only visible once the one before it was fixed. `fldln2; fxch;
fyl2x` is how a compiler builds `log()`. They went upstream into pcrecomp with
the rest of the x87 transcendental set.

**Count your runs.** A failure that happens about half the time reads as a coin
flip, and three- and four-run streaks were repeatedly mistaken for signal in
this round — a JSON bisect, a screenshot flag, a hook — each of them noise.

#### Still open

| | |
|---|---|
| The serial boards | The game posts three-byte overlapped reads on COM1 for ever and never writes one: the board is expected to speak first, so `jvs.c`, which answers requests, has nothing to answer. The drive board and steering are stood in for with a flag each, not a protocol |
| Input | `ES3_JVS_SEQ` presses switches on a timetable and the operator menu never answered them — the switches it reads come from the USB I/O board, which is answered for existence and not for data |
| `ES3_TRACE_NET` | Binds four more imports, and the boot then stalls early and reproducibly. The ALL.Net listener prints the paths it is asked for instead |
| `tools watch` | Runs the game as a debuggee and reads the kernel's account of how it died. It found the stack overflow; it could never reach the later failure, because under a debugger the run does not get that far |

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
