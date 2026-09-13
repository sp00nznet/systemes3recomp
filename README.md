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
Arcade GP DX* at **99.97% instruction coverage**, and the recompiled host maps
the image, answers 455 of its 495 imports out of the host's own DLLs and
reaches the game's entry point. See [Status](#status) for the numbers.

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
| Function recovery | **Works.** **28,597 functions** in 6 discovery rounds — 121 thunks, 11,972 leaves, 9,255,442 instructions — covering **99.5%** of the 4,308,348-byte code range. Nothing to read them from; see below. |
| Lifting | **Works.** All 28,596 sized functions lift to **2,126,309 lines of C** (199 MB) in 72 translation units. Not one fails outright. |
| Instruction coverage | **99.9737%.** 560 of 2,126,309 emitted lines are `/* TODO */ abort()`, down from 50,555 before the x87 compares landed upstream. |
| Compiles | **Yes.** The largest translation unit — 108 MB of C, before the split was made size-aware — builds to a clean 70 MB object with MSVC, no warnings. |
| Import resolution | **489 of 495** stack purges derived. The six left are `d3dx9_43` CPU-dispatch thunks, which need no purge — they are forwarded, and the real callee unwinds. |
| Runtime | **Boots.** Maps the image at `0x00400000`, patches all 495 IAT slots, resolves **455 imports** against the host's own DLLs and reaches the game's entry point. Not yet run against the full lifted image. |
| The board | **Not started, on purpose.** The 40 remaining imports: JVS, the card reader, the camera, authentication. See [docs/board-io.md](docs/board-io.md). |

### What is still unlifted, in full

560 lines out of 2.1 million, and no single family dominates any more:

| | count |
|---|---:|
| `in` / `out` / `insb` — port I/O, which userspace has no business doing | 82 |
| `clc` `stc` `cli` `hlt` `into` `iretd` `pushal` `arpl` `salc` … | ~180 |
| MMX — `movd` `psrlq` `psllq` `por` `emms` (a second register file, not SSE) | ~60 |
| `jmp`/`call fword ptr` — m16:32 far pointers, which a flat model cannot take | 13 |
| packed SSE — `shufps` `mulps` `addps` | few |

**A good part of that is not really code.** `hlt`, `cli`, `into`, `iretd`,
`arpl` and `salc` do not appear in a compiled Win32 user-mode program. They are
what data looks like when the recovery pass takes a pointer-shaped word for a
function start — which is the honest reading of this table, and the reason
[CONTRIBUTING](CONTRIBUTING.md) puts recovery precision above everything else.

Packed SSE arithmetic is the one left out deliberately rather than missed: it
needs per-lane code, and a plausible-looking wrong lane is worse than an honest
`abort()`.

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

### The binary is stripped

Worth saying on its own, because it is the one place this platform is *harder*
than Lindbergh. A Lindbergh ELF ships its full symbol table — 31,752 named,
sized functions, no discovery problem at all. An ES3 executable ships nothing:
the PDB path survives in the debug directory (`D:\work\MK3\repos\branches\
Master_1st\Bin\Final\MK_AGP3_FINAL.pdb`) and the PDB does not.

So the function list is recovered, not read, and recovery is the slow and
fallible step. pcrecomp's `disasm32.py` does it in rounds — direct branch
targets, then `push ebp; mov ebp, esp` prologues, then a fixpoint over tail
calls and thunks, then a probe of every pointer-shaped word in the data
sections. That last pass is why it also refuses candidates: a value that merely
*looks* like a code address, and does not decode as a run of instructions
reaching a `ret`, is not a function.

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
