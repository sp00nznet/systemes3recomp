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
Arcade GP DX*. See [Status](#status) for the numbers.

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
   +----------------------+   Slow: this is the hours-long step.
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
   +----------------------+   src/runtime/                       PARTIAL
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

Two things this project needed did not exist upstream, so they were built
upstream rather than here — which is the shape a good change to any of these
projects takes.

**Reading a stack purge off the callee's own `ret N`.** Every shim has to pop
exactly what the real function popped; get one wrong and the guest stack
silently desynchronises and the symptom appears nowhere near the cause. Every
existing strategy read the count off a *name*, and names run out exactly where
an arcade port gets interesting: OKAO Vision exports by ordinal only, and its
DLLs exist nowhere but in a game tree. But the count is also in the callee —
so `stdcall_argc.py` now disassembles the export and reads it. Checked against
the Windows SDK import libraries over every export where both have an answer:
**1,307 agree, 2 disagree.** On *Mario Kart*'s import table it took 449 of 495
resolved to **489 of 495**.

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
| Function recovery | **Works.** Recursive descent from the entry point, prologue scan, and data-pointer probe. See the table below. |
| Lifting | **Works.** |
| Import resolution | **489 of 495** stack purges derived. The six left are `d3dx9_43` CPU-dispatch thunks, which need no purge — they are forwarded, and the real callee unwinds. |
| Runtime | **Partial.** Image mapping, the IAT sentinel boundary, dispatch and the native forwarder build and run 32-bit, and the self-checks pass. Untested against a full game boot. |
| The board | **Not started, on purpose.** JVS, the card reader, the camera, authentication. See [docs/board-io.md](docs/board-io.md). |

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

# recover its functions - slow, run once, keep the catalog
py -3.11 -m tools scan MK_AGP3_FINAL.exe catalog.json

# lift it
py -3.11 -m tools recomp MK_AGP3_FINAL.exe catalog.json gen\

# the checks
py -3.11 tools\recomp\test_driver.py
py -3.11 pcrecomp\tools\pe\stdcall_argc.py --selftest
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
