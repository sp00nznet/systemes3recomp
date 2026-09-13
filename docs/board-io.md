# The board, measured

What a recompiled ES3 title asks for that a desktop cannot answer. Everything
here is read out of the import tables of the three *Mario Kart Arcade GP DX*
builds in this repo's target tree — nothing is inferred from documentation,
because there is none for most of it.

The numbers are `MK_AGP3_FINAL_v1.00.32.exe` (the 2013 Japanese release) unless
another build is named.

## The shape of the problem

495 imports, 27 DLLs. Sorted by who can answer them:

| | imports | who answers |
|---|---:|---|
| Windows itself — kernel32, user32, gdi32, advapi32, ole32, shell32, shlwapi, ws2_32, winhttp, winmm, iphlpapi, setupapi, comctl32, psapi | ~230 | the host, forwarded |
| Microsoft redistributables — MSVCR100, d3d9, d3d10, d3dx9_43, d3dx10_43, dinput8, MF/MFPlat/MFReadWrite | ~225 | the host, forwarded |
| **The cabinet** — eOkao×5, and on later builds bngrw, Nbam_QR_Code, JVSEmuMK | **40–58** | nobody yet |

`hle_native.c` forwards the first two groups to the host's own copy of the DLL
and does not reimplement any of it. This file is about the third group.

## Stack purges, and why they were hard

Every shim has to pop exactly what the real callee popped. Get one wrong and
the guest stack silently desynchronises; every value read after that call is
garbage and the symptom appears nowhere near the cause.

pcrecomp's `tools/pe/stdcall_argc.py` derives the count rather than taking it
from a hand-typed table. On this binary:

| evidence | imports |
|---|---:|
| Windows SDK import library (`_Name@N`) | 247 |
| C-runtime export table — cdecl, pops nothing | 170 |
| the callee's own `ret N`, read out of the DLL | **71** |
| C++ mangled convention | 1 |
| **could not be derived** | **6** |

**489 of 495.** That last-resort strategy — disassembling the export and
reading its `ret N` — was added upstream for this project, because the arcade
case defeats every strategy that reads a *name*: OKAO Vision exports by ordinal
only, and its DLLs exist nowhere but the game tree.

The six that remain are `d3dx9_43`'s math functions (`D3DXMatrixMultiply`,
`D3DXVec3Normalize`, …). Each export is a `jmp dword ptr [...]` CPU-dispatch
thunk whose slot is filled at DLL init with an SSE or an x87 implementation,
and nothing static can follow that. They do not need a purge anyway: they are
forwarded to the real d3dx9, and the real callee's own `ret` unwinds the frame.

## JVS I/O — the wheel, the pedals, the coins

The one that has to work before anything is playable.

On an original cabinet the controls are a Namco I/O board on USB, reached with
`DeviceIoControl` on a driver that is not on a desktop. Conversion trees do not
ship that driver; they ship `JVSEmuMK.dll`, which reads DirectInput and XInput
and presents the same interface — and it exports exactly one function:

```
JVSEmuMK.dll   engate      (1 export, 1 import)
  needs: DINPUT8.dll  XINPUT1_3.dll  USER32.dll  WINMM.dll  KERNEL32.dll
```

Only the `v1.06.35 OF` build imports it directly; `v1.00.32` and `v1.18.16` go
through `DeviceIoControl`, which is forwarded to the host and fails.

Either path ends in the same place: something has to produce a JVS report with
a wheel position, two analogue pedals, the item and view buttons, coin counters
and the service/test switches. **The report layout is not in this repo and has
not been measured.** Writing a plausible one is the wrong move — a wrong field
offset reads the brake as the wheel and the game is unplayable in a way that
looks like a physics bug.

## The card reader — `bngrw.dll`

22 exports, imported 11 at a time by `v1.18.16`. Imports only kernel32 and
MSVCR100, so it is a serial-protocol driver with no OS surface of its own.

Progress, licence and kart selection go to a magnetic card and come back next
session. A port needs, at minimum, an honest "no card present" — and the
interesting question, unanswered, is what the game does with that. An empty
slot is the normal state of a cabinet.

`Nbam_QR_Code.dll` (7 exports) encodes the code printed alongside. Its PDB path
says `P426_QR ... Ver1.0.2`, and it is pure computation with no hardware behind
it, which makes it the easiest of these to get right.

## The camera — OKAO Vision

Five DLLs, 40 imports on `v1.00.32`, **all by ordinal**:

| DLL | imports | what it is |
|---|---:|---|
| `eOkaoDt.dll` | 13 | face detection |
| `eOkaoPt.dll` | 10 | facial parts |
| `eOkaoAg.dll` | 8 | age estimation |
| `eOkaoGn.dll` | 8 | gender estimation |
| `eOkaoCo.dll` | 1 | common / library init |

The ordinals cluster — 2..5, 100..105, 300..316 — which is a library with an
init/destroy group, a configuration group and a per-frame group. The bodies are
readable: they are plain x86 with no OS calls, which is how the purge for all
40 was derived.

There is a camera in the cabinet roof. It photographs the player, the game puts
their face on the kart and guesses their age and sex. A port can reasonably
return "no face found" forever and the game should proceed — but that is a
belief, not a measurement, and it is the first thing to check.

## Authentication — AMCUS, Mucha, ALL.Net

`AMAuthd.exe`, `muchacd.exe`, `iauthdll.dll`, a certificate chain, and
`ipccl.dll` (a managed assembly that talks to the `ShareK` service). The game
itself reaches all of this through stock `WINHTTP` and `WS2_32`, so the
recompiled binary makes the same calls and they fail the way they failed when a
cabinet was unplugged from the network.

That is the correct first behaviour and it is free. Whether the game tolerates
it, or sits at an error screen forever, is a measurement nobody here has taken.

## What to do first

In the order the game will ask, which is the only order worth working in:

1. **Boot.** Forwarded imports only. The first `[hle]` abort names what is
   missing and which DLL it belongs to.
2. **Authentication timeout.** Let it fail; find out whether the game proceeds.
3. **JVS.** Nothing is playable until the wheel moves.
4. **Card reader.** "No card" honestly.
5. **Camera.** "No face" honestly.
6. **QR.** Last, and the least likely to block anything.
