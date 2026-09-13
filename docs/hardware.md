# What a System ES3 is

A PC in an arcade cabinet. That is not a figure of speech and it is the whole
reason this project is small.

Namco's System ES1 (2009) was the first of the line and System ES3 (2013) is
the one that matters here: a commodity Intel desktop board, a commodity NVIDIA
card, and Windows. Not a variant of Windows, not a cut-down embedded kernel
with a custom HAL — Windows Embedded Standard, running a Win32 application that
a Visual Studio 2010 toolchain built.

Everything below is read off the binaries in this repo's target trees rather
than from a datasheet, because the binaries are what the recompiler has to
agree with.

## What the executable says

```
$ py -3.11 -m tools pe MK_AGP3_FINAL_v1.00.32.exe
format     PE32 i386
image      0x00400000 .. 0x0081cd7c
entry      0x007cb996
code       0x00401000 + 0x41bd7c
linker     MSVC 10.00   built 2013-04-23 12:10:51 UTC
sections   .text .rdata .data .rsrc .reloc
imports    495 functions from 27 DLLs
```

| | |
|---|---|
| CPU | x86-32. A PE32 with machine `0x014C`, and every ES3 title is one. |
| Image base | `0x00400000`, and `DllCharacteristics` does not set `DYNAMIC_BASE`. The cabinet ran with ASLR off, so the image loads where it was linked and nothing relocates. |
| Toolchain | Microsoft Visual C++ 2010 — linker 10.00, and `MSVCR100.dll` in the import table of every build. |
| Graphics | **Both** Direct3D 9 and Direct3D 10, plus `d3dx9_43` and `d3dx10_43`. Not one or the other: the same binary imports from both, and picks at run time. |
| Video | Media Foundation (`MF`, `MFPlat`, `MFReadWrite`) for the attract-mode movies. |
| Input | DirectInput 8 for the test menu; the cabinet controls arrive over JVS, not DirectInput. |
| Network | `WS2_32` and `WINHTTP`, talking to Namco's ALL.Net/Mucha authentication. |
| Subsystem | Windows GUI. It is an ordinary desktop application that happens to run full-screen forever. |

The PDB path survives in the debug directory of every build, which is a
pleasant thing to find and says something about how these were made:

```
v1.00.32   D:\work\MK3\repos\branches\Master_1st\Bin\Final\MK_AGP3_FINAL.pdb
v1.18.16   F:\workspace\rom\branches\jpn\update8\Bin\Final\MK_AGP3_FINAL.pdb
v1.06.35   G:\global_rom\branches\global\Update3_BNA1Lite\Project\Bin\Final\...
```

The PDBs themselves are not shipped. Only the paths are, so there are no
symbols to recover from them — see "the binary is stripped" in the README.

## What is not a PC

Four things, and they are the entire job of a port:

**JVS I/O.** The coin mechanism, the start button, the steering wheel, the
pedals, the item button, the view button, the service and test switches. On a
real cabinet these are a Namco I/O board on USB, reached through
`DeviceIoControl` on a driver that does not exist on a desktop. Every
conversion tree replaces it with a `JVSEmu*.dll` that reads DirectInput and
XInput instead, which is a considerably better place to start from than the
original.

**The card reader.** `bngrw.dll` — Bandai Namco Common Read/Write. The game
writes a player's progress, licence and kart to a magnetic card and reads it
back next session. `Nbam_QR_Code.dll` encodes the QR code printed alongside it.

**The camera.** `eOkaoCo` / `eOkaoDt` / `eOkaoPt` / `eOkaoAg` / `eOkaoGn` —
OMRON's OKAO Vision SDK: common, detection, parts, age, gender. There is a
camera in the cabinet roof, it photographs the player, and the game puts their
face on their kart and guesses how old they are. These DLLs are imported
**entirely by ordinal**, they are documented nowhere, and they exist nowhere
but in a game tree.

**Authentication.** AMCUS, `AMAuthd.exe`, `muchacd.exe`, and a certificate
chain to servers that no longer answer. The imports it uses are stock Windows,
so the recompiled game reaches them like any other call and fails the way an
unplugged cabinet failed.

See [board-io.md](board-io.md) for what each of those has to be given.

## Why this is a good recompilation target

There is no CPU to model: the host is the same x86-32 it was. There is no GPU
to emulate: Direct3D 9 and 10 still exist and the host has them. There is no
operating system to reimplement: `CreateFileW` is `CreateFileW`.

What is left is the code, which is what a static recompiler is for — and four
pieces of arcade hardware, which is the honest remainder.
