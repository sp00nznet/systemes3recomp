#!/usr/bin/env python3
"""
driver.py - the ES3 end of the pipeline.

Everything hard here is pcrecomp's: `analyze_pe` reads the PE, `disasm32`
recovers the functions (an ES3 binary is stripped, so recursive descent is
where the function list comes from), `lift32_cpu` turns x86 into C. This file
is the wiring, plus the one thing an arcade PE needs that the shared toolbox
has no opinion about.

**There is no lifter subclass here, and that is deliberate.** Lindbergh needed
one because a Linux ELF reaches its libraries through PLT stubs, which the
lifter cannot see through. A PE reaches them through the IAT - an indirect
call through a data slot - and the lifter already emits exactly the right
thing for that: `_ct = rd32(GVA(0x0081D068)); dispatch(c, _ct)`. So the import
boundary is drawn at load time instead: guest.c writes a sentinel address into
every IAT slot and dispatch() routes that range to hle_call().

Drawing it there rather than in the lifter is not just less code. It catches
every way an import can be reached, not only `call [__imp_X]`:

  * the one-line thunks MSVC emits (`jmp [__imp_X]`), which are tail calls
  * a function pointer copied out of the IAT and called later - the CRT does
    this, and so does every GetProcAddress result stored in a struct
  * D3D and the OKAO libraries hand back vtables whose slots the game calls
    indirectly forever after

A lifter-side pattern match sees the first of those and misses the rest.

Usage:
  py -3.11 -m tools scan   <game.exe> <catalog.json>
  py -3.11 -m tools recomp <game.exe> <catalog.json> <outdir>
"""

import json
import os
import sys

from .. import pcrecomp

# Where the sentinel import addresses live. Chosen to sit outside any plausible
# ES3 image (they load at 0x00400000 and the largest we have is ~16 MB) and
# outside the heap, so a sentinel arriving at dispatch() can only have come out
# of an IAT slot. src/runtime/es3_rt.h has the matching definition and the
# selftest checks the two agree.
HLE_BASE = 0xE5300000
HLE_STRIDE = 4


def ident(name):
    return "".join(ch if ch.isalnum() else "_" for ch in name)


def purge_table(exe_path, iat):
    """{import name: argument bytes the real callee pops}, -1 where unknown.

    pcrecomp's tools/pe/stdcall_argc.py does the deriving, and it is given the
    directory the executable came from: an ES3 game tree ships the DLLs that
    exist nowhere else, and for an ordinal-only import like OKAO Vision's,
    reading the count out of the DLL's own `ret N` is the only way to get it.

    -1 rather than a guess. hle_call() refuses to call an import with an
    underivable purge unless the handler unwinds for itself, because a wrong
    purge desynchronises the guest stack and the symptom shows up nowhere near
    the cause."""
    argc_mod = pcrecomp.argc()
    r = argc_mod.ArgcResolver(dll_dirs=[os.path.dirname(os.path.abspath(exe_path))])
    out = {}
    for _, (dll, name) in sorted(iat.items()):
        if name in out:
            continue
        argc = r.lookup(dll, name)
        out[name] = -1 if argc is None else argc * 4
    return out


def scan(exe_path, out_json=None):
    """Recover the function catalog from a stripped ES3 executable.

    Slow - tens of minutes on a multi-megabyte .text - and its result is the
    input to every later step, so it is written out and reused rather than
    recomputed. Returns (PEInfo, {addr: size}, {iat_va: (dll, name)})."""
    pe, dis = pcrecomp.pe(), pcrecomp.disasm()
    info = pe.analyze_pe(exe_path)
    iat = pe.build_iat_map(info)
    with open(exe_path, "rb") as f:
        data = f.read()

    seeds = {info.image_base + info.entry_point_rva} if info.entry_point_rva else set()
    d = dis.Disassembler(data, info.image_base, info.sections)
    found = d.find_functions(info.code_start, info.code_end, iat,
                             seeds=seeds, release_operands=True)
    funcs = {f.address: f.size for f in found.values() if f.size > 0}

    if out_json:
        with open(out_json, "w") as f:
            json.dump({"exe": os.path.basename(exe_path),
                       "image_base": info.image_base,
                       "entry": info.image_base + info.entry_point_rva,
                       "functions": [[a, s] for a, s in sorted(funcs.items())],
                       "imports": [[va, dll, name]
                                   for va, (dll, name) in sorted(iat.items())]},
                      f)
    return info, funcs, iat


def load_catalog(path):
    """A catalog as `scan` writes it, or as pcrecomp's disasm32 CLI writes it -
    they are different shapes and both are worth accepting, because a long scan
    is usually run once by hand with whichever tool was to hand."""
    with open(path) as f:
        doc = json.load(f)
    if "functions" in doc and doc["functions"] and isinstance(doc["functions"][0], dict):
        funcs = {f["address"]: f["size"] for f in doc["functions"] if f["size"] > 0}
        return funcs, {}
    funcs = {int(a): int(s) for a, s in doc["functions"]}
    iat = {int(va): (dll, name) for va, dll, name in doc.get("imports", [])}
    return funcs, iat


def recompile(exe_path, catalog_path, outdir, addrs=None, split=400):
    """Lift an ES3 executable to C, `split` functions per translation unit.

    Returns (functions lifted, import names referenced)."""
    pe, lift = pcrecomp.pe(), pcrecomp.lifter()
    info = pe.analyze_pe(exe_path)
    funcs, iat = load_catalog(catalog_path)
    if not iat:                       # a catalog from pcrecomp's CLI carries none
        iat = pe.build_iat_map(info)

    lift.IMAGE_BASE = info.image_base           # read by Lifter.__init__
    lifter = lift.Lifter(exe_path, _size_of_image(exe_path),
                         _reader(exe_path, info.image_base))
    lifter.reloc_vas = _reloc_vas(exe_path, info.image_base)

    targets = sorted(addrs) if addrs else sorted(funcs)
    os.makedirs(outdir, exist_ok=True)
    header = ["/* AUTO-GENERATED by systemes3recomp - do not edit */",
              '#include "es3_rt.h"', ""]

    # One translation unit per `split` functions. A whole ES3 game in a single
    # .c is millions of lines, which no compiler will take in reasonable time
    # or memory - and one file per function is tens of thousands of compiler
    # invocations. A few hundred per file is the middle that builds.
    chunks, cur, done, failed = [], list(header), [], []
    for va in targets:
        size = funcs.get(va, 0)
        if not size:
            print("[!] no size for %#x, skipped" % va, file=sys.stderr)
            continue
        try:
            body = lifter.lift_function(lifter.read_va(va, size), va)
        except Exception as exc:
            # One instruction the lifter cannot express must not cost the other
            # 28,000 functions. The catalog is recovered by descent on a
            # stripped binary, so some of its entries are data that decodes as
            # something impossible - and a function that genuinely needs an
            # instruction we do not have should abort when the game calls it,
            # not when the game is built.
            failed.append((va, exc))
            body = ("/* FAILED TO LIFT: %s */\nvoid L_%08X(CPU *c)\n{\n"
                    "    (void)c; abort();\n}" % (str(exc).replace("*/", "* /"), va))
        cur.append(body)
        cur.append("")
        done.append(va)
        if split and len(done) % split == 0:
            chunks.append(cur)
            cur = list(header)
    if len(cur) > len(header):
        chunks.append(cur)

    for i, chunk in enumerate(chunks):
        with open(os.path.join(outdir, "recomp_funcs_%04d.c" % i), "w") as f:
            f.write("\n".join(chunk))

    emit_headers(outdir, done, iat, purge_table(exe_path, iat))
    print("[*] %d functions in %d translation units, %d imports"
          % (len(done), len(chunks), len(iat)), file=sys.stderr)
    if failed:
        print("[!] %d function(s) failed to lift and abort if called:"
              % len(failed), file=sys.stderr)
        for va, exc in failed[:20]:
            print("      %#010x  %s" % (va, exc), file=sys.stderr)
        if len(failed) > 20:
            print("      ... and %d more" % (len(failed) - 20), file=sys.stderr)
    return done, sorted({n for _, n in iat.values()})


def emit_headers(outdir, done, iat, purge=None):
    """The three generated headers the runtime compiles against."""
    purge = purge or {}
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "recomp_funcs_list.h"), "w") as f:
        f.write("/* AUTO-GENERATED by systemes3recomp */\n"
                "#define LIFTED_FUNCS(X) \\\n")
        f.write(" \\\n".join("    X(%08X)" % a for a in done) + "\n")

    # Every import name once, in a stable order - the sentinel an IAT slot gets
    # is its index in this list, so the order must be the same in both headers
    # and must not depend on dict iteration.
    names = sorted({n for _, n in iat.values()})
    dll_of = {}
    for _, (dll, n) in sorted(iat.items()):
        dll_of.setdefault(n, dll)

    with open(os.path.join(outdir, "recomp_imports.h"), "w") as f:
        f.write("/* AUTO-GENERATED by systemes3recomp - every import in the PE.\n"
                "   Fields: id, name, DLL, argument bytes the real callee pops\n"
                "   (-1 = could not be derived - see purge_table in driver.py).\n"
                "   The runtime provides a body for each; unimplemented ones abort\n"
                "   with their own name, which is how you find what to write next. */\n"
                "#define HLE_IMPORTS(X) \\\n")
        f.write(" \\\n".join('    X(HLE_%s, "%s", "%s", %d)'
                             % (ident(n), n, dll_of[n], purge.get(n, -1))
                             for n in names) + "\n")

    # Slot VA -> import id. guest_load() walks this after mapping the image and
    # writes HLE_BASE + 4*id into each slot, which is what turns the game's
    # `call [__imp_CreateFileW]` into a call the runtime can answer. One row per
    # slot and not per name: the same name can occupy several slots when the
    # linker emitted more than one, and every one of them has to be patched.
    idx = {n: i for i, n in enumerate(names)}
    with open(os.path.join(outdir, "recomp_iat.h"), "w") as f:
        f.write("/* AUTO-GENERATED by systemes3recomp - IAT slot -> import id. */\n"
                "#define IAT_SLOTS(X) \\\n")
        f.write(" \\\n".join("    X(0x%08Xu, %d)" % (va, idx[n])
                             for va, (_, n) in sorted(iat.items())) + "\n")


# ---- PE reading. pefile is already a pcrecomp dependency; these are the same
#      calls its lifter's own main() makes, without going through its CLI. ----

def _pefile(exe_path):
    import pefile
    return pefile.PE(exe_path, fast_load=True)


def _size_of_image(exe_path):
    return _pefile(exe_path).OPTIONAL_HEADER.SizeOfImage


def _reader(exe_path, image_base):
    pe = _pefile(exe_path)

    def read_va(va, n):
        return pe.get_data(va - image_base, n)
    return read_va


def _reloc_vas(exe_path, image_base):
    """VAs of the 32-bit absolute addresses the loader would fix up. The lifter
    uses these to tell `mov eax, [0x58d428]` (an address) from `mov eax,
    [ecx+8]` (an offset); without them the output is wrong at any load base,
    and an ES3 image is full of absolute table references."""
    import pefile
    pe = _pefile(exe_path)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']])
    out = set()
    for br in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []):
        for e in br.entries:
            if e.type == 3:                       # IMAGE_REL_BASED_HIGHLOW
                out.add((image_base + e.rva) & 0xffffffff)
    return out
