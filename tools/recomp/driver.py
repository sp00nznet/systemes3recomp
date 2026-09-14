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
import re
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
    """{(dll, import name): argument bytes the real callee pops}, -1 if unknown.

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
        if (dll, name) in out:
            continue
        argc = r.lookup(dll, name)
        out[(dll, name)] = -1 if argc is None else argc * 4
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
        # The dict shape, with entry_kind, so a re-read can tell a function
        # start from an alias - load_catalog needs that to clamp extents
        # without truncating a function that has an alias inside it.
        with open(out_json, "w") as f:
            json.dump({"exe": os.path.basename(exe_path),
                       "image_base": info.image_base,
                       "code_start": info.code_start,
                       "code_end": info.code_end,
                       "entry": info.image_base + info.entry_point_rva,
                       "functions": [{"address": a, "size": found[a].size,
                                      "entry_kind": found[a].entry_kind}
                                     for a in sorted(funcs)],
                       "imports": [[va, dll, name]
                                   for va, (dll, name) in sorted(iat.items())]},
                      f)
    return info, funcs, iat


def load_catalog(path, code_end=None, read_va=None, code_start=None):
    """A catalog as `scan` writes it, or as pcrecomp's disasm32 CLI writes it -
    they are different shapes and both are worth accepting, because a scan
    takes half an hour and gets run once by hand with whichever tool was there.

    Extents are clamped on the way in. A catalog produced before pcrecomp
    learned to clamp them claims function bodies that run over the top of the
    next function, and the lifter reads them linearly - on this game that was
    89 MB of claimed bodies for 4.3 MB of code, lifted twenty times over. The
    clamp is idempotent, so doing it here costs nothing on a fresh catalog and
    saves re-running the scan on an old one."""
    with open(path) as f:
        doc = json.load(f)

    # Imports may be absent - pcrecomp's own disasm32 CLI does not record them
    # - and recompile() rebuilds them from the PE when they are.
    iat = {int(va): (dll, name) for va, dll, name in doc.get("imports", [])}
    code_end = code_end or doc.get("code_end")

    aliases = set()
    if doc.get("functions") and isinstance(doc["functions"][0], dict):
        funcs = {f["address"]: f["size"] for f in doc["functions"] if f["size"] > 0}
        aliases = {f["address"] for f in doc["functions"]
                   if f.get("entry_kind", "start") != "start"}
    else:
        # The older flat [[addr, size], ...] shape, which carries no
        # entry_kind - so every entry is treated as a function start.
        funcs = {int(a): int(s) for a, s in doc["functions"]}

    if code_end is None:
        code_end = max((a + s for a, s in funcs.items()), default=0)

    # Drop entries that are not instruction boundaries, and do it BEFORE the
    # clamp. An address inside an instruction decodes as a stream the program
    # never runs, lifts and compiles perfectly well, and killed a boot with a
    # `hlt` in the middle of a C++ initialiser.
    #
    # Order matters both ways round. The check has to run first because the
    # clamp is what shortened the real function onto the false start, and it
    # has to be followed by the clamp because a function cut at an entry that
    # is now gone would fall through to an address nothing lifts.
    if read_va is not None:
        gone = pcrecomp.disasm().drop_mid_instruction_entries(
            read_va, funcs, code_start if code_start is not None else 0, code_end)
        if gone:
            print("[*] %d catalog entries were inside an instruction, not at one"
                  % gone, file=sys.stderr)

    before = sum(funcs.values())
    # Only function starts may act as a limit: clamping against an alias would
    # truncate the function it sits inside. The aliases are still clamped
    # themselves - an over-extended one is as wasteful as any other, and
    # cutting it at the next start cannot shorten its host.
    pcrecomp.disasm().clamp_extents(
        funcs, code_end, starts=[a for a in funcs if a not in aliases])

    # Last, because clamping is what creates the problem it solves: a function
    # cut at a shared epilogue has branch targets in its second half that now
    # point outside its extent, and the lifter turns each of those into a
    # dispatch that nothing answers.
    if read_va is not None:
        lo = code_start if code_start is not None else 0
        added = pcrecomp.disasm().close_dispatch_targets(
            read_va, funcs, lo, code_end, aliases=aliases)
        if added:
            print("[*] %d branch targets had no dispatchable body" % added,
                  file=sys.stderr)

        # ...and check those, because a branch target can be mid-instruction
        # too: the branch is then in a function that was itself decoded out of
        # phase. `0x00768279` is the second byte of `jne 0x768273` and came
        # back this way after the first pass had correctly removed it, so the
        # game ran an `stc` that is not in the binary, 271,636 calls in.
        #
        # A target removed here leaves a dispatch nothing answers, which the
        # runtime reports by name. That is the better failure: a fabricated
        # instruction is silent.
        again = pcrecomp.disasm().drop_mid_instruction_entries(
            read_va, funcs, lo, code_end)
        if again:
            print("[*] %d of those were not instruction boundaries either"
                  % again, file=sys.stderr)
    after = sum(funcs.values())
    if after < before:
        print("[*] clamped %d bytes of overlapping function bodies to %d"
              % (before, after), file=sys.stderr)
    return funcs, iat


_DISPATCH = re.compile(r"dispatch\(c, 0x([0-9A-F]{8})u\)")


def _extent_to_next(va, funcs, code_end, cap=0x4000):
    """How far a newly discovered entry may run.

    To the next known start, because that is where some other function's body
    begins - or `cap` bytes, because an address with nothing after it for a
    megabyte is data, and lifting a megabyte of it helps nobody. The lifter
    stops at the first `ret` in any case; this only bounds what it reads.
    """
    nxt = min((a for a in funcs if a > va), default=code_end)
    return max(1, min(nxt, va + cap, code_end) - va)


def _lift_round(lifter, funcs, pending, bodies, failed):
    """Lift each address in `pending`, and return the addresses those bodies
    dispatch to that still have none."""
    reached = set()
    for va in pending:
        if va in bodies:
            continue
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
        bodies[va] = body
        reached.update(int(h, 16) for h in _DISPATCH.findall(body))
    return {a for a in reached if a not in bodies}


def recompile(exe_path, catalog_path, outdir, addrs=None, split=400,
              split_lines=250000):
    """Lift an ES3 executable to C, at most `split` functions and
    `split_lines` lines per translation unit.

    Returns (functions lifted, (dll, name) pairs for every import)."""
    pe, lift = pcrecomp.pe(), pcrecomp.lifter()
    info = pe.analyze_pe(exe_path)
    read_va = _reader(exe_path, info.image_base)
    funcs, iat = load_catalog(catalog_path, info.code_end, read_va, info.code_start)
    if not iat:                       # a catalog from pcrecomp's CLI carries none
        iat = pe.build_iat_map(info)

    lift.IMAGE_BASE = info.image_base           # read by Lifter.__init__
    lifter = lift.Lifter(exe_path, _size_of_image(exe_path), read_va)
    lifter.reloc_vas = _reloc_vas(exe_path, info.image_base)

    targets = sorted(addrs) if addrs else sorted(funcs)
    os.makedirs(outdir, exist_ok=True)
    header = ["/* AUTO-GENERATED by systemes3recomp - do not edit */",
              '#include "es3_rt.h"',
              '#include "recomp_funcs_decl.h"', ""]

    # One translation unit per `split` functions OR `split_lines` lines,
    # whichever comes first. A whole ES3 game in a single .c is millions of
    # lines, which no compiler will take in reasonable time or memory - and one
    # file per function is tens of thousands of compiler invocations. A few
    # hundred per file is the middle that builds.
    #
    # The line cap is there because function count alone is not a proxy for
    # size: on this game a 400-function chunk came out at 108 MB, because
    # function sizes span four orders of magnitude and the big ones cluster.
    # MSVC took it, slowly; a parallel build with several of those in flight is
    # what runs a machine out of memory.
    # Lift, then close what the lifted code can reach, then lift that, until
    # nothing is left open.
    #
    # close_dispatch_targets() works from the disassembly and catches most of
    # it, but it cannot see the lifter's own arithmetic - the address a
    # clamped extent falls through to, an arm of a jump table - and the
    # mid-instruction check that follows it removes some of what it added. What
    # survives is a `dispatch()` with no body, and the way you find out is the
    # runtime saying `no lifted function at 0x0075619e` after ten minutes of a
    # game running. That is a slow way to learn something the generated text
    # already knows.
    #
    # So ask the text. Every literal `dispatch(c, 0x...)` in it is an address
    # lifted code can jump to, and every one of those needs a body. An address
    # that turns out to be nonsense costs one function nobody ever calls; an
    # address that was real and missing costs the boot.
    bodies, failed = {}, []
    pending, rounds = list(targets), 0
    while pending and rounds < 8:
        rounds += 1
        opened = _lift_round(lifter, funcs, pending, bodies, failed)
        # Inside the code, or it is not an address the program can run. A
        # function recovered out of a run of data decodes `call` instructions
        # to wherever its bytes happen to point, and lifting 0x727a0f49 fails
        # on the read rather than on anything useful.
        lo = info.code_start or 0
        pending = sorted(a for a in opened if lo <= a < info.code_end)
        if pending:
            print("[*] %d address(es) lifted code reaches had no body"
                  % len(pending), file=sys.stderr)
            for va in pending:
                funcs[va] = _extent_to_next(va, funcs, info.code_end)
    if pending:
        print("[!] %d dispatch target(s) still open after %d rounds"
              % (len(pending), rounds), file=sys.stderr)

    done = sorted(bodies)

    # Turn every call whose target we lifted into a direct C call.
    #
    # The lifter cannot do this itself: when it emits `call 0x41eaa0` it does
    # not yet know whether 0x0041EAA0 will end up in the output. The driver
    # does, because this IS the output - so the substitution happens here,
    # after the closure loop above has settled and `bodies` is final.
    #
    # It is the difference between a name and a search. `dispatch(c, 0xVA)`
    # checks the import-sentinel range, checks whether the address is a thunk,
    # looks the VA up in a table of thirty-one thousand entries and calls
    # through a pointer. `L_004xxxxx(c)` is a call. Measured on Mario Kart the
    # game was spending most of its life in the first one: `0041EAA0` is
    # `fabsf`, two instructions, and one sampled window had it called
    # ninety-seven thousand times at about four hundred nanoseconds each.
    #
    # Indirect calls are untouched. `dispatch(c, _ct)` from a vtable slot or a
    # task table still goes the long way round, which is what dispatch() is
    # for.
    counted = [0]

    def _direct(m):
        va = int(m.group(1), 16)
        if va not in bodies:
            return m.group(0)
        counted[0] += 1
        return "DCALL(0x%08Xu, L_%08X)" % (va, va)

    for va in done:
        bodies[va] = _DISPATCH.sub(_direct, bodies[va])
    print("[*] %d direct calls go straight to their function" % counted[0],
          file=sys.stderr)

    with open(os.path.join(outdir, "recomp_funcs_decl.h"), "w") as f:
        f.write("/* AUTO-GENERATED by systemes3recomp - every lifted function,\n"
                "   declared so that a direct call can be a direct call. */\n")
        f.write("".join("void L_%08X(CPU *c);\n" % a for a in done))

    chunks, cur = [], list(header)
    cur_funcs = cur_lines = 0
    for va in done:
        body = bodies[va]
        cur.append(body)
        cur.append("")
        cur_funcs += 1
        cur_lines += body.count("\n") + 2
        if (split and cur_funcs >= split) or \
                (split_lines and cur_lines >= split_lines):
            chunks.append(cur)
            cur = list(header)
            cur_funcs = cur_lines = 0
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
    return done, sorted(set(iat.values()))


def emit_headers(outdir, done, iat, purge=None):
    """The three generated headers the runtime compiles against."""
    purge = purge or {}
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "recomp_funcs_list.h"), "w") as f:
        f.write("/* AUTO-GENERATED by systemes3recomp */\n"
                "#define LIFTED_FUNCS(X) \\\n")
        f.write(" \\\n".join("    X(%08X)" % a for a in done) + "\n")

    # An import's identity is (DLL, name), not the name.
    #
    # That is not pedantry, it is the OKAO Vision camera. Those libraries export
    # by ordinal only, so pefile names their imports `ordinal_2`, `ordinal_5`,
    # `ordinal_101` - and eOkaoDt, eOkaoAg and eOkaoGn each export a DIFFERENT
    # function under each of those. Keying on the name alone collapsed 40 board
    # imports into 27 and silently routed face detection's calls into age
    # estimation. Found by running it; nothing about the generated C looks
    # wrong.
    #
    # Order is sorted and stable because the sentinel an IAT slot gets is this
    # list's index, and both headers have to agree on it.
    pairs = sorted({(dll, n) for dll, n in iat.values()})

    # The enumerator is still HLE_CreateFileW where that is unambiguous - it is
    # what a handler file writes and what an abort message prints. Only a name
    # that appears under more than one DLL takes the DLL's stem as a prefix.
    dup = {n for n in (p[1] for p in pairs)
           if sum(1 for q in pairs if q[1] == n) > 1}

    def enum_of(dll, name):
        if name in dup:
            return "HLE_%s_%s" % (ident(os.path.splitext(dll)[0]), ident(name))
        return "HLE_%s" % ident(name)

    with open(os.path.join(outdir, "recomp_imports.h"), "w") as f:
        f.write("/* AUTO-GENERATED by systemes3recomp - every import in the PE.\n"
                "   Fields: id, name, DLL, argument bytes the real callee pops\n"
                "   (-1 = could not be derived - see purge_table in driver.py).\n"
                "   One row per (DLL, name): two DLLs can export different\n"
                "   functions under the same name, which is the normal case for\n"
                "   the ordinal-only board libraries.\n"
                "   The runtime provides a body for each; unimplemented ones abort\n"
                "   with their own name, which is how you find what to write next. */\n"
                "#define HLE_IMPORTS(X) \\\n")
        f.write(" \\\n".join('    X(%s, "%s", "%s", %d)'
                             % (enum_of(dll, n), n, dll, purge.get((dll, n), -1))
                             for dll, n in pairs) + "\n")

    # Slot VA -> import id. guest_load() walks this after mapping the image and
    # writes HLE_BASE + 4*id into each slot, which is what turns the game's
    # `call [__imp_CreateFileW]` into a call the runtime can answer. One row per
    # slot and not per name: the same name can occupy several slots when the
    # linker emitted more than one, and every one of them has to be patched.
    idx = {p: i for i, p in enumerate(pairs)}
    with open(os.path.join(outdir, "recomp_iat.h"), "w") as f:
        f.write("/* AUTO-GENERATED by systemes3recomp - IAT slot -> import id. */\n"
                "#define IAT_SLOTS(X) \\\n")
        f.write(" \\\n".join("    X(0x%08Xu, %d)" % (va, idx[(dll, n)])
                             for va, (dll, n) in sorted(iat.items())) + "\n")


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
