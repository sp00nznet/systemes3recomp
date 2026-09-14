#!/usr/bin/env python3
"""systemes3recomp command line.

  py -3.11 -m tools pe     <game.exe>                       what the PE says it needs
  py -3.11 -m tools scan   <game.exe> <catalog.json>        recover the functions
  py -3.11 -m tools recomp <game.exe> <catalog.json> <out>  lift it to C
  py -3.11 -m tools trail  [es3_trail.bin] [game.exe]      read the last run

`scan` is the slow step - an ES3 binary is stripped, so its function list has
to be recovered by recursive descent rather than read out of a symbol table.
It writes a catalog you keep and reuse; `recomp` is minutes, not hours.
"""

import argparse
import collections
import json
import sys

from . import pcrecomp


def cmd_pe(a):
    pe = pcrecomp.pe()
    info = pe.analyze_pe(a.exe)
    print("format     %s %s" % (info.pe_type, info.machine))
    print("image      %#010x .. %#010x" % (info.image_base, info.code_end))
    print("entry      %#010x" % (info.image_base + info.entry_point_rva))
    print("code       %#010x + %#x" % (info.code_start, info.code_end - info.code_start))
    print("linker     MSVC %s   built %s" % (info.linker_version, info.timestamp_str))
    print("sections   %s" % " ".join(s.name for s in info.sections))

    by_dll = collections.Counter()
    for imp in info.imports:
        by_dll[imp.dll] += 1
    print("imports    %d functions from %d DLLs" % (len(info.imports), len(by_dll)))
    for dll, n in sorted(by_dll.items(), key=lambda kv: (-kv[1], kv[0])):
        print("  needs    %-20s %3d%s" % (dll, n, _note(dll)))


# The DLLs that are not stock Windows. These are the board, and between them
# they are the whole reason this toolkit exists rather than being one more
# pcrecomp game directory. Keep in step with docs/board-io.md.
BOARD_DLLS = {
    "jvsemumk.dll":     "JVS I/O - coins, wheel, pedals, buttons",
    "bngrw.dll":        "Bandai Namco card reader/writer",
    "nbam_qr_code.dll": "QR code encoder for the player's card",
    "eokaoag.dll":      "OMRON OKAO Vision - age estimation",
    "eokaoco.dll":      "OMRON OKAO Vision - common",
    "eokaodt.dll":      "OMRON OKAO Vision - face detection",
    "eokaogn.dll":      "OMRON OKAO Vision - gender estimation",
    "eokaopt.dll":      "OMRON OKAO Vision - facial parts",
    "eokaosm.dll":      "OMRON OKAO Vision - smile estimation",
    "ipccl.dll":        "IPC client (managed) - talks to the ShareK service",
}


def _note(dll):
    n = BOARD_DLLS.get(dll.lower())
    return "   <- %s" % n if n else ""


def cmd_scan(a):
    # Half an hour of progress, and redirected to a file it is block-buffered:
    # nothing appears until the run ends, and if it dies the buffer dies with
    # it and the log is zero bytes. pcrecomp's own CLI does this for the same
    # reason; going through the library rather than that CLI skipped it.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, OSError):
        pass
    from .recomp.driver import scan
    info, funcs, iat = scan(a.exe, a.catalog)
    code = info.code_end - info.code_start
    covered = sum(funcs.values())
    print("functions  %d recovered" % len(funcs))
    print("bytes      %d of %d code bytes claimed (%.1f%%)"
          % (covered, code, 100.0 * covered / code if code else 0.0))
    print("imports    %d IAT slots" % len(iat))
    print("catalog    %s" % a.catalog)


def cmd_recomp(a):
    from .recomp.driver import recompile
    addrs = [int(x, 16) for x in a.addrs] or None
    done, imports = recompile(a.exe, a.catalog, a.outdir, addrs)
    print("lifted %d functions, %d distinct imports -> %s"
          % (len(done), len(imports), a.outdir))


def cmd_trail(a):
    """The dispatch ring the runtime leaves behind.

    It is a memory-mapped file because the interesting deaths are the ones no
    handler sees: a forwarded CRT that gives up calls __fastfail, which is not
    an exception, and the process is simply gone with nothing printed. The ring
    is still on disk afterwards."""
    import struct

    raw = open(a.trail, "rb").read()
    if len(raw) < 8:
        sys.exit("%s is too short to be a trail" % a.trail)
    from .recomp.driver import HLE_BASE, HLE_STRIDE

    words = struct.unpack("<%dI" % (len(raw) // 4), raw[:len(raw) // 4 * 4])
    total, stride, body = words[0], (words[1] or 1), words[2:]
    n = len(body) // stride
    print("%d dispatches, last %d kept" % (total, min(total, n)))

    if stride == 2 and not a.thread:
        seen = {}
        for i in range(max(0, total - n), total):
            seen[body[stride * (i % n)]] = seen.get(body[stride * (i % n)], 0) + 1
        print("threads in the window: " +
              ", ".join("t%u(%d)" % (t, c)
                        for t, c in sorted(seen.items(), key=lambda kv: -kv[1])))

    # An import sentinel encodes an index into the sorted (DLL, name) list,
    # which is the order emit_headers() numbers them in. Rebuild it from the
    # executable rather than from a catalog: it is the authority either way,
    # and a catalog produced by pcrecomp's own CLI carries no imports at all.
    imports = []
    if a.exe:
        pe = pcrecomp.pe()
        imports = sorted(set(pe.build_iat_map(pe.analyze_pe(a.exe)).values()))

    for i in range(max(0, total - n), total):
        tid = body[stride * (i % n)] if stride == 2 else 0
        va = body[stride * (i % n) + (stride - 1)]
        if a.thread and tid != a.thread:
            continue
        who = ""
        if HLE_BASE <= va < HLE_BASE + HLE_STRIDE * max(len(imports), 1):
            k = (va - HLE_BASE) // HLE_STRIDE
            who = ("import %s (%s)" % (imports[k][1], imports[k][0])
                   if k < len(imports) else "import #%d" % k)
        print("  %6d  t%-6u %08X  %s" % (i, tid, va, who))


def main(argv=None):
    p = argparse.ArgumentParser(prog="tools", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("pe", help="report on a game executable")
    e.add_argument("exe")
    e.set_defaults(fn=cmd_pe)

    s = sub.add_parser("scan", help="recover the function catalog (slow)")
    s.add_argument("exe")
    s.add_argument("catalog", help="write the catalog here")
    s.set_defaults(fn=cmd_scan)

    r = sub.add_parser("recomp", help="lift a game executable to C")
    r.add_argument("exe")
    r.add_argument("catalog")
    r.add_argument("outdir")
    r.add_argument("addrs", nargs="*", help="lift only these (hex); default all")
    r.set_defaults(fn=cmd_recomp)

    t = sub.add_parser("trail", help="read the dispatch ring from the last run")
    t.add_argument("trail", nargs="?", default="es3_trail.bin")
    t.add_argument("exe", nargs="?", help="name the imports from the game exe")
    t.add_argument("--thread", type=int, default=0,
                   help="show only this thread - a worker pool buries everything else")
    t.set_defaults(fn=cmd_trail)

    a = p.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
