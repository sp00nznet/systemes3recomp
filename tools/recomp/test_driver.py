#!/usr/bin/env python3
"""
test_driver.py - checks for the parts of the driver that are not pcrecomp's.

  py -3.11 tools/recomp/test_driver.py

Everything the lifter and the disassembler do is checked upstream. What is
checked here is the wiring this project adds, and in particular the two things
that would be silently wrong rather than loudly broken:

  * the sentinel constant, which is duplicated between this Python and
    src/runtime/es3_rt.h and has to stay identical - the C selftest pins the
    arithmetic, and this pins the value
  * the generated headers, whose field order the runtime's X-macros depend on,
    and whose import ordering has to be stable because an IAT slot's sentinel
    is an index into it
"""

import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from tools.recomp import driver          # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

fails = []


def check(cond, what):
    if not cond:
        fails.append(what)


def test_sentinel_matches_c():
    """The one constant that lives in two languages."""
    hdr = open(os.path.join(ROOT, "src", "runtime", "es3_rt.h")).read()
    m = re.search(r"#define HLE_BASE\s+0x([0-9A-Fa-f]+)u", hdr)
    check(m is not None, "es3_rt.h has no HLE_BASE")
    if m:
        check(int(m.group(1), 16) == driver.HLE_BASE,
              "HLE_BASE differs: es3_rt.h says %s, driver.py says %#x"
              % (m.group(1), driver.HLE_BASE))
    m = re.search(r"#define HLE_STRIDE\s+(\d+)u", hdr)
    check(m and int(m.group(1)) == driver.HLE_STRIDE, "HLE_STRIDE differs")

    # And it has to be somewhere an ES3 image and its heap are not. The
    # largest title we have maps 0x00400000 + ~0x1000000.
    check(driver.HLE_BASE > 0x02000000,
          "HLE_BASE is low enough to collide with a mapped image")


def test_ident():
    """An import name becomes a C identifier. C++ mangled names are full of
    characters that are not, and MSVCR100 imports 9 of them."""
    check(driver.ident("CreateFileW") == "CreateFileW", "plain name mangled")
    check(driver.ident("ordinal_302") == "ordinal_302", "ordinal name mangled")
    check(driver.ident("??1bad_cast@std@@UAE@XZ") ==
          "__1bad_cast_std__UAE_XZ", "mangled name not made an identifier")
    check("@" not in driver.ident("_AIL_waveOutOpen@16"), "@ survived")


def test_emit_headers():
    iat = {
        0x0081D000: ("KERNEL32.dll", "Sleep"),
        0x0081D004: ("MSVCR100.dll", "memcpy"),
        0x0081D008: ("eOkaoDt.dll", "ordinal_302"),
        # The same name in two slots: MSVC does emit this, and every slot has
        # to be patched or the second one calls into the unmapped IAT.
        0x0081D00C: ("KERNEL32.dll", "Sleep"),
        # And the same name in two DIFFERENT DLLs, which is not the same thing
        # at all. The OKAO Vision libraries export by ordinal only, so these
        # are two unrelated functions that share a number. Collapsing them
        # routed face detection's calls into gender estimation.
        0x0081D010: ("eOkaoGn.dll", "ordinal_302"),
    }
    purge = {("KERNEL32.dll", "Sleep"): 4, ("MSVCR100.dll", "memcpy"): 0,
             ("eOkaoDt.dll", "ordinal_302"): 8, ("eOkaoGn.dll", "ordinal_302"): 12}
    with tempfile.TemporaryDirectory() as d:
        driver.emit_headers(d, [0x401000, 0x401200], iat, purge)
        imports = open(os.path.join(d, "recomp_imports.h")).read()
        slots = open(os.path.join(d, "recomp_iat.h")).read()
        funcs = open(os.path.join(d, "recomp_funcs_list.h")).read()

    # Four fields, in the order the runtime's X-macros unpack them.
    check('X(HLE_Sleep, "Sleep", "KERNEL32.dll", 4)' in imports,
          "stdcall import row wrong: " + imports)
    check('X(HLE_memcpy, "memcpy", "MSVCR100.dll", 0)' in imports,
          "cdecl import row wrong")

    # An ambiguous name takes its DLL's stem as a prefix; an unambiguous one
    # must NOT, because HLE_Sleep is what a handler file writes.
    check('X(HLE_eOkaoDt_ordinal_302, "ordinal_302", "eOkaoDt.dll", 8)' in imports,
          "ordinal import row wrong: " + imports)
    check('X(HLE_eOkaoGn_ordinal_302, "ordinal_302", "eOkaoGn.dll", 12)' in imports,
          "the second DLL's ordinal was dropped or merged")
    check("X(HLE_ordinal_302," not in imports, "ambiguous name left unqualified")

    # One row per (DLL, NAME) - four from five slots, not three.
    check(imports.count("X(HLE_") == 4, "imports deduplicated wrongly: " + imports)

    # ...but one row per SLOT there, and the two Sleep slots share an id while
    # the two ordinal_302 slots do not.
    check(slots.count("X(0x") == 5, "a slot was dropped: " + slots)
    ids = dict(re.findall(r"X\(0x([0-9A-F]+)u, (\d+)\)", slots))
    check(ids.get("0081D000") == ids.get("0081D00C"),
          "the same import got two different ids")
    check(ids.get("0081D008") != ids.get("0081D010"),
          "two different DLLs' ordinal_302 got the same id")

    # The id is an index into the import list, so the list must be sorted and
    # the ids must agree with that order.
    rows = re.findall(r'X\(\w+, "([^"]+)", "([^"]+)"', imports)
    pairs = [(dll, name) for name, dll in rows]
    check(pairs == sorted(pairs), "import order is not stable: %r" % (pairs,))
    check(int(ids["0081D004"]) == pairs.index(("MSVCR100.dll", "memcpy")),
          "slot id does not index the import list")

    check("X(00401000)" in funcs and "X(00401200)" in funcs, "function list wrong")


def test_purge_unknown_is_minus_one():
    """An underivable purge must be -1 and never 0. Zero is a real answer -
    cdecl pops nothing - so a placeholder that looks like one is the exact
    failure mode this is written to prevent."""
    with tempfile.TemporaryDirectory() as d:
        driver.emit_headers(d, [0x401000],
                            {0x1000: ("d3dx9_43.dll", "D3DXMatrixMultiply")},
                            {})
        imports = open(os.path.join(d, "recomp_imports.h")).read()
    check('"d3dx9_43.dll", -1)' in imports, "unknown purge is not -1: " + imports)


def test_load_catalog_both_shapes():
    """A long scan gets run once, by hand, with whichever tool was to hand -
    so a catalog from pcrecomp's own disasm32 CLI has to load too."""
    with tempfile.TemporaryDirectory() as d:
        ours = os.path.join(d, "ours.json")
        with open(ours, "w") as f:
            json.dump({"functions": [[0x401000, 32], [0x401100, 64]],
                       "imports": [[0x81D000, "KERNEL32.dll", "Sleep"]]}, f)
        funcs, iat = driver.load_catalog(ours)
        check(funcs == {0x401000: 32, 0x401100: 64}, "our catalog misread")
        check(iat == {0x81D000: ("KERNEL32.dll", "Sleep")}, "our imports misread")

        theirs = os.path.join(d, "theirs.json")
        with open(theirs, "w") as f:
            json.dump({"code_end": 0x402000, "functions": [
                {"address": 0x401000, "size": 32, "name": ""},
                {"address": 0x401100, "size": 0, "name": ""},   # size 0: unusable
            ]}, f)
        funcs, iat = driver.load_catalog(theirs)
        check(funcs == {0x401000: 32}, "pcrecomp catalog misread: %r" % (funcs,))
        check(iat == {}, "pcrecomp catalog invented imports")


def test_load_catalog_clamps():
    """An old catalog whose extents run over the next function must be clamped
    on the way in, or the lifter reads 89 MB of bodies out of a 4 MB image."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "over.json")
        with open(p, "w") as f:
            json.dump({"code_end": 0x410000, "functions": [
                # runs straight over the two after it
                {"address": 0x401000, "size": 0x8000, "entry_kind": "start"},
                {"address": 0x401200, "size": 0x100,  "entry_kind": "start"},
                # an alias inside 0x401200 - overlaps on purpose, must survive
                {"address": 0x401250, "size": 0x30,   "entry_kind": "alias"},
            ]}, f)
        funcs, _ = driver.load_catalog(p)
    check(funcs.get(0x401000) == 0x200,
          "over-extended function not clamped: %r" % (funcs,))
    check(funcs.get(0x401200) == 0x100, "an honest extent was changed")
    check(funcs.get(0x401250) == 0x30, "an alias was clamped away")


def main():
    for fn in (test_sentinel_matches_c, test_ident, test_emit_headers,
               test_purge_unknown_is_minus_one, test_load_catalog_both_shapes,
               test_load_catalog_clamps):
        fn()
    for f in fails:
        print("FAIL " + f, file=sys.stderr)
    if fails:
        print("%d check(s) failed" % len(fails), file=sys.stderr)
        return 1
    print("ok: sentinel constant, identifiers, generated headers, "
          "catalog shapes, extent clamping")
    return 0


if __name__ == "__main__":
    sys.exit(main())
