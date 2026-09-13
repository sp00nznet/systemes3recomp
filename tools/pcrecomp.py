#!/usr/bin/env python3
"""
pcrecomp.py - load the shared PC toolbox out of the submodule.

Everything this project does to a PE - parse it, find its functions, turn its
x86 into C - is pcrecomp's work, vendored at ./pcrecomp as a git submodule.
There is no ES3 fork of any of it and there should never be one: a fix to `adc`
belongs to every PC-era target at once. What systemes3recomp adds sits on top
of the lifted code, not inside the lifter.

pcrecomp's tools are scripts rather than an installed package, and they import
each other by sibling name, so this puts their directories on sys.path once and
hands back modules instead of every caller doing its own path surgery.
"""

import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PCRECOMP = os.path.join(ROOT, "pcrecomp")

_MISSING = ("pcrecomp submodule is missing (expected %s).\n"
            "  git submodule update --init --recursive")


def _load(rel, name):
    path = os.path.join(PCRECOMP, *rel)
    if not os.path.exists(path):
        raise SystemExit(_MISSING % path)
    # pe_analyze and disasm32 import each other as loose siblings.
    for d in ("pe", "disasm", "lift"):
        d = os.path.join(PCRECOMP, "tools", d)
        if d not in sys.path:
            sys.path.insert(0, d)
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def pe():
    """PE32 analysis: sections, entry point, imports, IAT slot -> name map."""
    return _load(("tools", "pe", "pe_analyze.py"), "pe_analyze")


def disasm():
    """Recursive-descent function recovery. An ES3 binary is stripped, so this
    is where the function list comes from - there is no symbol table to read."""
    return _load(("tools", "disasm", "disasm32.py"), "disasm32")


def argc():
    """Win32 stack-purge derivation. An ES3 handler has to pop exactly what the
    real callee popped, and the counts are derived rather than typed."""
    return _load(("tools", "pe", "stdcall_argc.py"), "stdcall_argc")


def lifter():
    """x86-32 -> C, CPU-struct model (pairs with runtime/recomp32_cpu/cpu.h)."""
    return _load(("tools", "lift", "lift32_cpu.py"), "lift32_cpu")
