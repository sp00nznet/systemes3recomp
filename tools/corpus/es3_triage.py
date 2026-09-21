"""
es3_triage.py - what is in the System ES3 corpus, and how far each title gets.

The corpus is 392 TeknoParrot titles across a dozen platforms; only the Namco
System ES3 family is ours, which is 17 builds of 8 distinct titles. This
catalogues those and nothing else.

Triage runs in stages, and a title only earns the next one by passing the
last:

    catalogued   the archive is found, its main binary identified, and its
                 architecture read out of the PE header - which decides
                 whether the 32-bit or the 64-bit lifter applies
    extracted    unpacked to a tree the runtime can run from
    lifted       pcrecomp has produced C for it
    built        that C compiles and links against the runtime
    boots        the process starts and gets through its own startup
    attract      it draws its attract mode
    ingame       a race or match actually runs
    playable     with working controls

Stage 1 is all this does. It reads archives and writes a catalogue; it does
not extract, and it never writes into the corpus. 126 GB of archive gets
listed, not copied.

    py -3.11 es3_triage.py            catalogue and print
    py -3.11 es3_triage.py --json     the same, as JSON on stdout
"""

import json
import os
import re
import struct
import subprocess
import sys
import tempfile

CORPUS = r"Y:\unsort\complete\teknoparrot-eggman"
SEVENZ = r"C:\Program Files\7-Zip\7z.exe"
HERE = os.path.dirname(os.path.abspath(__file__))
CATALOG = os.path.join(HERE, "es3_catalog.json")

# The ES3 family as the corpus tags it. ES1, N2 and BNA1 are different
# machines and are deliberately not here.
ES3_TAG = re.compile(r"\[Namco ES3([ABX]?)\]")

# Binaries that are never the game: launchers, auth daemons, installers and
# the AMCUS network stack that ships alongside every Namco title.
NOT_THE_GAME = re.compile(
    r"(^|[\\/])(AMCUS|Launcher|redist|_?Redistributables?|DirectX|vcredist)[\\/]"
    r"|amauth|amupdater|mucha|unins|setup|vcredist|dxsetup|rslauncher"
    r"|crashreport|prereq",
    re.I,
)


def sh(args):
    """Run a command and return its stdout, or '' if it failed."""
    try:
        cwd = TOOLS_DIR if args and args[0] == sys.executable else None
        out = subprocess.run(args, capture_output=True, timeout=900, cwd=cwd)
        return out.stdout.decode("utf-8", "replace")
    except Exception:
        return ""


def archives():
    """Every ES3 archive in the corpus, with its platform tag."""
    found = []
    try:
        names = os.listdir(CORPUS)
    except OSError as exc:
        print("cannot read the corpus at %s: %s" % (CORPUS, exc))
        return found
    for name in sorted(names):
        if not name.lower().endswith(".zip"):
            continue
        tag = ES3_TAG.search(name)
        if not tag:
            continue
        path = os.path.join(CORPUS, name)
        found.append(
            {
                "archive": name,
                "path": path,
                "variant": "ES3" + tag.group(1),
                "bytes": os.path.getsize(path),
                "title": re.sub(r"\s*\[.*$", "", name).strip(),
            }
        )
    return found


def entries(path):
    """(name, size) for every file in the archive, from its directory only."""
    text = sh([SEVENZ, "l", path])
    out = []
    for line in text.splitlines():
        # 7z's listing: date time attr size compressed name
        m = re.match(r"^\S+\s+\S+\s+\S+\s+(\d+)\s+\d*\s+(.+)$", line)
        if m:
            out.append((m.group(2).strip(), int(m.group(1))))
    return out


def pick_binary(files):
    """
    The game's own executable.

    The biggest .exe that is not a launcher or an auth daemon: every title
    here ships several, and the one that matters is the one with the game in
    it. Star Wars Battle Pod has seven and only
    Binaries/Win64/SWArcGame-Win64-Shipping.exe is the game.
    """
    best = None
    for name, size in files:
        if not name.lower().endswith(".exe"):
            continue
        if NOT_THE_GAME.search(name):
            continue
        if best is None or size > best[1]:
            best = (name, size)
    return best


def pe_machine(archive, member):
    """
    The PE machine type, read from the archive without unpacking the rest.

    This is what decides which lifter a title needs, so it is worth the one
    extraction: 0x014C is 32-bit and takes the x86 lifter, 0x8664 is 64-bit
    and needs the one being built for Battle Pod.
    """
    tmp = tempfile.mkdtemp(prefix="es3tri_")
    try:
        sh([SEVENZ, "e", "-o" + tmp, "-y", archive, member])
        local = os.path.join(tmp, os.path.basename(member.replace("\\", "/")))
        if not os.path.exists(local):
            return None, None
        with open(local, "rb") as fh:
            head = fh.read(0x400)
        if len(head) < 0x40 or head[:2] != b"MZ":
            return None, None
        off = struct.unpack_from("<I", head, 0x3C)[0]
        if off + 6 > len(head) or head[off : off + 4] != b"PE\0\0":
            return None, None
        machine = struct.unpack_from("<H", head, off + 4)[0]
        return machine, {0x014C: "x86", 0x8664: "x64"}.get(machine, hex(machine))
    finally:
        for root, _, names in os.walk(tmp, topdown=False):
            for n in names:
                try:
                    os.remove(os.path.join(root, n))
                except OSError:
                    pass
            try:
                os.rmdir(root)
            except OSError:
                pass



# pcrecomp's PE reader lives two directories up from tools/corpus.
TOOLS_DIR = os.path.dirname(os.path.dirname(HERE))


def pe_facts(archive, member):
    """
    What the binary needs, from pcrecomp's own PE reader.

    The import list is the best early measure of how much runtime a title
    will want: MachStorm asks for 254 functions from 18 DLLs against Mario
    Kart's 495 from 27, and the difference is most of the work. It also says
    which subsystems are shared - SETUPAPI means the USB I/O board, eOkaoDt
    means the OMRON camera - so effort already spent can be counted.
    """
    out = {"pe": None, "imports": 0, "dlls": [], "linker": None}
    tmp = tempfile.mkdtemp(prefix="es3pe_")
    try:
        sh([SEVENZ, "e", "-o" + tmp, "-y", archive, member])
        local = os.path.join(tmp, os.path.basename(member.replace("\\", "/")))
        if not os.path.exists(local):
            return out
        text = sh([sys.executable, "-m", "tools", "pe", local])
        for line in text.splitlines():
            if line.startswith("format"):
                out["pe"] = line.split(None, 1)[1].strip()
            elif line.startswith("linker"):
                out["linker"] = line.split(None, 1)[1].strip()
            elif line.startswith("imports"):
                m = re.search(r"(\d+) functions from (\d+)", line)
                if m:
                    out["imports"] = int(m.group(1))
            m = re.match(r"\s+needs\s+(\S+)\s+(\d+)", line)
            if m:
                out["dlls"].append([m.group(1), int(m.group(2))])
        return out
    finally:
        for root, _, names in os.walk(tmp, topdown=False):
            for n in names:
                try:
                    os.remove(os.path.join(root, n))
                except OSError:
                    pass
            try:
                os.rmdir(root)
            except OSError:
                pass

def main():
    want_json = "--json" in sys.argv
    rows = archives()
    if not rows:
        return 1

    for row in rows:
        files = entries(row["path"])
        row["files"] = len(files)
        pick = pick_binary(files)
        if pick:
            row["binary"], row["binary_bytes"] = pick
            _, arch = pe_machine(row["path"], pick[0])
            row["arch"] = arch or "unknown"
        else:
            row["binary"], row["binary_bytes"], row["arch"] = None, 0, "unknown"
        row["stage"] = "catalogued"
        if row["binary"]:
            row.update(pe_facts(row["path"], row["binary"]))

    with open(CATALOG, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=2)

    if want_json:
        json.dump(rows, sys.stdout, indent=2)
        return 0

    print("%-52s %-6s %-5s %8s  %s" % ("title", "family", "arch", "GB", "binary"))
    print("-" * 118)
    for row in rows:
        print(
            "%-52s %-6s %-5s %8.1f  %s"
            % (
                row["title"][:52],
                row["variant"],
                row["arch"],
                row["bytes"] / (1024.0 ** 3),
                (row["binary"] or "(none found)")[-44:],
            )
        )
    print()
    by_arch = {}
    for row in rows:
        by_arch[row["arch"]] = by_arch.get(row["arch"], 0) + 1
    print("%d builds; by architecture: %s" % (len(rows), by_arch))
    print("catalogue written to %s" % CATALOG)
    return 0


if __name__ == "__main__":
    sys.exit(main())
