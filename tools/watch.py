"""Run a recompiled game as a debuggee and report how it actually died.

Every exit door a runtime can hook from inside - the guest's `exit` import,
kernel32!ExitProcess, kernel32!TerminateProcess, ntdll!NtTerminateProcess, the
TLS detach callback - can be installed, verified present in the binary, and
still print nothing, because the death that matters is the one the kernel
performs itself: a thread faults on its guard page while already dispatching a
fault, exception dispatch fails, and the process is simply gone. No vectored
handler runs. No Windows Error Reporting record is written. The log stops
mid-line and the shell reports an exit code that belongs to nothing in the
source.

A debugger sees all of it, because the kernel tells the debugger before it
tells anyone else. This is the smallest one that answers the question: it
prints exceptions (skipping the three the runtime raises constantly by
design), the exit code of each of the last threads to go, and the process exit
code the kernel really used.

    py -3.11 -m tools watch game.exe [args...]

Read the output from the bottom. The last first-chance exception before the
end names the thread; STATUS_STACK_OVERFLOW (C00000FD) means a stack floor is
too low, not that anything is wrong with the lifted code.
"""

import ctypes
import ctypes.wintypes as w
import sys

DEBUG_ONLY_THIS_PROCESS = 0x00000002
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

EXCEPTION_DEBUG_EVENT = 1
CREATE_THREAD_DEBUG_EVENT = 2
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_THREAD_DEBUG_EVENT = 4
EXIT_PROCESS_DEBUG_EVENT = 5

# The ones a hybrid runtime raises on purpose and by the hundred thousand:
# OutputDebugString (wide and narrow) and the thread-name exception. Printing
# these buries the one line that matters.
BY_DESIGN = (0x4001000A, 0x40010006, 0x406D1388)

NAMES = {
    0xC0000005: "ACCESS VIOLATION",
    0xC00000FD: "STACK OVERFLOW",
    0xC0000409: "FAST FAIL",
    0xC000001D: "ILLEGAL INSTRUCTION",
    0xC0000094: "INTEGER DIVIDE BY ZERO",
    0xE06D7363: "C++ exception",
}


class _SI(ctypes.Structure):
    _fields_ = [("cb", w.DWORD), ("lpReserved", w.LPWSTR),
                ("lpDesktop", w.LPWSTR), ("lpTitle", w.LPWSTR),
                ("dwX", w.DWORD), ("dwY", w.DWORD), ("dwXSize", w.DWORD),
                ("dwYSize", w.DWORD), ("dwXCountChars", w.DWORD),
                ("dwYCountChars", w.DWORD), ("dwFillAttribute", w.DWORD),
                ("dwFlags", w.DWORD), ("wShowWindow", w.WORD),
                ("cbReserved2", w.WORD), ("lpReserved2", ctypes.c_void_p),
                ("hStdInput", w.HANDLE), ("hStdOutput", w.HANDLE),
                ("hStdError", w.HANDLE)]


class _PI(ctypes.Structure):
    _fields_ = [("hProcess", w.HANDLE), ("hThread", w.HANDLE),
                ("dwProcessId", w.DWORD), ("dwThreadId", w.DWORD)]


class _EXREC(ctypes.Structure):
    pass


_EXREC._fields_ = [("ExceptionCode", w.DWORD), ("ExceptionFlags", w.DWORD),
                   ("ExceptionRecord", ctypes.POINTER(_EXREC)),
                   ("ExceptionAddress", ctypes.c_void_p),
                   ("NumberParameters", w.DWORD),
                   ("ExceptionInformation", ctypes.c_void_p * 15)]


class _EXDBG(ctypes.Structure):
    _fields_ = [("ExceptionRecord", _EXREC), ("dwFirstChance", w.DWORD)]


class _EXIT(ctypes.Structure):
    _fields_ = [("dwExitCode", w.DWORD)]


class _U(ctypes.Union):
    _fields_ = [("Exception", _EXDBG), ("ExitThread", _EXIT),
                ("ExitProcess", _EXIT), ("pad", ctypes.c_byte * 160)]


class _EVENT(ctypes.Structure):
    _fields_ = [("dwDebugEventCode", w.DWORD), ("dwProcessId", w.DWORD),
                ("dwThreadId", w.DWORD), ("u", _U)]


def watch(argv, quiet_first_chance=False):
    """Run argv as a debuggee. Returns the process exit code."""
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    si, pi = _SI(), _PI()
    si.cb = ctypes.sizeof(si)
    cmd = ctypes.create_unicode_buffer(" ".join(argv))
    if not k.CreateProcessW(None, cmd, None, None, False,
                            DEBUG_ONLY_THIS_PROCESS, None, None,
                            ctypes.byref(si), ctypes.byref(pi)):
        sys.exit("CreateProcessW failed with %d - give the full path to the "
                 "exe, the current directory is not searched"
                 % ctypes.get_last_error())

    ev = _EVENT()
    live = 0
    seen = {}
    code = 0
    while True:
        if not k.WaitForDebugEvent(ctypes.byref(ev), 0xFFFFFFFF):
            print("!! WaitForDebugEvent failed %d" % ctypes.get_last_error())
            break
        what = ev.dwDebugEventCode
        cont = DBG_CONTINUE

        if what == EXCEPTION_DEBUG_EVENT:
            r = ev.u.Exception.ExceptionRecord
            first = ev.u.Exception.dwFirstChance
            show = r.ExceptionCode not in BY_DESIGN
            if quiet_first_chance and first:
                # Still count them: "86,754 access violations at one address"
                # is the shape of a mechanism, not of a bug, and the totals at
                # the end say which is which.
                seen[(r.ExceptionCode, r.ExceptionAddress)] = \
                    seen.get((r.ExceptionCode, r.ExceptionAddress), 0) + 1
                show = False
            if show:
                print("EXCEPTION %08X %s at %s  thread %d  %s" % (
                    r.ExceptionCode,
                    NAMES.get(r.ExceptionCode, ""),
                    hex(r.ExceptionAddress or 0), ev.dwThreadId,
                    "first chance" if first else "SECOND CHANCE"))
            # Not handled: the debuggee's own handlers must get their turn, and
            # a second chance is what tells us nobody took it.
            cont = DBG_EXCEPTION_NOT_HANDLED
        elif what in (CREATE_THREAD_DEBUG_EVENT, CREATE_PROCESS_DEBUG_EVENT):
            live += 1
        elif what == EXIT_THREAD_DEBUG_EVENT:
            live -= 1
            if live <= 3:          # the last few out are the shutdown order
                print("thread %d exited with %d (%d left)"
                      % (ev.dwThreadId, ev.u.ExitThread.dwExitCode, live))
        elif what == EXIT_PROCESS_DEBUG_EVENT:
            code = ev.u.ExitProcess.dwExitCode
            print("PROCESS EXIT code %d (%#010x), %d thread(s) still live"
                  % (code, code, live))
            k.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)
            break

        k.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont)

    for (c, at), n in sorted(seen.items(), key=lambda kv: -kv[1])[:10]:
        print("  %8d x %08X at %s" % (n, c, hex(at or 0)))
    return code
