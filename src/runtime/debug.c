/*
 * debug.c - run the game under ourselves, because some deaths have no handler.
 *
 * crash.c catches what a vectored handler can catch, and that is nearly
 * everything. The exception is the exception that cannot be *dispatched*: when
 * a thread faults with a stack the kernel cannot push an exception frame onto,
 * Windows ends the process there. No vectored handler, no unhandled filter, no
 * TLS callback, exit code 0xC0000005 and a log that stops mid-line. That is
 * precisely the shape a recompiler produces when it gets a stack pointer
 * wrong, so it is precisely the one worth being able to see.
 *
 * A debugger sees it, because the notification comes from the kernel rather
 * than from the faulting thread. So `ES3_DEBUG=1` makes this process relaunch
 * itself as its own debuggee and print every exception the child takes: code,
 * address, thread, first or second chance.
 *
 * The useful part is that parent and child are the same executable at the same
 * image base - /BASE:0x20000000 with /DYNAMICBASE:NO, for the guest's sake -
 * so a host address from the child resolves in the parent's own tables.
 * dispatch_owner() turns it straight back into a guest function.
 *
 * The parent also does what relaunch_reserving() does, because the child needs
 * 0x00400000 reserved before its loader runs and only something outside it
 * can do that. CREATE_PROCESS_DEBUG_EVENT arrives at exactly that moment.
 */

#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#endif

#include "es3_rt.h"

#ifdef _WIN32

#define ES3_DEBUG_CHILD "ES3_DEBUGGEE"

static const char *code_name(DWORD c)
{
    switch (c) {
    case EXCEPTION_ACCESS_VIOLATION:      return "access violation";
    case EXCEPTION_STACK_OVERFLOW:        return "stack overflow";
    case EXCEPTION_ILLEGAL_INSTRUCTION:   return "illegal instruction";
    case EXCEPTION_PRIV_INSTRUCTION:      return "privileged instruction";
    case EXCEPTION_INT_DIVIDE_BY_ZERO:    return "integer divide by zero";
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:    return "float divide by zero";
    case EXCEPTION_BREAKPOINT:            return "breakpoint";
    case 0xE06D7363u:                     return "C++ throw";
    case 0x406D1388u:                     return "thread name (for a debugger)";
    case 0x40010006u:                     return "OutputDebugString";
    case 0xC0000409u:                     return "__fastfail / stack cookie";
    default:                              return "";
    }
}

/* Only the ones worth a line. A running game raises thousands of C++ throws
 * and debug prints that it catches itself, and printing those buries the one
 * that ends the run. Second-chance is always printed: nothing catches those.
 *
 * The exception to the exception is the execute violation inside the guest
 * image. That one is not a fault at all, it is this runtime's mechanism: the
 * image is mapped without execute so that a real library calling an unthunked
 * guest pointer arrives at crash.c to be redirected. There are hundreds, they
 * are all expected, and left in they fill any budget before the interesting
 * one happens - which is how the first version of this reporter managed to
 * miss the very death it was written for. */
static int worth_saying(const EXCEPTION_RECORD *r, int first_chance)
{
    DWORD code = r->ExceptionCode;
    if (!first_chance) return 1;
    if (code == EXCEPTION_ACCESS_VIOLATION && r->NumberParameters >= 2 &&
        r->ExceptionInformation[0] == 8) {
        uint32_t va = (uint32_t)r->ExceptionInformation[1];
        if (va >= 0x00400000u && va < 0x02400000u) return 0;
    }
    return code == EXCEPTION_ACCESS_VIOLATION ||
           code == EXCEPTION_STACK_OVERFLOW ||
           code == EXCEPTION_ILLEGAL_INSTRUCTION ||
           code == EXCEPTION_PRIV_INSTRUCTION ||
           code == 0xC0000409u;
}

int es3_debug_self(void)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DEBUG_EVENT ev;
    DWORD code = 0;
    unsigned shown = 0;

    if (!getenv("ES3_DEBUG")) return 0;
    if (GetEnvironmentVariableA(ES3_DEBUG_CHILD, NULL, 0) != 0) return 0;

    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    SetEnvironmentVariableA(ES3_DEBUG_CHILD, "1");
    if (!CreateProcessW(NULL, GetCommandLineW(), NULL, NULL, TRUE,
                        DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "[debug] cannot relaunch as a debuggee (%lu)\n",
                GetLastError());
        return 0;
    }
    fprintf(stderr, "[debug] watching pid %lu; every exception it takes is "
                    "reported here\n", pi.dwProcessId);

    for (;;) {
        if (!WaitForDebugEvent(&ev, INFINITE)) break;

        if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            /* Its loader has not run. This is the one moment 0x00400000 is
             * free in that process - see guest.c's relaunch_reserving(). */
            if (!VirtualAllocEx(pi.hProcess, (LPVOID)(uintptr_t)0x00400000u,
                                0x02000000u, MEM_RESERVE, PAGE_READWRITE))
                fprintf(stderr, "[debug] could not reserve the guest range in "
                                "the child (%lu) - it will relaunch itself\n",
                        GetLastError());
            if (ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
        } else if (ev.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
            if (ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);
        } else if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            const EXCEPTION_RECORD *r = &ev.u.Exception.ExceptionRecord;
            int first = ev.u.Exception.dwFirstChance != 0;
            if (worth_saying(r, first) && shown < 200) {
                uint32_t owner = dispatch_owner(r->ExceptionAddress);
                shown++;
                fprintf(stderr, "[debug] %s chance %08lX %s at %p on thread %lu",
                        first ? "first" : "SECOND",
                        (unsigned long)r->ExceptionCode,
                        code_name(r->ExceptionCode), r->ExceptionAddress,
                        ev.dwThreadId);
                if (owner) fprintf(stderr, ", inside guest %08X", owner);
                /* And which module, because "at 037B7A52" is a number until
                 * something says it is MSVCR100. The parent can ask about the
                 * child's address space directly. */
                {
                    wchar_t name[MAX_PATH];
                    MEMORY_BASIC_INFORMATION mi;
                    if (GetMappedFileNameW(pi.hProcess, r->ExceptionAddress,
                                           name, MAX_PATH)) {
                        const wchar_t *b = wcsrchr(name, L'\\');
                        fprintf(stderr, " in %ls", b ? b + 1 : name);
                    } else if (VirtualQueryEx(pi.hProcess, r->ExceptionAddress,
                                              &mi, sizeof mi)) {
                        fprintf(stderr, " in private memory at %08X",
                                (uint32_t)(uintptr_t)mi.AllocationBase);
                    }
                    if (r->NumberParameters >= 2 &&
                        VirtualQueryEx(pi.hProcess,
                                       (LPCVOID)r->ExceptionInformation[1],
                                       &mi, sizeof mi))
                        fprintf(stderr, "; target region %08X %s",
                                (uint32_t)(uintptr_t)mi.AllocationBase,
                                mi.State == MEM_COMMIT ? "committed" :
                                mi.State == MEM_RESERVE ? "RESERVED, not committed"
                                                        : "FREE");
                    /* And the stack it was standing on, which is the question
                     * when the address that faulted is just below the bottom
                     * of something. Is that something the thread's own stack,
                     * or a region it was borrowing? */
                    {
                        HANDLE th = OpenThread(THREAD_GET_CONTEXT, FALSE,
                                               ev.dwThreadId);
                        if (th) {
                            CONTEXT cx;
                            memset(&cx, 0, sizeof cx);
                            cx.ContextFlags = CONTEXT_CONTROL;
                            if (GetThreadContext(th, &cx)) {
                                fprintf(stderr, "\n        esp=%08X ebp=%08X",
                                        (uint32_t)cx.Esp, (uint32_t)cx.Ebp);
                                if (VirtualQueryEx(pi.hProcess,
                                                   (LPCVOID)(uintptr_t)cx.Esp,
                                                   &mi, sizeof mi))
                                    fprintf(stderr, ", standing in %08X..%08X %s",
                                            (uint32_t)(uintptr_t)mi.AllocationBase,
                                            (uint32_t)(uintptr_t)mi.BaseAddress +
                                                (uint32_t)mi.RegionSize,
                                            mi.State == MEM_COMMIT ? "committed"
                                                                   : "not committed");
                            }
                            CloseHandle(th);
                        }
                    }
                    /* And the instruction itself. A fault address names a
                     * place; the bytes name what it was doing there, and with
                     * no symbols for a JIT or a driver that is the only way to
                     * tell a push from a string move. Disassemble them with
                     * whatever is to hand - they are x86. */
                    {
                        unsigned char code[16];
                        SIZE_T got = 0;
                        if (ReadProcessMemory(pi.hProcess, r->ExceptionAddress,
                                              code, sizeof code, &got) && got) {
                            SIZE_T k;
                            fprintf(stderr, "\n        bytes:");
                            for (k = 0; k < got; k++)
                                fprintf(stderr, " %02X", code[k]);
                        }
                    }
                }
                if (r->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
                    r->NumberParameters >= 2)
                    fprintf(stderr, " (%s %08X)",
                            r->ExceptionInformation[0] == 0 ? "reading" :
                            r->ExceptionInformation[0] == 1 ? "writing" :
                                                              "executing",
                            (uint32_t)r->ExceptionInformation[1]);
                fprintf(stderr, "\n");
                fflush(stderr);
            }
            /* Hand it back: the child's own handlers are the point, and this
             * is a reporter, not a debugger anyone types into. */
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId,
                               DBG_EXCEPTION_NOT_HANDLED);
            continue;
        } else if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            code = ev.u.ExitProcess.dwExitCode;
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
            break;
        }
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
    }

    fprintf(stderr, "[debug] the child ended with %08lX\n", (unsigned long)code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    exit((int)code);
}

#else
int es3_debug_self(void) { return 0; }
#endif
