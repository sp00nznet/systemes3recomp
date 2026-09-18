/*
 * trace64.c - where it got to.
 *
 * A recompiled game that stops has stopped somewhere, and there is no debugger
 * on the far side of a lifted call: the stack is C frames named L_0001400xxxxx
 * with no symbols, and a release build turns abort() into __fastfail, which no
 * handler sees and which leaves nothing behind at all. The only way to know
 * where it got to is to have written it down on the way.
 *
 * A ring buffer, because the interesting part is always the last few hundred
 * entries and the first few million are startup. Unsynchronised on purpose -
 * a lock here would change the timing of the thing being diagnosed, and a
 * torn entry in a crash log is still worth more than no log.
 */

#include "es3_rt64.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>

#define TRACE_N 4096

typedef struct { uint64_t va; const char *what; } trace_ent_t;

static trace_ent_t g_ring[TRACE_N];
static volatile long g_head;
static uint64_t g_calls;

void es3_trace(uint64_t va, const char *what)
{
    long i = (g_head++) & (TRACE_N - 1);
    g_ring[i].va = va;
    g_ring[i].what = what;
    g_calls++;
}

void es3_trace_dump(const char *why)
{
    FILE *f = fopen("es3_trace64.txt", "w");
    if (!f) f = stderr;
    fprintf(f, "=== es3 trace: %s ===\n", why);
    fprintf(f, "image base %p (preferred %#llx, delta %+lld)\n",
            (void *)g_image.base, (unsigned long long)g_image.preferred,
            (long long)g_image_delta);
    fprintf(f, "%llu dispatches total, last %d:\n",
            (unsigned long long)g_calls, TRACE_N);

    long head = g_head;
    long n = head < TRACE_N ? head : TRACE_N;
    for (long k = n; k > 0; k--) {
        long i = (head - k) & (TRACE_N - 1);
        if (!g_ring[i].what) continue;
        uint64_t va = g_ring[i].va;
        const char *nm = es3_import_name(va);
        fprintf(f, "  %-12s %#018llx %s\n", g_ring[i].what,
                (unsigned long long)va, nm ? nm : "");
    }
    fflush(f);
    if (f != stderr) {
        fclose(f);
        fprintf(stderr, "[trace] wrote es3_trace64.txt (%ld entries)\n", n);
    }
}

static LONG WINAPI es3_seh(EXCEPTION_POINTERS *ep)
{
    char msg[256];
    snprintf(msg, sizeof msg, "exception %#lx at %p",
             ep->ExceptionRecord->ExceptionCode,
             ep->ExceptionRecord->ExceptionAddress);
    fprintf(stderr, "\n[crash] %s\n", msg);

    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        /* The address the guest tried to touch is the diagnosis nine times out
         * of ten: near zero is an uninitialised pointer, and a value that looks
         * like a guest address with a 4 GB-multiple offset is a 32-bit register
         * write that failed to zero-extend. */
        fprintf(stderr, "[crash] %s address %#llx\n",
                ep->ExceptionRecord->ExceptionInformation[0] ? "write to" : "read from",
                (unsigned long long)ep->ExceptionRecord->ExceptionInformation[1]);
    }
    es3_trace_dump(msg);
    return EXCEPTION_EXECUTE_HANDLER;
}

static LONG CALLBACK es3_veh(EXCEPTION_POINTERS *ep)
{
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    /* Every exception gets a line, always. Passing one over silently as
     * "benign" is how a run ends with an exit code and no explanation: nothing
     * downstream had a handler either, so the exception this filter waved
     * through became the thing that killed the process. */
    fprintf(stderr, "[veh] exception %#lx at %p (dispatch %llu)\n",
            code, ep->ExceptionRecord->ExceptionAddress,
            (unsigned long long)g_dispatch_count);

    /* 0x406D1388 is the "set thread name" notification. It is addressed to a
     * debugger and is meant to be swallowed; with no debugger attached and no
     * guest SEH to catch it, letting it continue the search makes it fatal.
     * Continuing EXECUTION is what a debugger does. */
    if (code == 0x406D1388u)
        return EXCEPTION_CONTINUE_EXECUTION;

    /* A C++ throw is the guest working, not failing - its own handler is
     * further up, in lifted code. */
    if (code == 0xE06D7363u || code == (DWORD)DBG_PRINTEXCEPTION_C)
        return EXCEPTION_CONTINUE_SEARCH;

    es3_seh(ep);
    return EXCEPTION_CONTINUE_SEARCH;
}

void es3_install_crash_handler(void)
{
    /* Both, deliberately. SetUnhandledExceptionFilter runs last and does not
     * run at all if the fault corrupted enough state to prevent unwinding -
     * which is exactly the case when a lifted function walks off a stack. A
     * vectored handler runs FIRST, before any unwinding, so the trail survives
     * the faults that matter most. */
    AddVectoredExceptionHandler(1, es3_veh);
    SetUnhandledExceptionFilter(es3_seh);
}
