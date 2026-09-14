/*
 * crash.c - say where a recompiled game died, in the guest's terms.
 *
 * When lifted code faults, a debugger shows you `L_004A0550` inside a
 * two-million-line generated file, which is true and useless. What is wanted
 * is the simulated machine: which guest function was running, what it was
 * reaching for, and whether that address is anywhere meaningful.
 *
 * The one that pays for this file on its own is the import sentinel. A fault
 * at 0xE53000xx means something called an IAT slot as if it were a real
 * function pointer - which is exactly what happens when a real library
 * function calls back into guest code and runs the *original* bytes instead of
 * the lifted ones. That reads as a meaningless address in a debugger and as
 * one line here.
 *
 * pcrecomp has a crash reporter (runtime/recomp32/crash_report.c) and it does
 * not fit: it is written against the global-register model and reads `g_eax`
 * directly, which does not exist in a CPU-struct build. Generalising it is
 * worth doing when there is a second CPU-struct consumer to generalise for.
 *
 * The handler reports and then declines the exception, so the process still
 * dies and a debugger still gets its turn. Nothing here allocates.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include "es3_rt.h"

/* ponytail: a ring written on every dispatch. It costs two stores and a mask
 * per guest call, which does not show up next to the work a call does. If it
 * ever does, make it a build option rather than deleting it - the trail is
 * most of the value here. */
/* Pairs, not addresses: a thread id with every entry.
 *
 * One ring shared by every thread is almost useless once a game has a worker
 * pool - sixteen threads spinning on SignalObjectAndWait fill a thousand
 * entries in a millisecond and bury the one thread anybody wants to see. With
 * the id alongside, `tools trail` can show one thread at a time.
 *
 * The id comes from fs:[0x24] (TEB ClientId.UniqueThread) rather than
 * GetCurrentThreadId(), which is a call; this is one load. */
/* A whole boot, not a moment of one.
 * 4096 entries is about forty milliseconds of a game with twenty threads,
 * and every question worth asking spans more than that - `did the init step
 * run before the first frame` needs a hundred thousand. A million pairs is
 * 8 MB of a memory-mapped file, which costs nothing until it is read. */
#define TRAIL (1u << 20)
static uint32_t  g_fallback[2 * TRAIL + 2];
static uint32_t *g_ring = g_fallback;     /* [0]=count, [1]=stride, then pairs */
static const CPU *g_cpu;

/* How many times a real library called guest code directly - see the
 * execute-violation handler. Worth knowing: each one is a callback this
 * runtime did not thunk, and a page fault every time it happens. */
static unsigned g_r2l_faults;

#define RING_COUNT  g_ring[0]
#define RING_TID(i) g_ring[2 + 2 * ((i) & (TRAIL - 1))]
#define RING_VA(i)  g_ring[3 + 2 * ((i) & (TRAIL - 1))]

/* ES3_WATCH_VA=5a7c90,5a80b0 - say when those guest functions are entered.
 *
 * The ring answers "how did it get here", which is the question you have after
 * a fault. The question you have before one is "did this ever run, and did it
 * run before that" - a null singleton is an initialiser that did not happen,
 * and the update that trips over it is often a vtable slot with no static
 * caller to read. Eight addresses, compared on every dispatch, only when the
 * variable is set. */
static uint32_t g_watch_va[8];
static unsigned g_nwatch;
static int g_watch_read;

static void watch_va_init(void)
{
    const char *s = getenv("ES3_WATCH_VA");
    g_watch_read = 1;
    while (s && *s && g_nwatch < 8) {
        char *end;
        unsigned long v = strtoul(s, &end, 16);
        if (end == s) break;
        g_watch_va[g_nwatch++] = (uint32_t)v;
        s = *end == ',' ? end + 1 : end;
    }
    if (g_nwatch)
        fprintf(stderr, "[watch] %u guest address(es)\n", g_nwatch);
}

int es3_watched(uint32_t va)
{
    unsigned k;
    if (!g_watch_read) watch_va_init();
    for (k = 0; k < g_nwatch; k++)
        if (g_watch_va[k] == va) return 1;
    return 0;
}

unsigned es3_dispatch_count(void) { return RING_COUNT; }

void es3_note_dispatch(uint32_t va)
{
    unsigned i = RING_COUNT;

#ifdef _WIN32
    RING_TID(i) = __readfsdword(0x24);
#else
    RING_TID(i) = 0;
#endif
    RING_VA(i) = va;
    RING_COUNT = i + 1;
}

/*
 * The ring lives in a memory-mapped file, because the interesting deaths are
 * the ones no handler sees.
 *
 * A forwarded CRT that gives up calls `__fastfail`, and that is not an
 * exception: not a vectored handler, not an unhandled-exception filter, not
 * an SEH frame. The process is simply gone, exit code 0xC0000409, having
 * printed nothing. A trail that only exists in this process's memory goes with
 * it, and the run says nothing about how it got there.
 *
 * Mapped to a file, the last thousand guest calls are still on disk
 * afterwards. `es3_trail.bin`, in the working directory, dumped by
 * `py -3.11 -m tools trail`.
 */
static void open_trail(void)
{
#ifdef _WIN32
    HANDLE f = CreateFileA("es3_trail.bin", GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE m;
    void *v;
    if (f == INVALID_HANDLE_VALUE) return;
    m = CreateFileMappingA(f, NULL, PAGE_READWRITE, 0,
                           (2 * TRAIL + 2) * sizeof(uint32_t), NULL);
    CloseHandle(f);
    if (!m) return;
    v = MapViewOfFile(m, FILE_MAP_WRITE, 0, 0, 0);
    CloseHandle(m);
    if (!v) return;
    memset(v, 0, (2 * TRAIL + 2) * sizeof(uint32_t));
    g_ring = (uint32_t *)v;
    g_ring[1] = 2;                 /* words per entry, for the reader */
#endif
}

void es3_watch_cpu(const CPU *c) { g_cpu = c; }

static const char *region_of(uint32_t va)
{
    uint32_t base = guest_image_base();
    if (HLE_IS_ADDR(va)) return "an IMPORT SENTINEL - see below";
    if (va >= base && va < base + 0x02000000u) return "inside the guest image";
    if (va < 0x10000u) return "null page";
    return "";
}

/*
 * Where the address space went.
 *
 * A 32-bit process has 2 GB, and a recompiled game spends some of it before
 * the game gets any: the guest image at its linked address, the guest stack,
 * hybrid's per-thread callback arena, and this runtime's own thirty-megabyte
 * image. When `operator new` throws std::bad_alloc with a 125 MB working set,
 * the question is not what is allocated but what is RESERVED, and by whom.
 */
void es3_report_memory(void)
{
#ifdef _WIN32
    MEMORY_BASIC_INFORMATION mi;
    uint64_t reserved = 0, committed = 0, freeb = 0, biggest_free = 0;
    uint32_t a = 0x10000;
    unsigned regions = 0;

    fprintf(stderr, "  address space, largest reservations first:\n");
    /* Two passes would need a list; one pass and a threshold is enough to name
     * anything big enough to matter. */
    while (a < 0x7FFF0000u) {
        if (!VirtualQuery((LPCVOID)(uintptr_t)a, &mi, sizeof mi)) break;
        if (mi.State == MEM_RESERVE) reserved += mi.RegionSize;
        else if (mi.State == MEM_COMMIT) committed += mi.RegionSize;
        else { freeb += mi.RegionSize;
               if (mi.RegionSize > biggest_free) biggest_free = mi.RegionSize; }
        if (mi.State != MEM_FREE && mi.RegionSize >= (4u << 20))
            fprintf(stderr, "    %08X  %6u MB  %s %s\n",
                    (uint32_t)(uintptr_t)mi.BaseAddress,
                    (unsigned)(mi.RegionSize >> 20),
                    mi.State == MEM_RESERVE ? "reserved " : "committed",
                    mi.Type == MEM_IMAGE ? "image" :
                    mi.Type == MEM_MAPPED ? "mapped" : "private");
        a = (uint32_t)(uintptr_t)mi.BaseAddress + (uint32_t)mi.RegionSize;
        if (++regions > 20000) break;
    }
    fprintf(stderr, "  %u MB committed, %u MB reserved, %u MB free "
                    "(largest free run %u MB)\n",
            (unsigned)(committed >> 20), (unsigned)(reserved >> 20),
            (unsigned)(freeb >> 20), (unsigned)(biggest_free >> 20));
#endif
}

void es3_report_state(const char *why)
{
    unsigned total = RING_COUNT;
    unsigned show = total < 24 ? total : 24;
    unsigned i;

    fprintf(stderr, "\n=== %s ===\n", why);
    fprintf(stderr, "  guest image at %#010x, %u dispatches so far\n",
            guest_image_base(), total);
    if (g_cpu) {
        const CPU *c = g_cpu;
        fprintf(stderr, "  eax=%08X ecx=%08X edx=%08X ebx=%08X\n",
                c->eax, c->ecx, c->edx, c->ebx);
        fprintf(stderr, "  esp=%08X ebp=%08X esi=%08X edi=%08X\n",
                c->esp, c->ebp, c->esi, c->edi);
    }
    fprintf(stderr, "  last %u dispatches (oldest first):\n", show);
    for (i = total - show; i < total; i++) {
        uint32_t va = RING_VA(i);
        if (HLE_IS_ADDR(va))
            fprintf(stderr, "    t%-6u %08X  import %s (%s)\n", RING_TID(i), va,
                    hle_name(HLE_ID_OF(va)), hle_dll(HLE_ID_OF(va)));
        else
            fprintf(stderr, "    t%-6u %08X  %s\n", RING_TID(i), va, region_of(va));
    }
    fprintf(stderr, "  the whole trail is in es3_trail.bin - "
                    "py -3.11 -m tools trail\n");
}

/* An instruction the lifter could not express, reached at run time.
 *
 * Most of the 560 of these in a lifted Mario Kart are not instructions the
 * game executes - they are data a recovery scan mistook for a function, or the
 * middle of a real instruction. So reaching one usually means the catalog is
 * wrong at that address rather than the lifter being short an opcode, and the
 * address is what says which. */
void es3_unlifted(uint32_t va, const char *text)
{
    fprintf(stderr, "\n[unlifted] %#010x: %s\n", va, text);
    es3_report_state("how it got there");
    fprintf(stderr,
        "  Either the lifter is short this instruction, or - far more often -\n"
        "  %#010x is not really code: a false function start from the data\n"
        "  scan, or the middle of a real instruction that a truncated\n"
        "  neighbour fell into. Check what precedes it before adding an opcode.\n",
        va);
    fflush(stderr);
    abort();
}

#ifdef _WIN32

/*
 * One thunk per guest address, minted once.
 *
 * The first version of this ran the lifted function from inside the handler,
 * with the CPU's esp pointing at the faulting thread's REAL stack. That is the
 * mistake hybrid's arena exists to prevent: the lifted code's pushes and the
 * host's own C frames then descend on the same stack and interleave. It worked
 * for a shallow callback and corrupted a deep one, and the corruption arrived
 * as an access violation the kernel could not even dispatch - no vectored
 * handler, no filter, a log that stops mid-line.
 *
 * Redirecting EIP to a thunk hands the whole problem to the code that already
 * solves it: the caller's own `call` is still in flight, its return address is
 * still where it put it, and r2l_common does the marshalling it does for every
 * other callback. Nothing here touches a register.
 *
 * Cached because the fault recurs on every call - the caller's pointer still
 * says the guest address - and minting a thunk each time would drain the pool
 * in a second.
 */
#define THUNK_CACHE 512
static struct { uint32_t va, thunk; } g_thunks[THUNK_CACHE];
static CRITICAL_SECTION g_thunk_lock;
static int g_thunk_lock_ready;

static uint32_t thunk_for(uint32_t va)
{
    unsigned i = (va * 2654435761u) % THUNK_CACHE, n;
    uint32_t t;
    for (n = 0; n < THUNK_CACHE; n++) {
        unsigned k = (i + n) % THUNK_CACHE;
        if (g_thunks[k].va == va) return g_thunks[k].thunk;
        if (!g_thunks[k].va) break;
    }
    if (!g_thunk_lock_ready) return 0;
    EnterCriticalSection(&g_thunk_lock);
    /* Again under the lock: another thread may have minted it meanwhile. */
    for (n = 0; n < THUNK_CACHE; n++) {
        unsigned k = (i + n) % THUNK_CACHE;
        if (g_thunks[k].va == va) { t = g_thunks[k].thunk; goto out; }
        if (!g_thunks[k].va) {
            t = es3_callback(va);
            g_thunks[k].thunk = t;
            g_thunks[k].va = va;          /* last, so a reader never sees half */
            goto out;
        }
    }
    t = 0;
out:
    LeaveCriticalSection(&g_thunk_lock);
    return t;
}

/* The address, written with no CRT at all.
 *
 * A fault report that goes through fprintf can be lost: the process died
 * part-way through one, leaving a blank line and nothing else, twice in a row.
 * stdio locks, and a lock is exactly what a thread in a bad state cannot take.
 * Sixteen bytes and one WriteFile cannot be lost that way. */
static void raw_fault(const EXCEPTION_RECORD *r, const void *at)
{
    static const char hex[] = "0123456789ABCDEF";
    char b[64], *p = b;
    const char *t = "\n!! fault ";
    unsigned long v;
    int i;
    DWORD n;
    while (*t) *p++ = *t++;
    v = r->ExceptionCode;
    for (i = 28; i >= 0; i -= 4) *p++ = hex[(v >> i) & 15];
    *p++ = ' '; *p++ = 'a'; *p++ = 't'; *p++ = ' ';
    v = (unsigned long)(uintptr_t)at;
    for (i = 28; i >= 0; i -= 4) *p++ = hex[(v >> i) & 15];
    *p++ = '\n';
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), b, (DWORD)(p - b), &n, NULL);
}

static LONG WINAPI es3_veh(EXCEPTION_POINTERS *ep)
{
    const EXCEPTION_RECORD *r = ep->ExceptionRecord;

    if (r->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        !(r->NumberParameters >= 2 && r->ExceptionInformation[0] == 8))
        raw_fault(r, r->ExceptionAddress);
    if (r->ExceptionCode != EXCEPTION_ACCESS_VIOLATION &&
        r->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION &&
        r->ExceptionCode != EXCEPTION_PRIV_INSTRUCTION) {
        /* Everything else, named once.
         *
         * A vectored handler sees every exception, including the ones the
         * guest raises on purpose and catches itself - the C++ throw
         * (0xE06D7363), the debugger's thread-name notice (0x406D1388),
         * OutputDebugString's own (0x40010006). Those are normal and there
         * are thousands of them, so this says each code once and declines.
         *
         * It is worth the line because "the process vanished" and "the guest
         * raised something nobody caught" look identical from outside, and
         * the last thing in the trail is then a RaiseException with no
         * explanation after it. */
        /* 0x406D1388 is "I am naming a thread", addressed to a debugger.
         *
         * There is no debugger, so nothing is listening, and the only thing
         * that can happen is the guest's own `__except` catching it back. That
         * handler is a guest address, and Windows calls a handler as real code
         * - so it would run the ORIGINAL bytes at that address, off a CPU
         * struct it knows nothing about, and the thread never comes back to
         * lifted code. The main thread went quiet exactly there.
         *
         * Thunking SEH handlers the way hybrid_thunk() handles callbacks is
         * the real answer and is a subsystem, not a line. This one exception
         * does not need it: resume, and RaiseException simply returns, which
         * is what it does on a machine with nobody watching. Every other code
         * is still the guest's to catch. */
        if (r->ExceptionCode == 0x406D1388u) return EXCEPTION_CONTINUE_EXECUTION;

        static volatile LONG said[8];
        int i;
        for (i = 0; i < 8; i++) {
            if ((DWORD)said[i] == r->ExceptionCode) break;
            if (!said[i] &&
                InterlockedCompareExchange(&said[i], (LONG)r->ExceptionCode, 0) == 0) {
                fprintf(stderr, "[seh] guest raised %08lX at %p (first time; "
                                "declining - it is the guest's to catch)\n",
                        (unsigned long)r->ExceptionCode, r->ExceptionAddress);
                /* A C++ throw is usually caught and unremarkable. This one is
                 * not: it ends the process with 0xE06D7363 and no message, and
                 * on a 2 GB address space the likeliest thrower by far is
                 * `operator new`. Say where the address space went. */
                if (r->ExceptionCode == 0xE06D7363u) es3_report_memory();
                fflush(stderr);
                break;
            }
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    /*
     * Real code tried to execute guest code. Run the lifted version instead.
     *
     * guest_load() maps the image without execute for exactly this: any
     * pointer to guest code that reached a real library unthunked arrives
     * here, as an execute violation at the address that was called, with the
     * caller's registers in the CONTEXT and its return address on the stack.
     *
     * That is everything a dispatch needs. Build a CPU from the context, run
     * the lifted function, put the registers back, and resume at the return
     * address the caller pushed - which the lifted `ret` has already stepped
     * esp past, so esp comes back from the CPU rather than being adjusted
     * here.
     *
     * The alternative is a thunk per callback, and the callbacks that need one
     * are not all arguments: a COM interface the game implements is a vtable
     * of guest addresses handed to a library, with nothing to wrap. This is
     * the same trade hybrid_thunk() makes, made once for every case at once,
     * at the cost of a first-time page fault per distinct callback.
     */
    if (r->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        r->NumberParameters >= 2 && r->ExceptionInformation[0] == 8) {
        uint32_t va = (uint32_t)r->ExceptionInformation[1];
        uint32_t base = guest_image_base();
        if (va >= base && va < base + guest_image_size() && dispatch_has(va)) {
            uint32_t thunk = thunk_for(va);
            if (thunk) {
                g_r2l_faults++;
                if (g_r2l_faults <= 8)
                    fprintf(stderr, "[r2l] real code called guest %08X directly "
                                    "(unthunked callback %u) - sending it "
                                    "through a thunk\n", va, g_r2l_faults);
                ep->ContextRecord->Eip = thunk;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    /* The address first, the trail after.
     *
     * Twenty-four lines of trail is long enough that a second thread faulting
     * mid-report, or the process being torn down, truncates the tail - and the
     * tail was where the address used to be. The trail can be reconstructed
     * from es3_trail.bin afterwards; the faulting address cannot. */
    {
        uint32_t owner = dispatch_owner(r->ExceptionAddress);
        fprintf(stderr, "\n=== the guest faulted: %08lX at host %p",
                (unsigned long)r->ExceptionCode, r->ExceptionAddress);
        if (owner)
            fprintf(stderr, ", inside guest %08X ===\n"
                            "    (the nearest lifted body at or below it - a"
                            " runtime helper reads as its caller)\n", owner);
        else
            fprintf(stderr, " - not in any lifted body ===\n");
        fflush(stderr);
    }

    if (r->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        r->NumberParameters >= 2) {
        uint32_t bad;
        es3_report_state("how it got there");
        bad = (uint32_t)r->ExceptionInformation[1];
        static const char *const how[] = { "read", "written", "?", "?",
                                           "?", "?", "?", "?", "executed" };
        ULONG_PTR k = r->ExceptionInformation[0];
        fprintf(stderr, "  %08X could not be %s   %s\n", bad,
                k < sizeof how / sizeof how[0] ? how[k] : "?", region_of(bad));

        /* The diagnosis this file exists for. */
        if (HLE_IS_ADDR(bad)) {
            HleId id = HLE_ID_OF(bad);
            fprintf(stderr,
                "\n  That address is the import sentinel for %s (%s).\n"
                "  Something reached it as a real function pointer rather than\n"
                "  through dispatch() - which is what happens when a forwarded\n"
                "  library function calls back into guest code: the original\n"
                "  bytes are still mapped, so the host runs the UNLIFTED\n"
                "  original, and its `call [__imp_...]` lands here.\n"
                "  The fix is pcrecomp's hybrid_thunk(). See CONTRIBUTING.\n",
                hle_name(id), hle_dll(id));
        }
    }
    fflush(stderr);
    return EXCEPTION_CONTINUE_SEARCH;   /* still die; a debugger still gets it */
}

void es3_install_crash_handler(void)
{
    static int done;
    if (done) return;
    done = 1;
    InitializeCriticalSection(&g_thunk_lock);
    g_thunk_lock_ready = 1;
    open_trail();
    AddVectoredExceptionHandler(1, es3_veh);
}

#else
void es3_install_crash_handler(void) { open_trail(); }
#endif
