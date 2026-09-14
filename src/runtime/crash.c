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
#include <tlhelp32.h>
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

/* ES3_NO_TRAIL: stop recording, and find out what recording costs.
 *
 * The ring is two stores per guest call, which sounds free and is not: it is
 * two stores into an eight-megabyte MAPPED FILE, so the pages are dirty and
 * the operating system writes them back, for ever, at whatever rate the game
 * makes calls. This exists to measure that rather than argue about it. */
static int g_trail_off;
void es3_trail_init(void) { g_trail_off = getenv("ES3_NO_TRAIL") != NULL; }

void es3_note_dispatch(uint32_t va)
{
    unsigned i;
    if (g_trail_off) return;
    i = RING_COUNT;

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

/* The thread that ran main(), so a thread report can say which one it is. */
static unsigned long g_main_tid;

/* And the thread the guest's own call graph runs on - es3_enter_guest()
 * makes it, and it is the one a thread report is actually about. */
unsigned long g_guest_tid;

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

/*
 * Where every thread actually is, right now.
 *
 * The dispatch trail answers "what did guest code do", and for a game that has
 * stopped drawing that is the wrong question. A thread blocked inside real
 * Win32 - waiting on a message, on a semaphore, on a device that is not
 * plugged into this PC - dispatches nothing at all, so it does not appear in
 * the trail even once, and in a recompiled arcade title it is usually the
 * thread that matters. Mario Kart's primary thread is invisible for exactly
 * this reason while twenty worker threads poll Sleep(100) around it.
 *
 * Suspend each thread, read its Eip, name what it is in. An Eip inside this
 * runtime's own image means lifted code, and then the guest function is the
 * interesting half of the answer, so dispatch_owner() names that too.
 *
 * ES3_STALL=<seconds> prints it on that period, which is what a game that is
 * alive and drawing nothing calls for.
 */
#ifdef _WIN32
static const char *module_at(uint32_t eip, int *ours, uint32_t *base)
{
    static char name[80];
    static wchar_t w[MAX_PATH];
    MEMORY_BASIC_INFORMATION mi;
    const wchar_t *leaf;

    *ours = 0;
    *base = 0;
    if (!VirtualQuery((LPCVOID)(uintptr_t)eip, &mi, sizeof mi)) return "?";
    if (mi.Type != MEM_IMAGE)
        return mi.State == MEM_COMMIT ? "private code" : "unmapped";
    *base = (uint32_t)(uintptr_t)mi.AllocationBase;
    if (mi.AllocationBase == (void *)GetModuleHandleW(NULL)) *ours = 1;
    if (!GetModuleFileNameW((HMODULE)mi.AllocationBase, w, MAX_PATH))
        return "an image";
    leaf = wcsrchr(w, L'\\');
    WideCharToMultiByte(CP_ACP, 0, leaf ? leaf + 1 : w, -1,
                        name, sizeof name, NULL, NULL);
    return name;
}

/* The last thing a given thread asked for, from the ring.
 *
 * A thread parked in ntdll is waiting, and "ntdll.dll" is the same answer for
 * every one of them. What separates them is the guest call they were in when
 * they went to sleep, and the trail has it - so walk backwards to this
 * thread's most recent entry. Bounded by the ring: a thread that has not
 * dispatched in a million calls has nothing to say anyway.
 */
static uint32_t last_va_on(unsigned long tid, uint32_t *import_va)
{
    unsigned total = RING_COUNT, i, n = total < TRAIL ? total : TRAIL;
    *import_va = 0;
    for (i = 0; i < n; i++) {
        unsigned k = total - 1 - i;
        if (RING_TID(k) != (uint32_t)tid) continue;
        if (HLE_IS_ADDR(RING_VA(k))) {
            if (!*import_va) *import_va = RING_VA(k);
            continue;
        }
        return RING_VA(k);
    }
    return 0;
}

/* ES3_PEEK=959b0c,**959b64+3c - guest state, printed with every thread report.
 *
 * A recompiled game keeps its state where the original kept it, so an address
 * out of the disassembly is still the right address at run time, and reading
 * one is usually cheaper than working out which lifted function to instrument.
 *
 * The stars are the point. Game state is rarely a global - it is a global
 * holding a pointer to an object holding a pointer to the thing you want, and
 * `mov eax,[0x959b64]; mov edi,[eax]; cmp ...[edi+0x3c]` is what the
 * disassembly actually says. So an entry is some number of dereferences, an
 * address, and an offset: `**959b64+3c` is exactly that line, and prints the
 * eight words there.
 */
#define PEEK_MAX 8
#define PEEK_OPS 8
/* An entry is an address followed by a little program: '*' dereferences,
 * '+hex' adds. Leading stars are the old spelling and still mean the same
 * thing, so `**959b64+3c` reads as it always did; `95a86c*+8*` is "load the
 * pointer, step to the array field, follow it" - which is the shape almost
 * every piece of game state actually has. */
static struct {
    uint32_t addr;
    unsigned nops;
    struct { char op; uint32_t arg; } ops[PEEK_OPS];
} g_peek[PEEK_MAX];
static unsigned g_npeek;
static int g_peek_read;

static void peek_init(void)
{
    const char *e = getenv("ES3_PEEK");
    g_peek_read = 1;
    while (e && *e && g_npeek < PEEK_MAX) {
        unsigned stars = 0, n = 0;
        char *end;
        unsigned long v;
        while (*e == '*') { stars++; e++; }
        v = strtoul(e, &end, 16);
        if (end == e) break;
        g_peek[g_npeek].addr = (uint32_t)v;
        e = end;
        while (stars-- && n < PEEK_OPS) g_peek[g_npeek].ops[n++].op = '*';
        while (*e && *e != ',' && n < PEEK_OPS) {
            if (*e == '*') { g_peek[g_npeek].ops[n].op = '*'; n++; e++; }
            else if (*e == '+') {
                g_peek[g_npeek].ops[n].op = '+';
                g_peek[g_npeek].ops[n].arg = (uint32_t)strtoul(e + 1, &end, 16);
                n++; e = end;
            } else break;
        }
        g_peek[g_npeek].nops = n;
        g_npeek++;
        if (*e == ',') e++;
    }
}

/* Without IsBadReadPtr, which probes by faulting: every call raises a
 * first-chance access violation, the vectored handler prints it, and the
 * diagnostic fills the log with reports of itself. */
static int readable(uint32_t a, size_t n)
{
    MEMORY_BASIC_INFORMATION mi;
    if (!a || !VirtualQuery((LPCVOID)(uintptr_t)a, &mi, sizeof mi)) return 0;
    if (mi.State != MEM_COMMIT) return 0;
    if (mi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return 0;
    return a + n <= (uint32_t)(uintptr_t)mi.BaseAddress + (uint32_t)mi.RegionSize;
}

static void report_peeks(void)
{
    unsigned k, j, o;
    if (!g_peek_read) peek_init();
    for (k = 0; k < g_npeek; k++) {
        uint32_t v = g_peek[k].addr;
        int bad = 0;
        for (o = 0; o < g_peek[k].nops && !bad; o++) {
            if (g_peek[k].ops[o].op == '+') { v += g_peek[k].ops[o].arg; continue; }
            if (!readable(v, 4)) { bad = 1; break; }
            v = *(const uint32_t *)(uintptr_t)v;
        }
        if (bad || !readable(v, 32)) {
            fprintf(stderr, "  peek %08X: unreadable\n", g_peek[k].addr);
            continue;
        }
        fprintf(stderr, "  peek %08X -> %08X:", g_peek[k].addr, v);
        for (j = 0; j < 8; j++)
            fprintf(stderr, " %08X", ((const uint32_t *)(uintptr_t)v)[j]);
        fprintf(stderr, "\n");
    }
}

void es3_report_threads(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te;
    DWORD me = GetCurrentThreadId(), pid = GetCurrentProcessId();
    unsigned n = 0;
    BOOL ok;

    if (snap == INVALID_HANDLE_VALUE) return;
    te.dwSize = sizeof te;
    fprintf(stderr, "\n=== where every thread is, %u dispatches in ===\n",
            es3_dispatch_count());
    for (ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
        HANDLE h;
        CONTEXT ctx;
        if (te.th32OwnerProcessID != pid || te.th32ThreadID == me) continue;
        h = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE,
                       te.th32ThreadID);
        if (!h) continue;
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (SuspendThread(h) != (DWORD)-1) {
            if (GetThreadContext(h, &ctx)) {
                int ours = 0;
                uint32_t mbase = 0;
                const char *mod = module_at((uint32_t)ctx.Eip, &ours, &mbase);
                n++;
                /* Resume before printing: fprintf takes a lock the suspended
                 * thread may be holding, and deadlocking the diagnostic is a
                 * poor way to diagnose a hang. */
                ResumeThread(h);
                CloseHandle(h);
                {
                    uint32_t imp = 0, last = last_va_on(te.th32ThreadID, &imp);
                    const char *tag =
                        te.th32ThreadID == g_guest_tid ? "  <- the guest" :
                        te.th32ThreadID == g_main_tid  ? "  <- host main" : "";
                    /* The host Eip as well as the guess. dispatch_owner() is
                     * the nearest lifted body at or below an address, so a
                     * thread inside a runtime helper - or inside a lifted
                     * function the linker placed after that helper - reads as
                     * whichever body sorts below it, which is not the same
                     * claim. Sampling the raw address twice says more than
                     * trusting the name once. */
                    if (ours)
                        fprintf(stderr, "  t%-6lu running   %08lX  near lifted "
                                        "%08X%s\n",
                                te.th32ThreadID, ctx.Eip,
                                dispatch_owner((const void *)(uintptr_t)ctx.Eip),
                                tag);
                    /* module+offset, not just the module. "ntdll.dll" is the
                     * same answer for every parked thread; the offset is what
                     * a map of that DLL's exports turns into a name. */
                    else if (imp)
                        fprintf(stderr, "  t%-6lu in %s+0x%-6X waiting in %s, "
                                        "last guest %08X%s\n",
                                te.th32ThreadID, mod,
                                (unsigned)((uint32_t)ctx.Eip - mbase),
                                hle_name(HLE_ID_OF(imp)), last, tag);
                    else
                        fprintf(stderr, "  t%-6lu in %s+0x%-6X last guest "
                                        "%08X%s\n",
                                te.th32ThreadID, mod,
                                (unsigned)((uint32_t)ctx.Eip - mbase),
                                last, tag);
                }
                continue;
            }
            ResumeThread(h);
        }
        CloseHandle(h);
    }
    CloseHandle(snap);
    fprintf(stderr, "  %u thread(s)\n", n);
    report_peeks();
    fflush(stderr);
}
#else
void es3_report_threads(void) {}
#endif

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

        /*
         * The one exception that has to be caught, checked where it is raised.
         *
         * OutputDebugString raises 0x40010006 and catches it in its own __try,
         * and Windows only offers a handler the frame it is registered from
         * lies between this thread's StackLimit and StackBase. Lifted code does
         * not run on the stack the TEB describes, so es3_teb_cover() widens the
         * bounds on every thread that crosses into it - and a thread that was
         * missed does not fail visibly. It raises, nobody is eligible, and the
         * process ends with 0x40010006 as its exit code and nothing in the log.
         *
         * So say it here, where both halves are in hand. Once per thread.
         */
        if (r->ExceptionCode == 0x40010006u) {
            uint32_t lo = __readfsdword(0x08), hi = __readfsdword(0x04);
            uint32_t sp = ep->ContextRecord->Esp;
            if (sp < lo || sp >= hi) {
                static volatile LONG told[16];
                LONG self = (LONG)GetCurrentThreadId();
                int k;
                for (k = 0; k < 16; k++) {
                    if (told[k] == self) break;
                    if (!told[k] &&
                        InterlockedCompareExchange(&told[k], self, 0) == 0) {
                        fprintf(stderr,
                            "\n[seh] thread %lu raised OutputDebugString's "
                            "exception with esp=%08X, and its TEB says the "
                            "stack is %08X..%08X.\n"
                            "      No handler on it can be eligible, so this "
                            "one goes unhandled and ends the process with "
                            "exit code 40010006.\n"
                            "      Something entered lifted code on this thread "
                            "without es3_teb_cover().\n",
                            GetCurrentThreadId(), sp, lo, hi);
                        fflush(stderr);
                        break;
                    }
                }
            }
        }

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
    g_main_tid = GetCurrentThreadId();
    es3_trail_init();
    dispatch_build_index();
    es3_stack_trace_init();
    es3_trace_from_init();
    InitializeCriticalSection(&g_thunk_lock);
    g_thunk_lock_ready = 1;
    open_trail();
    AddVectoredExceptionHandler(1, es3_veh);
}

#else
void es3_install_crash_handler(void) { open_trail(); }
#endif
