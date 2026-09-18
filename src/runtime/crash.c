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

/* The range the watched addresses span, so DCALL can decline in two compares.
 * A direct call does not go through dispatch() - the driver rewrites 146,736
 * of them - so without this a watch on a function the game calls directly is
 * silently never reported, which reads as "it never ran". */
uint32_t es3_watch_lo = 0xFFFFFFFFu, es3_watch_hi = 0;

/* Said on the way in and on the way out, by both callers - dispatch() and
 * DCALL - so a watch reads the same whichever way the call arrived. */
void es3_watch_enter(CPU *c, uint32_t va)
{
    fprintf(stderr, "[watch] %08X entered from %08X (thread %lu, dispatch %u)\n",
            va, rd32(c->esp), GetCurrentThreadId(), es3_dispatch_count());
}

void es3_watch_leave(CPU *c, uint32_t va, uint32_t from)
{
    fprintf(stderr, "[watch] %08X returned %08X to %08X (thread %lu, "
                    "dispatch %u)\n", va, c->eax, from, GetCurrentThreadId(),
            es3_dispatch_count());
}

static void watch_va_init(void)
{
    const char *s = getenv("ES3_WATCH_VA");
    unsigned k;
    g_watch_read = 1;
    while (s && *s && g_nwatch < 8) {
        char *end;
        unsigned long v = strtoul(s, &end, 16);
        if (end == s) break;
        g_watch_va[g_nwatch++] = (uint32_t)v;
        s = *end == ',' ? end + 1 : end;
    }
    for (k = 0; k < g_nwatch; k++) {
        if (g_watch_va[k] < es3_watch_lo) es3_watch_lo = g_watch_va[k];
        if (g_watch_va[k] > es3_watch_hi) es3_watch_hi = g_watch_va[k];
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
void es3_trail_init(void)
{
    g_trail_off = getenv("ES3_NO_TRAIL") != NULL;
    /* Eagerly, so DCALL's range test is armed before the first
     * direct call rather than after the first dispatch. */
    if (!g_watch_read) watch_va_init();
}

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

/* One entry's little program: leading stars, an address, then `*` and `+hex`
 * in written order. Returns where it stopped, or NULL if there was no
 * address there at all. Shared with ES3_POKE. */
static const char *chain(const char *e, uint32_t *addr, unsigned *nops,
                         struct { char op; uint32_t arg; } *ops)
{
    unsigned stars = 0, n = 0;
    char *end;
    unsigned long v;

    while (*e == '*') { stars++; e++; }
    v = strtoul(e, &end, 16);
    if (end == e) return NULL;
    *addr = (uint32_t)v;
    e = end;
    while (stars-- && n < PEEK_OPS) ops[n++].op = '*';
    while (*e && *e != ',' && *e != '=' && n < PEEK_OPS) {
        if (*e == '*') { ops[n].op = '*'; n++; e++; }
        else if (*e == '+') {
            ops[n].op = '+';
            ops[n].arg = (uint32_t)strtoul(e + 1, &end, 16);
            n++; e = end;
        } else break;
    }
    *nops = n;
    return e;
}

static void peek_init(void)
{
    const char *e = getenv("ES3_PEEK");
    g_peek_read = 1;
    while (e && *e && g_npeek < PEEK_MAX) {
        e = chain(e, &g_peek[g_npeek].addr, &g_peek[g_npeek].nops,
                  g_peek[g_npeek].ops);
        if (!e) break;
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

/* ES3_POKE=9595c0=2 - write a guest value, every thread report.
 *
 * The other half of ES3_PEEK, and it earns its place on the same question:
 * when a boot stalls waiting for a piece of hardware, the cheapest way to find
 * out whether THAT is what it is waiting for is to write the value the
 * hardware would have produced and watch what happens next. It is not a fix -
 * a fix emulates the device - it is the experiment that says whether the
 * device is worth emulating.
 *
 * Same chain syntax, then `=value`. Rewritten on every report, because the
 * game writes its own value back.
 */
/*
 * Widths, because a dword is the wrong tool for a flag.
 *
 * Several of this game's decisions are single bytes with live neighbours -
 * the one that puts it online is [[0x959B1C]+3], and 0x00952914 sits next to
 * two more flags the game reads - so writing four bytes to set one corrupts
 * the other three. `:b` and `:w` say how much to write; the default stays a
 * dword, which is what every existing ES3_POKE expects.
 *
 *   ES3_POKE=959b1c*+3:b=1     one byte, through a pointer
 */
#define POKE_MAX 8
static struct {
    uint32_t addr, value;
    unsigned nops;
    unsigned width;                  /* 1, 2 or 4 bytes */
    struct { char op; uint32_t arg; } ops[PEEK_OPS];
} g_poke[POKE_MAX];
static unsigned g_npoke;
static int g_poke_read;

static void poke_init(void)
{
    const char *e = getenv("ES3_POKE");
    char *end;
    g_poke_read = 1;
    while (e && *e && g_npoke < POKE_MAX) {
        e = chain(e, &g_poke[g_npoke].addr, &g_poke[g_npoke].nops,
                  g_poke[g_npoke].ops);
        if (!e) break;
        g_poke[g_npoke].width = 4;
        if (*e == ':') {
            if (e[1] == 'b' || e[1] == 'B')      g_poke[g_npoke].width = 1;
            else if (e[1] == 'w' || e[1] == 'W') g_poke[g_npoke].width = 2;
            else break;
            e += 2;
        }
        if (*e != '=') break;
        g_poke[g_npoke].value = (uint32_t)strtoul(e + 1, &end, 16);
        e = end;
        g_npoke++;
        if (*e == ',') e++;
    }
    if (g_npoke)
        fprintf(stderr, "[poke] holding %u guest value(s) down\n", g_npoke);
}

void es3_apply_pokes(void)
{
    unsigned k, o;
    if (!g_poke_read) poke_init();
    for (k = 0; k < g_npoke; k++) {
        uint32_t v = g_poke[k].addr;
        int bad = 0;
        for (o = 0; o < g_poke[k].nops && !bad; o++) {
            if (g_poke[k].ops[o].op == '+') { v += g_poke[k].ops[o].arg; continue; }
            if (!readable(v, 4)) { bad = 1; break; }
            v = *(const uint32_t *)(uintptr_t)v;
        }
        {
            unsigned w = g_poke[k].width ? g_poke[k].width : 4;
            if (bad || !readable(v, w)) continue;
            if (w == 1)      *(uint8_t  *)(uintptr_t)v = (uint8_t)g_poke[k].value;
            else if (w == 2) *(uint16_t *)(uintptr_t)v = (uint16_t)g_poke[k].value;
            else             *(uint32_t *)(uintptr_t)v = g_poke[k].value;
        }
    }
}

/* Not folded into the thread report any more: suspending a hundred threads
 * and naming each one takes long enough that the peeks rode a cadence of
 * minutes, and a peek is wanted while the game is RUNNING, which is exactly
 * when a stall report is not due. The watchdog calls this on its own. */
void es3_report_peeks(void)
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
    es3_apply_pokes();
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

int es3_watch_mem_hit(EXCEPTION_POINTERS *ep);

static LONG WINAPI es3_veh(EXCEPTION_POINTERS *ep)
{
    const EXCEPTION_RECORD *r = ep->ExceptionRecord;

    /* First, because a debug register fires constantly once armed and the
     * rest of this handler has nothing to say about it. */
    if (es3_watch_mem_hit(ep)) return EXCEPTION_CONTINUE_EXECUTION;

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

        /*
         * And then swallow it, rather than hoping something else will.
         *
         * 0x40010006 and its wide twin 0x4001000A exist for one purpose: to
         * hand a string to a debugger. There is no debugger here, the
         * exception is informational and continuable, and the only thing
         * OutputDebugString's own __try does with it is continue - so doing
         * that here is not a workaround, it is the same answer one frame
         * earlier. What it removes is the failure where nothing is eligible to
         * catch it: no eligible handler on an informational exception is not a
         * bug that reports itself, it is a process that exits with 0x40010006
         * and a log that stops mid-sentence. Through MSYS that arrives as
         * "exit 6" - a number belonging to nothing in the source, which was
         * chased as one for most of a week before the exit code was read in
         * full.
         *
         * The thread-name exception above is already treated exactly this way,
         * for exactly this reason.
         */
        if (r->ExceptionCode == 0x40010006u || r->ExceptionCode == 0x4001000Au)
            return EXCEPTION_CONTINUE_EXECUTION;

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

                /*
                 * A stack overflow is nobody's to catch.
                 *
                 * Declining STATUS_STACK_OVERFLOW is declining to say anything
                 * about the one exception a guest almost never handles: the
                 * search finds no handler, ntdll ends the process, and the log
                 * stops on a single line that names an address and nothing
                 * else. That is how a thirty-minute run died unattended with
                 * no idea what had been recursing.
                 *
                 * Lifted code carries the whole guest call graph on the real
                 * stack - one C frame per guest function plus dispatch between
                 * them - so an overflow here means runaway recursion in the
                 * game, and the dispatch trail is a list of what it was going
                 * round. Print it while there is still stack to print it with;
                 * the guard page gives us the room SetThreadStackGuarantee
                 * reserved, and we are still declining afterwards, so nothing
                 * about who handles it changes.
                 */
                if (r->ExceptionCode == 0xC00000FDu) {
                    fprintf(stderr, "[seh] that is a stack overflow, and a "
                                    "guest does not catch those - the process "
                                    "is about to end. Lifted code carries the "
                                    "guest call graph on the real stack, so "
                                    "this is runaway recursion in the game:\n");
                    es3_report_state("what it was recursing through");
                }
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

/*
 * The last door, and the only one that was never watched.
 *
 * This file installs a vectored handler, which sees an exception first - and a
 * vectored handler that declines passes the fault to the frame handlers and
 * then to the unhandled-exception filter. That filter is where a program gets
 * to end itself on its own terms, and this runtime forwards the guest's
 * SetUnhandledExceptionFilter straight through to the real one (see
 * hle_callback.c), so whatever the game installed is what runs there - and
 * whatever it then does, it does out of sight.
 *
 * So take the filter first and chain to whoever had it. On a run that never
 * faults this costs nothing; on a run that ends with an exit code belonging to
 * nothing in the source it is the difference between a name and another week.
 */
static LPTOP_LEVEL_EXCEPTION_FILTER g_prev_filter;

static LONG WINAPI es3_last_filter(EXCEPTION_POINTERS *ep)
{
    EXCEPTION_RECORD *r = ep ? ep->ExceptionRecord : NULL;
    fprintf(stderr, "\n[exit] nobody handled %08lX at %p (thread %lu, "
                    "dispatch %u) - this is the unhandled-exception filter\n",
            r ? (unsigned long)r->ExceptionCode : 0ul,
            r ? r->ExceptionAddress : NULL,
            GetCurrentThreadId(), es3_dispatch_count());
    es3_report_state("nobody handled it");
    fflush(stderr);
    if (g_prev_filter) return g_prev_filter(ep);
    return EXCEPTION_CONTINUE_SEARCH;
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
    g_prev_filter = SetUnhandledExceptionFilter(es3_last_filter);
    es3_watch_exit();
}

#else
void es3_install_crash_handler(void) { open_trail(); }
#endif

#ifdef _WIN32
/*
 * ES3_WATCH_MEM - a hardware watchpoint on a guest address, named by chain.
 *
 * `who writes this` is the question every one of these boot gates comes down
 * to, and neither of the other two tools answers it: the trail says which
 * functions ran, ES3_PEEK says what the value became. A debug register says
 * which instruction, and dispatch_owner() turns the host address back into
 * the lifted guest function it belongs to.
 *
 *   ES3_WATCH_MEM="959b64**+3c"
 *
 * The address is resolved the same way ES3_PEEK resolves one, which matters
 * because the interesting words are all behind two pointers into the heap and
 * are at a different address every run. It arms once the chain resolves, and
 * re-arms every few seconds so threads started later are covered too.
 *
 * DR0 only, four bytes, break on write. One watch is all this has needed.
 */
static uint32_t g_wm_addr;                  /* resolved, or 0 */
static int g_wm_read;
static struct { uint32_t addr; unsigned nops;
                struct { char op; uint32_t arg; } ops[PEEK_OPS]; } g_wm;

static uint32_t wm_resolve(void)
{
    uint32_t v = g_wm.addr;
    unsigned o;
    for (o = 0; o < g_wm.nops; o++) {
        if (g_wm.ops[o].op == '+') { v += g_wm.ops[o].arg; continue; }
        if (!readable(v, 4)) return 0;
        v = rd32(v);
    }
    return readable(v, 4) ? v : 0;
}

/* DR7: L0 enables DR0; bits 16-17 are the condition (01 = write) and 18-19
 * the length (11 = four bytes). */
#define DR7_ARM ((1u << 0) | (1u << 16) | (3u << 18))

static void wm_arm_thread(DWORD tid, uint32_t addr)
{
    HANDLE h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                          THREAD_SUSPEND_RESUME, FALSE, tid);
    CONTEXT ctx;
    if (!h) return;
    if (SuspendThread(h) != (DWORD)-1) {
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(h, &ctx) && ctx.Dr0 != addr) {
            ctx.Dr0 = addr;
            ctx.Dr7 = (ctx.Dr7 & ~0xFFFFFu) | DR7_ARM;
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            SetThreadContext(h, &ctx);
        }
        ResumeThread(h);
    }
    CloseHandle(h);
}

/* Called from the peek thread, which already wakes on a timer. */
void es3_watch_mem_tick(void)
{
    HANDLE snap;
    THREADENTRY32 te;
    DWORD me = GetCurrentThreadId(), pid = GetCurrentProcessId();
    BOOL ok;
    uint32_t addr;

    if (!g_wm_read) {
        const char *e = getenv("ES3_WATCH_MEM");
        g_wm_read = 1;
        if (!e || !chain(e, &g_wm.addr, &g_wm.nops, g_wm.ops)) g_wm.nops = 0xFFFF;
    }
    if (g_wm.nops == 0xFFFF) return;

    addr = wm_resolve();
    if (!addr) return;
    if (addr != g_wm_addr) {
        g_wm_addr = addr;
        fprintf(stderr, "[watchmem] watching %08X for writes\n", addr);
    }

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    te.dwSize = sizeof te;
    for (ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te))
        if (te.th32OwnerProcessID == pid && te.th32ThreadID != me)
            wm_arm_thread(te.th32ThreadID, addr);
    CloseHandle(snap);
}

/* From the vectored handler. Returns 1 if this was our watchpoint. */
int es3_watch_mem_hit(EXCEPTION_POINTERS *ep)
{
    uint32_t eip;
    if (!g_wm_addr) return 0;
    if (ep->ExceptionRecord->ExceptionCode != (DWORD)EXCEPTION_SINGLE_STEP)
        return 0;
    if (!(ep->ContextRecord->Dr6 & 1u)) return 0;
    eip = (uint32_t)ep->ContextRecord->Eip;
    fprintf(stderr, "[watchmem] %08X written at host %08X, in lifted %08X "
                    "(thread %lu); it now reads %08X\n",
            g_wm_addr, eip, dispatch_owner((const void *)(uintptr_t)eip),
            GetCurrentThreadId(), rd32(g_wm_addr));
    fflush(stderr);
    ep->ContextRecord->Dr6 = 0;
    return 1;
}
#else
void es3_watch_mem_tick(void) {}
#endif

#ifdef _WIN32
/*
 * Who called ExitProcess, and with what.
 *
 * The TLS callback in the game's host.c names the thread at
 * DLL_PROCESS_DETACH, and the import handlers catch every exit path the guest
 * imports - exit, _exit, abort, TerminateProcess. Mario Kart's boot walks
 * past all of them: it ends with code 6, silently, having logged nothing, and
 * the dispatch trail's last entries are a worker thread going to sleep.
 *
 * That leaves a call into the real kernel32 from inside a forwarded library,
 * which no IAT handler can see. So patch kernel32!ExitProcess itself. No
 * trampoline is needed and none is written: ExitProcess does not return, so
 * the replacement is free to say what it knows and end the process itself.
 *
 * Five bytes of `jmp rel32`, which is the whole hook on x86. If the first
 * instruction is not at least five bytes this would corrupt the second one -
 * it is `mov edi, edi; push ebp; mov ebp, esp` on every Windows this runs on,
 * which is seven, and the code checks anyway.
 */
/* The raw syscall stub, which nothing here patches - both replacements end
 * through it so they cannot call back into each other. */
static LONG (WINAPI *g_nt_terminate)(HANDLE, LONG);

static void WINAPI es3_exit_process(UINT code)
{
    void *from = _ReturnAddress();
    int ours = 0;
    uint32_t base = 0;
    const char *mod = module_at((uint32_t)(uintptr_t)from, &ours, &base);

    fprintf(stderr, "\n[exit] ExitProcess(%u) from %p", code, from);
    if (mod) fprintf(stderr, ", in %s+0x%X", mod, (unsigned)((uint32_t)(uintptr_t)from - base));
    if (ours)
        fprintf(stderr, " - lifted %08X",
                dispatch_owner(from));
    fprintf(stderr, " (thread %lu, dispatch %u)\n",
            GetCurrentThreadId(), es3_dispatch_count());
    es3_report_state("who ended it");
    fflush(stderr);
    g_nt_terminate(GetCurrentProcess(), (LONG)code);
    for (;;) { }                      /* not reached; keeps the compiler calm */
}

static BOOL WINAPI es3_terminate_process(HANDLE proc, UINT code)
{
    void *from = _ReturnAddress();
    int ours = 0;
    uint32_t base = 0;
    const char *mod = module_at((uint32_t)(uintptr_t)from, &ours, &base);

    fprintf(stderr, "\n[exit] TerminateProcess(%p, %u) from %p",
            (void *)proc, code, from);
    if (mod) fprintf(stderr, ", in %s+0x%X", mod,
                     (unsigned)((uint32_t)(uintptr_t)from - base));
    if (ours) fprintf(stderr, " - lifted %08X", dispatch_owner(from));
    fprintf(stderr, " (thread %lu, dispatch %u)\n",
            GetCurrentThreadId(), es3_dispatch_count());
    if (proc == GetCurrentProcess()) es3_report_state("who ended it");
    fflush(stderr);
    return g_nt_terminate(proc, (LONG)code) >= 0;
}

/* The last door. ExitProcess and TerminateProcess both funnel here, and so
 * does anything that skips them - which is what this boot does.
 *
 * A trampoline IS needed this time, because unlike the two above this one can
 * be called for another process and return. An x86 ntdll syscall stub begins
 * `mov eax, imm32`, which is exactly five bytes, so copying five and jumping
 * back lands on an instruction boundary. Checked rather than assumed: if the
 * first byte is not 0xB8 the hook is not installed. */
static LONG (WINAPI *g_nt_terminate_tramp)(HANDLE, LONG);

static LONG WINAPI es3_nt_terminate(HANDLE proc, LONG code)
{
    void *from = _ReturnAddress();
    int ours = 0;
    uint32_t base = 0;
    const char *mod = module_at((uint32_t)(uintptr_t)from, &ours, &base);

    fprintf(stderr, "\n[exit] NtTerminateProcess(%p, %ld) from %p",
            (void *)proc, code, from);
    if (mod) fprintf(stderr, ", in %s+0x%X", mod,
                     (unsigned)((uint32_t)(uintptr_t)from - base));
    if (ours) fprintf(stderr, " - lifted %08X", dispatch_owner(from));
    fprintf(stderr, " (thread %lu, dispatch %u)\n",
            GetCurrentThreadId(), es3_dispatch_count());
    fflush(stderr);
    return g_nt_terminate_tramp(proc, code);
}

static void hook_nt_terminate(void)
{
    unsigned char *p = (unsigned char *)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtTerminateProcess");
    unsigned char *tramp;
    DWORD old;
    intptr_t rel;

    if (!p || p[0] != 0xB8) {                 /* not the stub shape expected */
        fprintf(stderr, "[exit] ntdll!NtTerminateProcess at %p starts %02X, "
                        "not B8 - not hooking it\n",
                (void *)p, p ? p[0] : 0);
        return;
    }
    tramp = (unsigned char *)VirtualAlloc(NULL, 16, MEM_COMMIT | MEM_RESERVE,
                                          PAGE_EXECUTE_READWRITE);
    if (!tramp) return;
    memcpy(tramp, p, 5);
    tramp[5] = 0xE9;
    rel = (intptr_t)(p + 5) - (intptr_t)(tramp + 10);
    memcpy(tramp + 6, &rel, 4);
    g_nt_terminate_tramp = (LONG (WINAPI *)(HANDLE, LONG))tramp;

    if (!VirtualProtect(p, 5, PAGE_EXECUTE_READWRITE, &old)) return;
    rel = (intptr_t)es3_nt_terminate - (intptr_t)(p + 5);
    p[0] = 0xE9;
    memcpy(p + 1, &rel, 4);
    VirtualProtect(p, 5, old, &old);
}

void es3_watch_exit(void)
{
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    unsigned char *p;
    DWORD old;
    intptr_t rel;

    if (!k32 || getenv("ES3_NO_EXIT_HOOK")) return;
    p = (unsigned char *)GetProcAddress(k32, "ExitProcess");
    g_nt_terminate = (LONG (WINAPI *)(HANDLE, LONG))
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtTerminateProcess");
    if (!p || !g_nt_terminate) return;
    if (!VirtualProtect(p, 5, PAGE_EXECUTE_READWRITE, &old)) return;
    rel = (intptr_t)es3_exit_process - (intptr_t)(p + 5);
    p[0] = 0xE9;
    memcpy(p + 1, &rel, 4);
    VirtualProtect(p, 5, old, &old);
    /* And TerminateProcess, which is the other way out and the one a watchdog
     * reaches for. This boot leaves through neither `exit` nor
     * `TerminateProcess` as the GUEST imports them - both are bound to
     * hle_give_up and both stay quiet - and not through kernel32!ExitProcess
     * either, so the call is coming from a forwarded library and this is the
     * remaining door. */
    p = (unsigned char *)GetProcAddress(k32, "TerminateProcess");
    if (p && VirtualProtect(p, 5, PAGE_EXECUTE_READWRITE, &old)) {
        rel = (intptr_t)es3_terminate_process - (intptr_t)(p + 5);
        p[0] = 0xE9;
        memcpy(p + 1, &rel, 4);
        VirtualProtect(p, 5, old, &old);
    }

    hook_nt_terminate();

    /* With the addresses, because "watching" was printed for two runs during
     * which nothing was in fact watched: the addresses say which module the
     * forwarder landed in and make the claim checkable. */
    fprintf(stderr, "[exit] watching ExitProcess %p, TerminateProcess %p, "
                    "NtTerminateProcess %p (%sinstalled)"
                    " (ES3_NO_EXIT_HOOK to leave them alone)\n",
            (void *)GetProcAddress(k32, "ExitProcess"),
            (void *)GetProcAddress(k32, "TerminateProcess"),
            (void *)g_nt_terminate, g_nt_terminate_tramp ? "" : "NOT ");
}
#else
void es3_watch_exit(void) {}
#endif
