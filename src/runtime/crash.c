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
#define TRAIL 4096
static uint32_t  g_fallback[2 * TRAIL + 2];
static uint32_t *g_ring = g_fallback;     /* [0]=count, [1]=stride, then pairs */
static const CPU *g_cpu;

#define RING_COUNT  g_ring[0]
#define RING_TID(i) g_ring[2 + 2 * ((i) & (TRAIL - 1))]
#define RING_VA(i)  g_ring[3 + 2 * ((i) & (TRAIL - 1))]

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

static LONG WINAPI es3_veh(EXCEPTION_POINTERS *ep)
{
    const EXCEPTION_RECORD *r = ep->ExceptionRecord;
    if (r->ExceptionCode != EXCEPTION_ACCESS_VIOLATION &&
        r->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION &&
        r->ExceptionCode != EXCEPTION_PRIV_INSTRUCTION)
        return EXCEPTION_CONTINUE_SEARCH;

    es3_report_state("the guest faulted");
    fprintf(stderr, "  code   %08lX at host %p\n",
            (unsigned long)r->ExceptionCode, r->ExceptionAddress);

    if (r->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
        r->NumberParameters >= 2) {
        uint32_t bad = (uint32_t)r->ExceptionInformation[1];
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
    open_trail();
    AddVectoredExceptionHandler(1, es3_veh);
}

#else
void es3_install_crash_handler(void) { open_trail(); }
#endif
