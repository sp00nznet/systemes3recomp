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

/* ponytail: a 16-entry ring, written on every dispatch. It costs a store and a
 * mask per guest call, which does not show up next to the work a call does.
 * If it ever does, make it a build option rather than deleting it - the trail
 * is most of the value here. */
#define TRAIL 16
static uint32_t g_trail[TRAIL];
static unsigned g_trail_i;
static unsigned long g_dispatches;
static const CPU *g_cpu;

void es3_note_dispatch(uint32_t va)
{
    g_trail[g_trail_i++ & (TRAIL - 1)] = va;
    g_dispatches++;
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
    unsigned i;
    fprintf(stderr, "\n=== %s ===\n", why);
    fprintf(stderr, "  guest image at %#010x, %lu dispatches so far\n",
            guest_image_base(), g_dispatches);
    if (g_cpu) {
        const CPU *c = g_cpu;
        fprintf(stderr, "  eax=%08X ecx=%08X edx=%08X ebx=%08X\n",
                c->eax, c->ecx, c->edx, c->ebx);
        fprintf(stderr, "  esp=%08X ebp=%08X esi=%08X edi=%08X\n",
                c->esp, c->ebp, c->esi, c->edi);
    }
    fprintf(stderr, "  last %d dispatches (oldest first):\n", TRAIL);
    for (i = 0; i < TRAIL; i++) {
        uint32_t va = g_trail[(g_trail_i + i) & (TRAIL - 1)];
        if (!va) continue;
        if (HLE_IS_ADDR(va))
            fprintf(stderr, "    %08X  import %s (%s)\n", va,
                    hle_name(HLE_ID_OF(va)), hle_dll(HLE_ID_OF(va)));
        else
            fprintf(stderr, "    %08X  %s\n", va, region_of(va));
    }
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
    AddVectoredExceptionHandler(1, es3_veh);
}

#else
void es3_install_crash_handler(void) { }
#endif
