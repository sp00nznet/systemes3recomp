/*
 * hle_callback.c - the imports that take a pointer to guest code.
 *
 * Forwarding an import to the host's own DLL is right until the import is
 * handed a function pointer. Then the real library calls that address as
 * machine code - and the original bytes are still mapped there, so the host
 * runs the *unlifted* original, whose `call [__imp_...]` reads an IAT slot
 * full of runtime sentinels and jumps into nothing. That is where the first
 * full boot of Mario Kart stopped, 18 guest calls in, at `_initterm_e`.
 *
 * There are two ways across, and this file uses both, because they are good at
 * different things.
 *
 * **Walk it ourselves.** `_initterm` and `_initterm_e` are four lines of C
 * each with a contract that has not changed since the 1990s: march a pointer
 * from begin to end and call every non-null entry. Reimplementing that and
 * dispatching each entry as guest code is exact - no heuristics, no address
 * that might or might not be a function - and it is the whole fix for the CRT
 * startup path. Prefer this whenever the contract is small and known.
 *
 * **Hand out a thunk.** For everything else - a window procedure, a `qsort`
 * comparator, an exception filter, anything stored now and called later by
 * code we do not control - the pointer has to survive on its own. pcrecomp's
 * `hybrid_thunk()` mints a real address that lands back in lifted code, and
 * `dispatch()` knows how to turn one back into a guest VA when lifted code
 * reads the same slot. `es3_callback()` is the wrapper.
 *
 * Bound after hle_register_native(), so these override the forwarded versions.
 */

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include "es3_rt.h"
#include "hybrid.h"

/* A return address for a guest call this runtime makes itself. A lifted `ret`
 * pops the slot without reading it, so the value only has to be recognisable
 * if it ever turns up in a crash report. */
#define CALLBACK_RETURN 0xE5FFFF00u

/* Real code has called a thunk; run the lifted function behind it.
 *
 * hybrid has already built an emulated frame on its private arena with the
 * real caller's arguments copied above a fake return slot, and seeded the
 * callee-saved registers. All this does is put that into a CPU, dispatch, and
 * report two things back: the result, and how many argument bytes the callee
 * cleaned - which is what lets the trampoline return __stdcall- and
 * __thiscall-correctly without knowing the convention in advance. The lifter's
 * `ret N` is the only thing that knows, and it says so by where it leaves esp.
 */
uint64_t es3_hybrid_invoke(uint32_t ova, hybrid_regs *r, uint32_t *real_args)
{
    CPU c;
    uint32_t esp0 = r->esp;
    uint32_t cleaned;

#ifdef _WIN32
    /* This thread is about to run lifted code on hybrid's arena, which its TEB
     * has never heard of - so any `__try` the guest sets up would be rejected
     * as out of stack range. Two reads and usually no writes, so it costs less
     * than tracking which threads have already been covered.
     *
     * Mario Kart's engine startup makes eight threads and every one of them
     * crosses, which is also worth saying out loud once each: "how many
     * threads are in lifted code" is the first question when something races,
     * and the lifted->real direction is still single-threaded (hybrid RULE 4). */
    es3_teb_cover(r->esp - (1u << 20), r->esp + 0x1000u);
    {
        static volatile LONG seen[16];
        LONG self = (LONG)GetCurrentThreadId();
        int i;
        for (i = 0; i < 16; i++) {
            if (seen[i] == self) break;
            if (!seen[i] && InterlockedCompareExchange(&seen[i], self, 0) == 0) {
                fprintf(stderr, "[hybrid] thread %ld is now calling back into "
                                "lifted code (%d so far)\n", self, i + 1);
                break;
            }
        }
    }
#endif

    (void)real_args;
    memset(&c, 0, sizeof c);
    c.eax = r->eax; c.ecx = r->ecx; c.edx = r->edx; c.ebx = r->ebx;
    c.esp = r->esp; c.ebp = r->ebp; c.esi = r->esi; c.edi = r->edi;

    dispatch(&c, ova);

    r->eax = c.eax;
    r->edx = c.edx;
    /* The fake return slot is the 4; anything beyond it is the callee's own
     * `ret N`. A callee that popped nothing is cdecl and leaves 0, which is
     * also what the trampoline should add to esp on the way out. */
    cleaned = (c.esp >= esp0 + 4u) ? c.esp - esp0 - 4u : 0u;
    return (uint64_t)c.eax | ((uint64_t)cleaned << 32);
}

uint32_t es3_callback(uint32_t guest_va)
{
    uint32_t t;
    if (!guest_va) return 0;
    t = hybrid_thunk(guest_va);
    if (t) return t;
    /* The thunk pool is exhausted. Handing back the raw guest address would
     * "work" until the moment it is called, and then run unlifted code - the
     * exact failure this file exists to prevent. Say so now. */
    fprintf(stderr, "[callback] out of thunks for %#010x\n", guest_va);
    abort();
    return 0;
}

/* ---- the CRT initialiser tables ----
 *
 *   void _initterm (_PVFV *begin, _PVFV *end);
 *   int  _initterm_e(_PIFV *begin, _PIFV *end);
 *
 * Both cdecl, both taking a half-open range of function pointers in .rdata.
 * `_initterm_e` stops at the first entry that returns non-zero and returns it;
 * `_initterm` ignores return values. A null entry is skipped, and there are
 * many - the linker pads these tables.
 */
static uint32_t run_initterm(CPU *c, int stop_on_error)
{
    uint32_t p = A32(0), end = A32(1), n = 0, err = 0;

    for (; p < end; p += 4) {
        uint32_t fp = rd32(p);
        if (!fp) continue;
        push32(c, CALLBACK_RETURN);
        dispatch(c, fp);
        n++;
        if (stop_on_error && c->eax) { err = c->eax; break; }
    }
    return err;
}

static void hle_initterm(CPU *c, HleId id)
{
    (void)id;
    run_initterm(c, 0);
    RET(0);
}

static void hle_initterm_e(CPU *c, HleId id)
{
    (void)id;
    RET(run_initterm(c, 1));
}

/* ---- pointers handed out to real code ----
 *
 * `_onexit(f)`, `signal(sig, f)`, `qsort(..., cmp)`,
 * `SetUnhandledExceptionFilter(f)`: the real library stores the pointer and
 * calls it later, from code this runtime has no say in. Swap the guest address
 * for a thunk on the way past and forward the call unchanged.
 *
 * The swap is written into the caller's own argument slot, which is how the
 * real function is going to read it. A caller that re-reads its pushed
 * argument afterwards would see the thunk instead - possible in principle,
 * not something MSVC-generated code does, and the alternative is copying the
 * whole frame to change one word.
 */
static void wrap_callback_arg(CPU *c, HleId id, unsigned argno)
{
    uint32_t va = A32(argno);
    uint32_t base = guest_image_base();

    /* Only a pointer into the guest image is guest code. NULL is meaningful to
     * several of these (signal(SIG_DFL), a filter being cleared), and a
     * pointer the game got from the host belongs to the host. */
    if (va >= base && va < base + guest_image_size())
        wr32(c->esp + 4u + 4u * argno, es3_callback(va));

    hle_call_native(c, id);
}

/* Same idea, for a callback that arrives inside a struct rather than as an
 * argument. `RegisterClassW` is handed a WNDCLASSW whose `lpfnWndProc` is at
 * +4; `RegisterClassExW` a WNDCLASSEXW with a `cbSize` in front of it, so +8.
 * The struct is the game's own memory and is rewritten in place - the game
 * does not read it back, and copying one to change a word would need a guest
 * allocation this runtime has no business making. */
static void wrap_callback_field(CPU *c, HleId id, unsigned field_off)
{
    uint32_t sp = A32(0);
    uint32_t base = guest_image_base();
    if (sp) {
        uint32_t proc = rd32(sp + field_off);
        if (proc >= base && proc < base + guest_image_size())
            wr32(sp + field_off, es3_callback(proc));
        if (getenv("ES3_TRACE_CALLS")) {
            unsigned k;
            fprintf(stderr, "[wndclass] %s @%08X:", hle_name(id), sp);
            for (k = 0; k < 12; k++) fprintf(stderr, " %08X", rd32(sp + 4 * k));
            fprintf(stderr, "\n");
        }
    }
    hle_call_native(c, id);
}

static void hle_register_class(CPU *c, HleId id) { wrap_callback_field(c, id, 4); }
static void hle_register_class_ex(CPU *c, HleId id) { wrap_callback_field(c, id, 8); }

/* SetWindowLongW(hwnd, index, value) only carries a callback when the index is
 * GWL_WNDPROC. Every other index is an integer the game keeps for itself, and
 * thunking one would corrupt it. */
static void hle_set_window_long(CPU *c, HleId id)
{
    if (AI32(1) == -4) wrap_callback_arg(c, id, 2);
    else hle_call_native(c, id);
}

/* A thread entry point is a callback like any other - and the first sign that
 * this runtime is about to be asked for something it cannot do. See the note
 * on threads below. */
static void hle_create_thread(CPU *c, HleId id) { wrap_callback_arg(c, id, 2); }

static void hle_onexit(CPU *c, HleId id) { wrap_callback_arg(c, id, 0); }
static void hle_seh_filter(CPU *c, HleId id) { wrap_callback_arg(c, id, 0); }
static void hle_signal(CPU *c, HleId id) { wrap_callback_arg(c, id, 1); }
static void hle_qsort(CPU *c, HleId id) { wrap_callback_arg(c, id, 3); }

/* ---- the ways a CRT gives up ----
 *
 * Every one of these ends the process, and forwarded to the real DLL they end
 * it through `__fastfail`, which no exception handler sees: the run dies with
 * 0xC0000409 and prints nothing at all. Saying which one was reached, and
 * what the guest was doing, is the difference between a diagnosis and a
 * shrug - so each says so and then does what it was going to do anyway.
 */
static void hle_give_up(CPU *c, HleId id)
{
    fprintf(stderr, "\n[exit] the guest called %s (%s)\n",
            hle_name(id), hle_dll(id));
    es3_report_state("how it got there");
    hle_call_native(c, id);
}

void hle_register_callbacks(void)
{
    unsigned tables = 0, ptrs = 0, exits = 0;

    tables += (unsigned)hle_bind("_initterm", hle_initterm);
    tables += (unsigned)hle_bind("_initterm_e", hle_initterm_e);

    ptrs += (unsigned)hle_bind("_onexit", hle_onexit);
    ptrs += (unsigned)hle_bind("atexit", hle_onexit);
    ptrs += (unsigned)hle_bind("signal", hle_signal);
    ptrs += (unsigned)hle_bind("qsort", hle_qsort);
    ptrs += (unsigned)hle_bind("SetUnhandledExceptionFilter", hle_seh_filter);
    ptrs += (unsigned)hle_bind("RegisterClassW", hle_register_class);
    ptrs += (unsigned)hle_bind("RegisterClassA", hle_register_class);
    ptrs += (unsigned)hle_bind("RegisterClassExW", hle_register_class_ex);
    ptrs += (unsigned)hle_bind("RegisterClassExA", hle_register_class_ex);
    ptrs += (unsigned)hle_bind("SetWindowLongW", hle_set_window_long);
    ptrs += (unsigned)hle_bind("SetWindowLongA", hle_set_window_long);
    ptrs += (unsigned)hle_bind("CreateThread", hle_create_thread);
    ptrs += (unsigned)hle_bind("_beginthreadex", hle_create_thread);

    exits += (unsigned)hle_bind("abort", hle_give_up);
    exits += (unsigned)hle_bind("exit", hle_give_up);
    exits += (unsigned)hle_bind("_exit", hle_give_up);
    exits += (unsigned)hle_bind("_cexit", hle_give_up);
    exits += (unsigned)hle_bind("_amsg_exit", hle_give_up);
    exits += (unsigned)hle_bind("_invoke_watson", hle_give_up);
    exits += (unsigned)hle_bind("TerminateProcess", hle_give_up);
    exits += (unsigned)hle_bind("UnhandledExceptionFilter", hle_give_up);

    fprintf(stderr,
            "[hle] %u initialiser table(s) walked here so their entries run "
            "lifted, %u callback pointer(s) thunked, %u exit path(s) traced\n",
            tables, ptrs, exits);
}
