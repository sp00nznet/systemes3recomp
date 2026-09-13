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

/* ---- registration ---- */

void hle_register_callbacks(void)
{
    unsigned n = 0;
    n += (unsigned)hle_bind("_initterm", hle_initterm);
    n += (unsigned)hle_bind("_initterm_e", hle_initterm_e);
    if (n)
        fprintf(stderr, "[hle] %u initialiser-table import(s) taken over from "
                        "the host, so their entries run lifted\n", n);
}
