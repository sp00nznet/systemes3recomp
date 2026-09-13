/*
 * dispatch.c - original address -> lifted function, and imports on the way past.
 *
 * Direct calls could have been emitted as plain C calls, but indirect ones
 * cannot: the game computes a target at run time (vtables, the D3D and OKAO
 * interfaces, the task tables arcade code is full of) and hands over an
 * address from the original image. Every call goes through here so both kinds
 * land the same way - and so that the import sentinels guest_load() wrote into
 * the IAT are recognised wherever they are called from, not just at a `call
 * dword ptr [__imp_X]` the lifter could have pattern-matched.
 *
 * The table is generated - recomp_funcs_list.h is the X-macro of every VA that
 * lifted, emitted in ascending order, which is what lets this binary search
 * instead of scanning tens of thousands of entries per indirect call.
 */

#include <stdio.h>
#include <stdlib.h>

#include "es3_rt.h"
#include "recomp_funcs_list.h"

#define DECL(a) void L_##a(CPU *c);
LIFTED_FUNCS(DECL)
#undef DECL

typedef struct { uint32_t va; void (*fn)(CPU *); } Entry;

#define ENT(a) { 0x##a##u, L_##a },
static const Entry g_table[] = { LIFTED_FUNCS(ENT) };
#undef ENT

#define N (sizeof g_table / sizeof g_table[0])

static void (*find(uint32_t va))(CPU *)
{
    size_t lo = 0, hi = N;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (g_table[mid].va == va) return g_table[mid].fn;
        if (g_table[mid].va < va) lo = mid + 1; else hi = mid;
    }
    return NULL;
}

int dispatch_has(uint32_t va) { return find(va) != NULL; }

void dispatch(CPU *c, uint32_t va)
{
    es3_note_dispatch(va);
    if (HLE_IS_ADDR(va)) { hle_call(c, HLE_ID_OF(va)); return; }

    void (*fn)(CPU *) = find(va);
    if (fn) { fn(c); return; }

    /* Not lifted. On a stripped PE this is the expected way to find out what
     * the catalog missed, so the message has to be worth acting on: the
     * address goes into a seed file and the next scan starts from it.
     * (pcrecomp's tools/disasm/seed_from_log.py reads exactly this shape.) */
    fprintf(stderr,
            "[dispatch] no lifted function at %#010x (esp=%#010x)\n"
            "           add it as a seed and re-scan.\n", va, c->esp);
    es3_report_state("unresolved dispatch");
    abort();
}

void dispatch_jmp(CPU *c, uint32_t va)
{
    /* A tail call: the caller already popped its frame, so the callee returns
     * straight to our caller's caller. Same table, no return address pushed -
     * and the same sentinel check, because `jmp dword ptr [__imp_X]` is how
     * MSVC writes an import thunk and there are hundreds of them. */
    dispatch(c, va);
}
