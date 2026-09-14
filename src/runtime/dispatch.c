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
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

#include "es3_rt.h"
#include "hybrid.h"
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

/*
 * Which guest function is the host code at `host` part of?
 *
 * A fault in lifted code reports a host address, and a host address in a
 * thirty-megabyte generated image says nothing at all. But the same table that
 * answers dispatch() holds both halves of the mapping, so the answer is a
 * search over it - by function pointer instead of by VA.
 *
 * It has to be a linear scan because the table is sorted by guest VA and the
 * linker lays the bodies out in whatever order it likes. Thirty thousand
 * comparisons, once, while the process is already dying.
 *
 * The nearest body at or below the address, which is the containing one unless
 * the fault is in a runtime helper between two of them - so the result is a
 * guess, and the caller says so.
 */
uint32_t dispatch_owner(const void *host)
{
    uintptr_t a = (uintptr_t)host, best = 0;
    uint32_t va = 0;
    size_t i;
    for (i = 0; i < N; i++) {
        uintptr_t f = (uintptr_t)g_table[i].fn;
        if (f <= a && f > best) { best = f; va = g_table[i].va; }
    }
    return va;
}

static void dispatch_inner(CPU *c, uint32_t va);

void dispatch(CPU *c, uint32_t va)
{
    es3_note_dispatch(va);

    /* ES3_WATCH_VA, reported here rather than in the ring, because here there
     * is a CPU: the return address the caller pushed is the top of the guest
     * stack, and "who called this" is most of what the question was. A
     * function reached through a vtable has no caller you can grep for. */
    if (es3_watched(va)) {
        uint32_t from = rd32(c->esp), at = es3_dispatch_count();
        fprintf(stderr, "[watch] %08X entered from %08X (thread %lu, "
                        "dispatch %u)\n", va, from, GetCurrentThreadId(), at);
        /* And what it answered. An init step that returns a bool is the whole
         * question when the chain after it never runs. */
        dispatch_inner(c, va);
        fprintf(stderr, "[watch] %08X returned %08X to %08X (thread %lu, "
                        "dispatch %u)\n", va, c->eax, from,
                        GetCurrentThreadId(), es3_dispatch_count());
        return;
    }
    dispatch_inner(c, va);
}

static void dispatch_inner(CPU *c, uint32_t va)
{
    uint32_t ova;

    if (HLE_IS_ADDR(va)) { hle_call(c, HLE_ID_OF(va)); return; }

    /* A thunk address, not a guest VA. Lifted code that reads a slot this
     * runtime handed to a real library - a window procedure, a comparator -
     * gets the thunk back, and calling it would go the long way round through
     * the real->lifted trampoline and arrive here anyway. Short-circuit to the
     * function it stands for. */
    if (hybrid_thunk_target(va, &ova)) va = ova;

    void (*fn)(CPU *) = find(va);
    if (fn) { fn(c); return; }

    /* Real code the game got at run time rather than through the IAT: a COM
     * vtable slot, a GetProcAddress result. The mirror of the callback problem
     * and the same answer - it is real code, so run it as real code. Checked
     * after the lifted table, because a guest address is the common case and
     * this one costs a region lookup. */
    if (es3_is_host_code(va)) { hle_call_address(c, va); return; }

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
