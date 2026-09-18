/*
 * dispatch64.c - turn a guest address into a call.
 *
 * Three things can be on the other side of a guest address:
 *
 *   1. a lifted function          -> call its C body
 *   2. a real function in a DLL   -> forward with the guest's arguments
 *   3. nothing we know about      -> say so loudly, with a trail
 *
 * Telling 1 from 2 is not done with sentinels, as the 32-bit runtime does. The
 * distinguishing property of an import here is simply that it is not a lifted
 * function and not inside the guest image, and testing THAT catches every way
 * an import can be reached: the IAT slot itself, a one-line `jmp [__imp_X]`
 * thunk, a function pointer copied out of the IAT and called an hour later, and
 * the vtables D3D and Wwise hand back full of addresses inside their own DLLs.
 */

#include "es3_rt64.h"
#include "thunk64.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>

int g_trace_enabled = 0;
uint64_t g_dispatch_limit = 0;      /* 0 = unlimited */
uint64_t g_dispatch_count = 0;

/* Bringing a new image up, the trail matters more than the fault: a guest that
 * runs away ends up faulting somewhere unrelated to the mistake, and the last
 * few hundred dispatches before the limit say far more than the address it
 * eventually died on. */
static void check_limit(void)
{
    if (g_dispatch_limit && ++g_dispatch_count >= g_dispatch_limit) {
        es3_trace_dump("dispatch limit reached");
        fprintf(stderr, "[dispatch] stopped at the %llu-dispatch limit\n",
                (unsigned long long)g_dispatch_limit);
        exit(3);
    }
}

/* ---- the lifted-function index ----
 * Built once, sorted, then binary searched. The table the generator emits is
 * already in address order, but sorting here rather than trusting that keeps
 * the two files independent - and 90,818 entries is a 17-step search either
 * way. */
static const recomp_entry_t *g_sorted;
static uint32_t g_count;

static int cmp_entry(const void *a, const void *b)
{
    uint64_t x = ((const recomp_entry_t *)a)->va;
    uint64_t y = ((const recomp_entry_t *)b)->va;
    return (x > y) - (x < y);
}

static void ensure_index(void)
{
    if (g_sorted) return;
    g_count = recomp_dispatch_count;
    recomp_entry_t *t = (recomp_entry_t *)malloc(g_count * sizeof *t);
    memcpy(t, recomp_dispatch_table, g_count * sizeof *t);
    qsort(t, g_count, sizeof *t, cmp_entry);
    g_sorted = t;
}

static void (*lookup(uint64_t va))(CPU *)
{
    ensure_index();
    uint32_t lo = 0, hi = g_count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (g_sorted[mid].va < va) lo = mid + 1;
        else hi = mid;
    }
    if (lo < g_count && g_sorted[lo].va == va) return g_sorted[lo].fn;
    return NULL;
}

/* The lifted table is indexed by the address the image PREFERRED. If the image
 * had to be relocated, a guest pointer computed at runtime is a real address
 * and has to come back to that space before it can be looked up. */
static uint64_t to_preferred(uint64_t real)
{
    return (uint64_t)((int64_t)real - g_image_delta);
}

/* ---- the native side ---- */

int es3_native_call(CPU *c, uint64_t target)
{
    HLEFRAME f;
    memset(&f, 0, sizeof f);

    /* At this point the lifted caller has pushed a return address, so c->rsp
     * points at it and c->rsp+8 is the shadow space - exactly the frame a
     * Win64 callee expects to see. The callee's own RET is what would have
     * removed the return address, and there is no lifted callee here to do it,
     * so this does it instead. Getting that wrong leaves the guest stack eight
     * bytes out with nothing to show for it. */
    uint64_t gsp = c->rsp;
    c->rsp = gsp + 8;

    f.fn  = (void *)target;
    f.rcx = c->rcx;
    f.rdx = c->rdx;
    f.r8  = c->r8;
    f.r9  = c->r9;
    memcpy(&f.x0, &c->xmm[0], 16);
    memcpy(&f.x1, &c->xmm[1], 16);
    memcpy(&f.x2, &c->xmm[2], 16);
    memcpy(&f.x3, &c->xmm[3], 16);

    /* Stack arguments begin above the shadow space. How many there are is not
     * knowable from here - the IAT says nothing about arity - so a fixed window
     * is copied. It is only ever read by the callee up to its real argument
     * count, and the source is the guest's own stack, so copying too much is
     * harmless where copying too little would pass garbage. */
    f.stack  = c->rsp + 32;
    f.nstack = HLE_STACK_ARGS;

    hle_invoke(&f);

    /* Win64 returns integers in RAX and floats in XMM0. Which one the callee
     * used is not knowable here either, so both are taken; the guest reads the
     * one its own prototype says, and the other is a register it was entitled
     * to treat as volatile anyway. */
    c->rax = f.rax_out;
    memcpy(&c->xmm[0], &f.xmm0_out, 16);

    /* RCX, RDX, R8-R11 and XMM0-5 are volatile across a Win64 call, so their
     * contents afterwards are undefined and the guest cannot read them. Left
     * alone deliberately: scrambling them would be more faithful but would make
     * every trace harder to read for no behavioural difference. */
    return 1;
}

/* ---- the entry points the lifted code calls ---- */

static void unknown_target(CPU *c, uint64_t target, const char *how)
{
    char msg[256];
    const char *nm = es3_import_name(target);
    snprintf(msg, sizeof msg,
             "%s to %#llx (%s) - not a lifted function, not in the image",
             how, (unsigned long long)target, nm ? nm : "unknown");
    es3_trace_dump(msg);
    fprintf(stderr, "[dispatch] %s\n", msg);
    abort();
}

void dispatch(CPU *c, uint64_t target)
{
    check_limit();
    uint64_t pref = to_preferred(target);
    void (*fn)(CPU *) = lookup(pref);
    if (fn) {
        if (g_trace_enabled) es3_trace(pref, "call");
        fn(c);
        return;
    }
    /* Inside the image but not a catalogued function: the disassembler missed
     * it. That is a real gap and worth reporting as one rather than trying to
     * call into it. */
    if (target >= g_image.text_lo && target < g_image.text_hi) {
        unknown_target(c, target, "call into uncatalogued guest code");
        return;
    }
    if (g_trace_enabled) es3_trace(target, "native");
    es3_native_call(c, target);
}

void dispatch_jmp(CPU *c, uint64_t target)
{
    check_limit();
    /* A tail call. The difference from dispatch() is that no return address was
     * pushed - the jump reuses the caller's - so a native callee here already
     * has the right frame and must NOT have the stack adjusted for it. */
    uint64_t pref = to_preferred(target);
    void (*fn)(CPU *) = lookup(pref);
    if (fn) {
        if (g_trace_enabled) es3_trace(pref, "tail");
        fn(c);
        return;
    }
    if (target >= g_image.text_lo && target < g_image.text_hi) {
        unknown_target(c, target, "tail call into uncatalogued guest code");
        return;
    }
    if (g_trace_enabled) es3_trace(target, "native-tail");

    /* No stack adjustment here, and that is not an omission.
     *
     * A `jmp [__imp_memcpy]` thunk does not push a return address - it reuses
     * the one its own caller pushed, and the native callee's RET is what
     * consumes it. That is the same net effect as the call case, where the
     * lifted caller pushed the address and the callee's RET consumes it. So
     * both paths hand es3_native_call a stack pointing at a return address
     * with the shadow space above it, and both want the same adjustment. */
    es3_native_call(c, target);
}
