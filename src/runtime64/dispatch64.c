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
int g_swallow_raise = 0;    /* diagnostic; see the RaiseException note */

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

/* The thread shim is defined below, next to the note explaining it, but the
 * import interception that installs it lives in es3_native_call above it. */
typedef struct { uint64_t guest_fn, param; size_t stack; } thread_start_t;
static DWORD WINAPI es3_thread_shim(void *arg);

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

    /* ---- RaiseException(0x406D1388): the thread-name notification ----
     *
     * This is not a failure, it is a message to a debugger, and the standard
     * idiom that sends it wraps the call in the caller's own __try/__except:
     *
     *     __try { RaiseException(0x406D1388, 0, 4, &info); }
     *     __except (EXCEPTION_EXECUTE_HANDLER) { }
     *
     * Lifted code has no structured exception handling, so with the exception
     * actually raised there is nothing to catch it and it kills the process.
     * Swallowing it in a vectored handler does not work either: continuing
     * execution resumes inside RtlRaiseException and raises again.
     *
     * Not raising it in the first place is what the guest's own __except would
     * have amounted to, and it is a decision that belongs at the import
     * boundary rather than in an exception filter. Every other exception code
     * is forwarded untouched - a guest that really does raise something is
     * still a guest whose behaviour we want.
     */
    if (target == g_addr_RaiseException) {
        if ((uint32_t)c->rcx == 0x406D1388u) {
            c->rax = 0;
            return 1;
        }
        /* Anything else is forwarded, but named first. Lifted code has no
         * structured exception handling, so a raise the guest expected to
         * catch itself will escape and look like a crash in ntdll - which is
         * a long way from the guest code that asked for it. */
        fprintf(stderr, "[raise] guest RaiseException(code=%#x, flags=%#x, "
                        "nargs=%u) from thread %lu\n",
                (unsigned)c->rcx, (unsigned)c->rdx, (unsigned)c->r8,
                GetCurrentThreadId());
        /* Dump the trail HERE, at the first one, not when the process finally
         * dies. By then the ring holds nothing but the main thread's spin loop
         * waiting on the worker this raise just killed - four thousand entries
         * of QueryPerformanceCounter and not one of the code that failed. */
        {
            static long once = 0;
            if (InterlockedExchange(&once, 1) == 0)
                es3_trace_dump("first guest RaiseException");
        }
        /* A DIAGNOSTIC, not a fix, and off unless asked for. Dropping the
         * raise pretends the guest's own __except caught it, which is true for
         * an idiom like the thread-name notification and false for a genuine
         * error - and there is no way to tell which from here. It exists to
         * answer one question while bringing the image up: is missing SEH the
         * only thing in the way, or the first of several? */
        if (g_swallow_raise) {
            c->rax = 0;
            return 1;
        }
    }

    /* ---- CreateThread: substitute a native start routine ----
     *
     * Win64 argument order: rcx=attributes, rdx=stack size, r8=start address,
     * r9=parameter, [rsp+0x28]=flags, [rsp+0x30]=out thread id. Only r8 and r9
     * are replaced; everything else is forwarded untouched, so the guest's
     * stack size, CREATE_SUSPENDED and returned thread id all still work.
     */
    if (target == g_addr_CreateThread && c->r8) {
        thread_start_t *ts = (thread_start_t *)malloc(sizeof *ts);
        ts->guest_fn = c->r8;
        ts->param    = c->r9;
        ts->stack    = (size_t)c->rdx;
        c->r8 = (uint64_t)(uintptr_t)es3_thread_shim;
        c->r9 = (uint64_t)(uintptr_t)ts;
        /* falls through and forwards, now with a start routine that exists */
    }

    /* ---- _initterm / _initterm_e: the static-initialiser tables ----
     *
     * `_initterm_e(first, last)` walks an array of function pointers and calls
     * each one. Every pointer in it is a GUEST address, so letting the real
     * MSVCR100 do the walking means the CRT calls guest code directly - which
     * is where this build faulted, eleven dispatches in, on pre_c_init.
     *
     * Doing the walk here instead is not an approximation of the CRT; this IS
     * what those two functions do, in full. The only difference is that each
     * entry goes through the dispatcher.
     *
     * The _e form stops at the first entry returning non-zero and yields that
     * value; the plain form ignores return values. Getting that backwards
     * would run initialisers after one had already failed.
     */
    if ((target == g_addr_initterm || target == g_addr_initterm_e) &&
        c->rcx && c->rdx) {
        int wants_result = (target == g_addr_initterm_e);
        uint64_t p = c->rcx, end = c->rdx;
        uint64_t saved_rcx = c->rcx, saved_rdx = c->rdx;
        uint32_t rc = 0;
        for (; p < end; p += 8) {
            uint64_t fnp = rd64(p);
            if (!fnp) continue;            /* the table is sparse */
            es3_call_guest(c, fnp);
            if (wants_result && (uint32_t)c->rax) { rc = (uint32_t)c->rax; break; }
        }
        c->rcx = saved_rcx; c->rdx = saved_rdx;
        c->rax = rc;
        return 1;
    }

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

/* ---- calling INTO lifted code ----
 *
 * The other direction, and the one a recompiled build cannot do without. A
 * guest function pointer handed to a real DLL is a guest address, and the DLL
 * will call it: _initterm_e walks the C++ static-initialiser table, qsort calls
 * a comparator, CreateThread calls a thread procedure, user32 calls a window
 * procedure. The address it calls has no executable code at it - guest memory
 * is mapped non-executable precisely so that this is caught rather than
 * silently running the original machine code.
 *
 * So the runtime intercepts the import and re-enters through the dispatcher,
 * which is the only path to the lifted body.
 */
void es3_call_guest(CPU *c, uint64_t target)
{
    /* The callee's RET pops a return address, so there has to be one. The
     * value is never used - the lifted function returns to us by returning
     * from its C body - but the stack accounting has to match or every
     * subsequent frame is eight bytes out. */
    c->rsp -= 8;
    wr64(c->rsp, 0xE5E3CA11E5E3CA11ULL);
    dispatch(c, target);
}

/* ---- threads ----
 *
 * CreateThread is handed a GUEST address as its start routine, and the real
 * kernel32 will call it on a brand new thread. Everything about that is wrong
 * for a recompiled build: there is no executable code at the address, and even
 * if there were, the new thread has no CPU state.
 *
 * So the start routine is replaced with a native shim and the guest's own
 * routine travels alongside it. Each thread gets its OWN CPU - which is the
 * whole reason the lifter emits `void L_x(CPU *c)` and not a global register
 * file. A global one would have made this the point where the project stopped.
 */
/* ---- the general callback bridge ----
 *
 * Intercepting imports one at a time does not scale: _initterm_e, CreateThread,
 * then a TLS callback, a window procedure, a qsort comparator, a Wwise or D3D
 * callback. Each is the same problem - a native caller reaching a guest address
 * - and each would need its own shim, forever, with a crash for every one not
 * yet written.
 *
 * The DEP fault already carries everything needed to bridge it generically.
 * When native code CALLs a guest address the call itself completes: the return
 * address is pushed, and the fault happens fetching the first instruction. So
 * when the handler runs,
 *
 *     ctx->Rip  is the guest function
 *     ctx->Rsp  points at the return address the call pushed
 *     Rcx/Rdx/R8/R9 and Xmm0-3 hold the arguments, in the same ABI the guest
 *               itself uses
 *
 * which is exactly a guest call frame. Seed a CPU from the context, dispatch to
 * the lifted body, and put the results back: RIP to the return address, RSP to
 * where the callee's RET left it, RAX and XMM0 to the return value. The thread
 * continues as though the call had simply worked.
 *
 * This is what makes the non-executable mapping a design rather than a
 * diagnostic: every guest address a DLL can call becomes callable, and no
 * original machine code ever runs.
 */
int es3_bridge_callback(EXCEPTION_POINTERS *ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return 0;
    if (ep->ExceptionRecord->ExceptionInformation[0] != 8)   /* not execute */
        return 0;

    uint64_t fn = (uint64_t)ep->ExceptionRecord->ExceptionInformation[1];
    if (!g_image.base || fn < g_image.text_lo || fn >= g_image.text_hi)
        return 0;
    if (!lookup(to_preferred(fn)))          /* not a function we can enter */
        return 0;

    CONTEXT *ctx = ep->ContextRecord;
    CPU c;
    memset(&c, 0, sizeof c);
    c.rax = ctx->Rax; c.rcx = ctx->Rcx; c.rdx = ctx->Rdx; c.rbx = ctx->Rbx;
    c.rsp = ctx->Rsp; c.rbp = ctx->Rbp; c.rsi = ctx->Rsi; c.rdi = ctx->Rdi;
    c.r8  = ctx->R8;  c.r9  = ctx->R9;  c.r10 = ctx->R10; c.r11 = ctx->R11;
    c.r12 = ctx->R12; c.r13 = ctx->R13; c.r14 = ctx->R14; c.r15 = ctx->R15;
    memcpy(c.xmm, &ctx->Xmm0, sizeof c.xmm);

    uint64_t retaddr = rd64(ctx->Rsp);

    if (g_trace_enabled) es3_trace(fn, "callback");
    dispatch(&c, fn);                       /* the callee's RET does rsp += 8 */

    ctx->Rip = retaddr;
    ctx->Rsp = c.rsp;
    ctx->Rax = c.rax;
    /* Callee-saved registers are the guest's to preserve, and the lifted body
     * did preserve them - in the CPU. Copy them back, or the native caller
     * finds its own non-volatiles holding whatever the guest left there. */
    ctx->Rbx = c.rbx; ctx->Rbp = c.rbp; ctx->Rsi = c.rsi; ctx->Rdi = c.rdi;
    ctx->R12 = c.r12; ctx->R13 = c.r13; ctx->R14 = c.r14; ctx->R15 = c.r15;
    memcpy(&ctx->Xmm0, c.xmm, sizeof c.xmm);
    return 1;
}

static DWORD WINAPI es3_thread_shim(void *arg)
{
    thread_start_t ts = *(thread_start_t *)arg;
    free(arg);

    CPU c;
    memset(&c, 0, sizeof c);
    c.rsp = es3_alloc_stack(ts.stack ? ts.stack : (1u << 20));
    if (!c.rsp) {
        fprintf(stderr, "[thread] no guest stack for %#llx\n",
                (unsigned long long)ts.guest_fn);
        return 1;
    }
    c.rcx = ts.param;                 /* the thread parameter, first argument */
    es3_call_guest(&c, ts.guest_fn);
    return (DWORD)c.rax;
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
