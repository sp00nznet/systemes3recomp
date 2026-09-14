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
    /* StackBase is the top; the bottom is DeallocationStack at TEB+0xE0C, not
     * StackLimit - StackLimit is only as low as the stack has actually grown
     * so far, so it reads 8 KB on a thread with a megabyte reserved. */
    uint32_t teb_base = __readfsdword(0x04), teb_limit = __readfsdword(0xE0C);
    es3_teb_cover(r->esp - (1u << 20), r->esp + 0x1000u);
    {
        /* Sixty-four, because this game has more than sixteen and the ones
         * past the end were the interesting ones - a thread nobody knew about
         * running an update before its subsystem had been built. With the
         * address it came in at, so `ES3_WATCH_VA` has something to aim at. */
        static volatile LONG seen[64];
        LONG self = (LONG)GetCurrentThreadId();
        int i;
        for (i = 0; i < 64; i++) {
            if (seen[i] == self) break;
            if (!seen[i] && InterlockedCompareExchange(&seen[i], self, 0) == 0) {
                /* And how much real stack it has. Lifted code carries the
                 * whole call graph on it - one C frame per guest function plus
                 * dispatch in between - and a thread this runtime did not
                 * create has whatever its owner chose. D3DX10 makes its own
                 * pump threads; if one of those is small, the overflow arrives
                 * as an access violation the kernel cannot dispatch, which
                 * means no handler, no report, and a log that stops. */
                fprintf(stderr, "[hybrid] thread %ld enters lifted code at "
                                "%08X (%d so far, %u KB of real stack)\n",
                        self, ova, i + 1,
                        (unsigned)((teb_base - teb_limit) >> 10));
                break;
            }
        }
    }
#endif

    /* The first crossings, with what the real caller passed and what the guest
     * gave back. For a window procedure that is (hwnd, message, wParam,
     * lParam) and an LRESULT, which is exactly the conversation that decides
     * whether CreateWindowEx succeeds: returning 0 to WM_NCCREATE (0x0081)
     * makes it fail, and it reports ERROR_NOT_ENOUGH_MEMORY when it does. */
    {
        /* Per callback address, not per process. One worker-thread entry point
         * called by sixteen threads in a spin will otherwise eat the whole
         * budget before the interesting one crosses even once. */
        static uint32_t seen[256];
        static unsigned char hits[256];
        int show = 0, k;
        if (getenv("ES3_TRACE_CALLS")) {
            for (k = 0; k < 256 && seen[k] && seen[k] != ova; k++) {}
            if (k < 256) { seen[k] = ova; show = hits[k]++ < 8; }
        }
        if (show)
            fprintf(stderr, "[r2l] %08X(%08X, %08X, %08X, %08X)", ova,
                    real_args[0], real_args[1], real_args[2], real_args[3]);

        memset(&c, 0, sizeof c);
        c.eax = r->eax; c.ecx = r->ecx; c.edx = r->edx; c.ebx = r->ebx;
        c.esp = r->esp; c.ebp = r->ebp; c.esi = r->esi; c.edi = r->edi;

        dispatch(&c, ova);

        if (show)
            fprintf(stderr, " = %08X\n", c.eax);
    }
    goto done;

    (void)real_args;
    memset(&c, 0, sizeof c);
    c.eax = r->eax; c.ecx = r->ecx; c.edx = r->edx; c.ebx = r->ebx;
    c.esp = r->esp; c.ebp = r->ebp; c.esi = r->esi; c.edi = r->edi;

    dispatch(&c, ova);

done:
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
        /* ES3_NO_WNDPROC_THUNK isolates one question when a window will not
         * create: is the thunk the problem, or the environment it runs in?
         * Without the thunk the procedure runs UNLIFTED and will fault the
         * moment it is called - so this is a diagnostic, never a setting. */
        if (proc >= base && proc < base + guest_image_size() &&
            !getenv("ES3_NO_WNDPROC_THUNK"))
            wr32(sp + field_off, es3_callback(proc));

        /* And the hInstance three fields along - offset 16 in a WNDCLASS,
         * 20 in a WNDCLASSEX, which is field_off + 12 either way.
         *
         * It has to move with the one hle_native.c substitutes in
         * CreateWindowEx, because a class is identified by (atom, hInstance):
         * register under the guest's image base and create with the host's and
         * the lookup fails with ERROR_CANNOT_FIND_WND_CLASS, which is a
         * different and equally opaque way to get no window. */
        if (rd32(sp + field_off + 12) == base && !getenv("ES3_NO_HINSTANCE_FIX"))
            wr32(sp + field_off + 12,
                 (uint32_t)(uintptr_t)GetModuleHandleW(NULL));
        if (getenv("ES3_TRACE_CALLS")) {
            unsigned k;
            uint32_t thunk = rd32(sp + field_off), tova = 0;
            hybrid_thunk_target(thunk, &tova);
            fprintf(stderr, "[wndclass] %s @%08X: wndproc %08X is %08X:",
                    hle_name(id), sp, thunk, tova);
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
/*
 * A thread the guest makes needs a bigger stack than the guest asked for.
 *
 * `CreateThread(attr, stack, start, ...)` and `_beginthreadex(sec, stack,
 * start, ...)` both name the size in argument 1, and a game picks it to fit
 * its own compiled frames. Lifted code does not have those frames: every guest
 * function is a C function with its own locals, dispatch() sits between each
 * pair, and the emulated frame is somewhere else entirely - so the real stack
 * carries the whole call graph and several times the depth per level.
 *
 * When it runs out, the thread faults on the guard page while already handling
 * a fault, and Windows ends the process THERE - no vectored handler, no
 * unhandled filter, no report of any kind, exit code 0xC0000005 and a log that
 * stops mid-line. It cost an afternoon to recognise, so the floor is generous:
 * address space is cheap for a reservation, and a stack is reserved, not
 * committed.
 */
#define THREAD_STACK_SIZE (8u << 20)

/*
 * Keep the game in a window, and keep it there.
 *
 * An ES3 title is a cabinet program: it asks for a borderless window the size
 * of the cabinet's screen and expects to own the display. On a desktop that
 * means it covers everything, including whatever you were doing - and a
 * recompiled game under development is something you run dozens of times an
 * hour while reading a log next to it.
 *
 * So the window it actually gets is an ordinary framed one, at a size that
 * fits on a desktop, unless ES3_FULLSCREEN says otherwise. The game is told
 * nothing: the client area it asked for is what CreateWindowEx is given, and
 * WS_POPUP - which is what makes it borderless and screen-sized - is traded
 * for WS_OVERLAPPEDWINDOW.
 *
 * SetWindowPos is clamped for the same reason, because the game moves and
 * resizes its own window afterwards.
 */
static int windowed(void)
{
    static int on = -1;
    if (on < 0) on = getenv("ES3_FULLSCREEN") == NULL;
    return on;
}

#define ES3_MAX_W 1280
#define ES3_MAX_H 720

static void hle_create_window(CPU *c, HleId id)
{
    if (windowed()) {
        uint32_t style = A32(3);
        int w = (int)A32(6), h = (int)A32(7);
        if (style & 0x80000000u) {                    /* WS_POPUP */
            static unsigned char said;
            if (!said) {
                said = 1;
                fprintf(stderr, "[hle] the game asked for a borderless %dx%d "
                                "window; giving it a framed one that fits on a "
                                "desktop (ES3_FULLSCREEN=1 to allow it)\n", w, h);
            }
            style = (style & ~0x80000000u) | 0x00CF0000u;   /* WS_OVERLAPPEDWINDOW */
            wr32(c->esp + 4 + 4 * 3, style);
        }
        if (w > ES3_MAX_W) wr32(c->esp + 4 + 4 * 6, (uint32_t)ES3_MAX_W);
        if (h > ES3_MAX_H) wr32(c->esp + 4 + 4 * 7, (uint32_t)ES3_MAX_H);
        wr32(c->esp + 4 + 4 * 4, 64);                 /* x */
        wr32(c->esp + 4 + 4 * 5, 64);                 /* y */
    }
    hle_call_native(c, id);
}

/* SetWindowPos(hwnd, after, x, y, cx, cy, flags) - arguments 4 and 5. */
static void hle_set_window_pos(CPU *c, HleId id)
{
    if (windowed()) {
        if ((int)A32(4) > ES3_MAX_W) wr32(c->esp + 4 + 4 * 4, (uint32_t)ES3_MAX_W);
        if ((int)A32(5) > ES3_MAX_H) wr32(c->esp + 4 + 4 * 5, (uint32_t)ES3_MAX_H);
    }
    hle_call_native(c, id);
}

/* Direct3DCreate9Ex(SDKVersion, ppD3D) - the factory comes back through the
 * out-parameter, and its vtable is the only way to recognise CreateDeviceEx
 * later, because that one is a slot and not an import. */
static void hle_d3d_create9ex(CPU *c, HleId id)
{
    uint32_t pp = A32(1);
    hle_call_native(c, id);
    if (pp && c->eax == 0) es3_d3d_note_factory(rd32(pp));
}

static void hle_thread_exit(CPU *c, HleId id)
{
    fprintf(stderr, "[exit] a guest thread ended through %s\n", hle_name(id));
    hle_call_native_noreturn(c, id);
}

static void hle_create_thread(CPU *c, HleId id)
{
    uint32_t want = A32(1);
    static unsigned char said;

    if (!said) {
        said = 1;
        fprintf(stderr, "[hle] the guest asks for %u KB thread stacks; "
                        "reserving %u MB for every one of them\n",
                want >> 10, THREAD_STACK_SIZE >> 20);
    }
    /*
     * Both halves, or neither works.
     *
     * dwStackSize on its own is the size Windows COMMITS; what it reserves
     * comes from the PE header, which is /STACK - and /STACK is a quarter of a
     * gigabyte here because the primary thread runs the whole lifted call
     * graph. Twenty-nine worker threads each reserving that is the whole
     * address space, and the run ends inside a minute with bad_alloc.
     *
     * STACK_SIZE_PARAM_IS_A_RESERVATION is what makes argument 1 mean reserve.
     * It is argument 4 of CreateThread (dwCreationFlags) and argument 4 of
     * _beginthreadex (initflag), which forwards it, so one write serves both.
     */
    wr32(c->esp + 4 + 4 * 1, THREAD_STACK_SIZE);
    wr32(c->esp + 4 + 4 * 4, A32(4) | 0x00010000u);
    wrap_callback_arg(c, id, 2);
}

/* SetWindowsHookEx(idHook, lpfn, hmod, threadId) - the callback is argument 1.
 * EnumWindows(lpEnumFunc, lParam) - argument 0. */
/*
 * The cabinet was never at the other end of a Remote Desktop session.
 *
 * This title is built on DXUT, Microsoft's sample framework, and DXUT opens
 * with GetSystemMetrics(SM_REMOTESESSION) and refuses if it is non-zero:
 *
 *   MessageBoxW(hwnd, "Direct3D does not work over a remote session.",
 *               "mkart3", MB_ICONERROR)
 *
 * That box is modal, the thread carrying the game sits in NtUserWaitMessage
 * inside it for ever, and from outside the run looks like a hang with a black
 * window - which is exactly what it looked like.
 *
 * The check is the framework's and it is about 2006 hardware. Direct3D 10 and
 * 11 do work over a modern RDP session; the cabinet had a monitor bolted to it
 * and could never have been remote either way. So answer 0 and let the game
 * get on with it, the same way this runtime already answers HINSTANCE with a
 * module handle the loader has heard of.
 *
 * Only SM_REMOTESESSION. Every other metric is the host's to answer.
 */
#define SM_REMOTESESSION_ 0x1000

static void hle_get_system_metrics(CPU *c, HleId id)
{
    if (A32(0) == SM_REMOTESESSION_) {
        static unsigned char said;
        hle_call_native(c, id);
        if (c->eax) {
            if (!said) {
                said = 1;
                fprintf(stderr, "[hle] this is a remote session, and the game "
                                "refuses Direct3D on one; saying it is not.\n");
            }
            c->eax = 0;
        }
        return;
    }
    hle_call_native(c, id);
}

/*
 * A modal dialog is a hang with a picture on it.
 *
 * Nothing is watching a cabinet, so a game that puts up a MessageBox and waits
 * for OK has stopped, and the run says nothing except that one thread is in
 * NtUserWaitMessage. Print what it says - which is the most informative line
 * the game will ever produce - and answer IDOK without showing it.
 *
 * That is a behaviour change and it is the right one: the alternative is a
 * silent stall. ES3_MODAL=1 shows the box for anyone who wants to click it.
 */
static void hle_message_box(CPU *c, HleId id)
{
    static int show = -1;
    /* A copy, because es3_arg_string() answers out of one static buffer and
     * the second call overwrites the first - which printed the caption twice
     * and lost the only sentence the game had to say. */
    char cap[128];
    const char *s = es3_arg_string(A32(2));
    if (show < 0) show = getenv("ES3_MODAL") != NULL;
    strncpy(cap, s ? s : "", sizeof cap - 1);
    cap[sizeof cap - 1] = 0;
    s = es3_arg_string(A32(1));

    fprintf(stderr, "\n[game] MessageBox: %s%s%s\n",
            cap, cap[0] ? " - " : "", s ? s : "(unreadable)");
    if (show) { hle_call_native(c, id); return; }
    fprintf(stderr, "       answering OK without showing it - a modal box on a "
                    "cabinet is a stall (ES3_MODAL=1 to see it).\n");
    fflush(stderr);
    c->eax = 1;                                  /* IDOK */
    c->esp += 4 + 4 * 4;                         /* __stdcall, four arguments */
}

/*
 * The serial port the I/O board is on, answered by jvs.c.
 *
 * CreateFile on a COM name hands back a handle of ours; everything that can be
 * done to a serial port is then recognised by that handle and answered here
 * rather than forwarded. A real port on a real machine is left completely
 * alone - es3_jvs_open() returns 0 for any other name, and every one of these
 * falls through to the host.
 *
 * The stdcall purges are written out rather than derived because these bypass
 * hle_call_native entirely: there is no callee to pop the arguments, so this
 * has to. Argument counts are from the Win32 headers and a wrong one corrupts
 * the guest's stack immediately, which is at least a loud way to be wrong.
 */
#define JVS_RET(c, val, argc) do { (c)->eax = (uint32_t)(val); \
                                   (c)->esp += 4 + 4 * (argc); } while (0)

static void hle_create_file(CPU *c, HleId id)
{
    static int off = -1;
    const char *name;
    uint32_t h;

    if (off < 0) off = getenv("ES3_NO_COM") != NULL;
    name = es3_arg_string(A32(0));

    /* ES3_NO_COM: refuse the port outright. A diagnostic that separates "the
     * board never answered" from "the game wanted the open itself to fail" -
     * it does not, as it turns out, but it is the first thing to try. */
    if (off && name) {
        const char *p = name;
        if (p[0] == '\\' && p[1] == '\\' && p[2] == '.' && p[3] == '\\') p += 4;
        if ((p[0] == 'C' || p[0] == 'c') && (p[1] == 'O' || p[1] == 'o') &&
            (p[2] == 'M' || p[2] == 'm') && p[3] >= '0' && p[3] <= '9') {
            static unsigned char said;
            if (!said) {
                said = 1;
                fprintf(stderr, "[hle] ES3_NO_COM: refusing %s, which is where "
                                "the JVS I/O board would be\n", name);
            }
            SetLastError(ERROR_FILE_NOT_FOUND);
            JVS_RET(c, 0xFFFFFFFFu, 7);
            return;
        }
    }

    h = name ? es3_jvs_open(name) : 0;
    if (h) { SetLastError(0); JVS_RET(c, h, 7); return; }
    hle_call_native(c, id);
}

/* Configuring a port that is not a port. Every one of these succeeds, because
 * the thing they configure - baud, parity, buffer sizes, timeouts - is a
 * property of a wire this board does not have. */
static void comm_ok(CPU *c, HleId id, int argc)
{
    if (es3_jvs_is_port(A32(0))) {
        es3_jvs_note(hle_name(id), A32(1), A32(2));
        SetLastError(0); JVS_RET(c, 1, argc); return;
    }
    hle_call_native(c, id);
}

static void hle_setup_comm(CPU *c, HleId id)      { comm_ok(c, id, 3); }
static void hle_purge_comm(CPU *c, HleId id)      { comm_ok(c, id, 2); }
static void hle_set_comm_state(CPU *c, HleId id)  { comm_ok(c, id, 2); }
static void hle_set_comm_mask(CPU *c, HleId id)   { comm_ok(c, id, 2); }
static void hle_set_comm_timeouts(CPU *c, HleId id)
{
    if (es3_jvs_is_port(A32(0))) es3_jvs_set_timeouts(A32(1));
    comm_ok(c, id, 2);
}
static void hle_cancel_io_ex(CPU *c, HleId id)
{
    if (es3_jvs_is_port(A32(0))) { es3_jvs_cancel(); SetLastError(0); JVS_RET(c, 1, 2); return; }
    hle_call_native(c, id);
}

/* GetCommState and GetCommTimeouts are asked for a structure, and a caller
 * that reads back what it set is entitled to something coherent. Zeroed with
 * the size field right is coherent; the game overwrites both immediately. */
static void hle_get_comm_state(CPU *c, HleId id)
{
    if (es3_jvs_is_port(A32(0))) {
        uint32_t dcb = A32(1);
        if (dcb) { memset((void *)(uintptr_t)dcb, 0, 28); wr32(dcb, 28); }
        SetLastError(0);
        JVS_RET(c, 1, 2);
        return;
    }
    hle_call_native(c, id);
}

static void hle_get_comm_timeouts(CPU *c, HleId id)
{
    if (es3_jvs_is_port(A32(0))) {
        uint32_t t = A32(1);
        if (t) memset((void *)(uintptr_t)t, 0, 20);
        SetLastError(0);
        JVS_RET(c, 1, 2);
        return;
    }
    hle_call_native(c, id);
}

/* A modem status with nothing asserted - there is no modem, and the game only
 * looks at this to decide whether the line is alive. */
static void hle_get_comm_modem_status(CPU *c, HleId id)
{
    if (es3_jvs_is_port(A32(0))) {
        uint32_t p = A32(1);
        if (p) wr32(p, 0x0020);            /* MS_DSR_ON */
        SetLastError(0);
        JVS_RET(c, 1, 2);
        return;
    }
    hle_call_native(c, id);
}

/* WriteFile(h, buf, n, written, ovl) - the request goes straight into the
 * board, which answers into the pipe the reads come out of. */
static void hle_write_file(CPU *c, HleId id)
{
    if (es3_jvs_is_port(A32(0))) {
        uint32_t n = A32(2), written = A32(3);
        es3_jvs_write(A32(1), n);
        if (written) wr32(written, n);
        SetLastError(0);
        JVS_RET(c, 1, 5);
        return;
    }
    hle_call_native(c, id);
}

/* WriteFileEx(h, buf, n, ovl, routine) - same, and the completion is reported
 * at once because the write itself never blocks on a board that is a function
 * call away. */
static void hle_write_file_ex(CPU *c, HleId id)
{
    if (es3_jvs_is_port(A32(0))) {
        uint32_t n = A32(2), ovl = A32(3);
        es3_jvs_write(A32(1), n);
        if (ovl) { wr32(ovl, 0); wr32(ovl + 4, n); }
        es3_jvs_complete_write(ovl, n, A32(4));
        SetLastError(0);
        JVS_RET(c, 1, 5);
        return;
    }
    hle_call_native(c, id);
}

static void hle_read_file(CPU *c, HleId id)
{
    if (es3_jvs_is_port(A32(0))) {
        uint32_t got = es3_jvs_read(A32(1), A32(2)), read = A32(3);
        if (read) wr32(read, got);
        SetLastError(0);
        JVS_RET(c, 1, 5);
        return;
    }
    hle_call_native(c, id);
}

/* ReadFileEx(h, buf, n, ovl, routine) - posted, not performed. It completes
 * when the board has that many bytes to give, by an APC on this thread, which
 * is where the game's completion routine expects to run. */
static void hle_read_file_ex(CPU *c, HleId id)
{
    if (es3_jvs_is_port(A32(0))) {
        es3_jvs_post_read(A32(1), A32(2), A32(3), A32(4));
        SetLastError(0);
        JVS_RET(c, 1, 5);
        return;
    }
    hle_call_native(c, id);
}

static void hle_close_handle(CPU *c, HleId id)
{
    /* Keep the port: the game closes and reopens it when it decides the board
     * is not answering, and a handle that went away would fail the reopen. */
    if (es3_jvs_is_port(A32(0))) { SetLastError(0); JVS_RET(c, 1, 1); return; }
    hle_call_native(c, id);
}

/* A DLL the game loads itself may rewrite the game's code - see
 * es3_guest_diff(). Diff right after it lands, while nothing else has run. */
static void hle_load_library(CPU *c, HleId id)
{
    const char *name = es3_arg_string(A32(0));
    char kept[96];
    strncpy(kept, name ? name : "a library", sizeof kept - 1);
    kept[sizeof kept - 1] = 0;
    hle_call_native(c, id);
    if (c->eax) es3_guest_diff(kept);
}

static void hle_hook_proc(CPU *c, HleId id) { wrap_callback_arg(c, id, 1); }
static void hle_enum_windows(CPU *c, HleId id) { wrap_callback_arg(c, id, 0); }

static void hle_onexit(CPU *c, HleId id) { wrap_callback_arg(c, id, 0); }
static void hle_seh_filter(CPU *c, HleId id) { wrap_callback_arg(c, id, 0); }
static void hle_signal(CPU *c, HleId id) { wrap_callback_arg(c, id, 1); }
static void hle_qsort(CPU *c, HleId id) { wrap_callback_arg(c, id, 3); }

/*
 * What the game says about itself.
 *
 * An ES3 title is a debug-friendly build shipped to a cabinet: it narrates its
 * own startup through OutputDebugString, and on the cabinet that went to a
 * kernel debugger nobody was watching. Here it is the only account of the
 * boot written by someone who knows what the boot is supposed to do - which
 * subsystem is coming up, which file it wants, which device it did not find.
 *
 * Forwarded as well as echoed: the real call raises and catches
 * DBG_PRINTEXCEPTION_C, and the guest's own SEH frames are involved.
 */
static void hle_debug_string(CPU *c, HleId id)
{
    uint32_t p = A32(0);
    if (p) {
        if (hle_name(id)[strlen(hle_name(id)) - 1] == 'W')
            fprintf(stderr, "[game] %ls\n", (const wchar_t *)(uintptr_t)p);
        else
            fprintf(stderr, "[game] %s\n", (const char *)(uintptr_t)p);
    }
    hle_call_native(c, id);
}

/*
 * What the game threw.
 *
 * `_CxxThrowException(object, throwinfo)` carries the static type of the thing
 * being thrown, and on x86 every pointer in that chain is absolute, so the
 * name is three dereferences away. It is worth printing because an uncaught
 * C++ exception ends the process with 0xE06D7363 and nothing else - and
 * because the name usually says whether the game is reporting a problem it
 * found or hitting one this runtime made.
 *
 * The object comes first in case it is a std::exception: its vtable slot 0 is
 * `what()`, which needs a call, but the first pointer-sized field of most
 * game exception classes is a message anyway.
 */
static void hle_cxx_throw(CPU *c, HleId id)
{
    static volatile LONG shown;
    if (InterlockedIncrement(&shown) <= 4) {
        uint32_t ti = A32(1);
        const char *name = NULL;
        if (ti) {
            uint32_t cta = rd32(ti + 12);                 /* CatchableTypeArray */
            if (cta && rd32(cta) > 0) {
                uint32_t ct = rd32(cta + 4);              /* first CatchableType */
                uint32_t td = ct ? rd32(ct + 4) : 0;      /* TypeDescriptor */
                if (td) name = (const char *)(uintptr_t)(td + 8);
            }
        }
        fprintf(stderr, "\n[throw] the guest threw %s (object %08X)\n",
                name ? name : "something with no type descriptor", A32(0));
        es3_report_state("where it threw");
    }
    hle_call_native(c, id);
}

/*
 * ES3_NO_THREAD_PUMP: refuse D3DX10 its worker threads.
 *
 * The pump is the one place a *library* makes threads that then run lifted
 * code, through the game's own ID3DX10DataLoader. Those threads have whatever
 * stack D3DX10 chose, and lifted code needs far more real stack than the
 * original did - one C frame per guest function with dispatch() between each
 * pair - so one of them overflows and the process ends with a fault the kernel
 * cannot dispatch.
 *
 * The proper fix is for hybrid to switch the real stack as well as the
 * emulated one. This is the other end of the same problem: a game that cannot
 * create a pump loads synchronously instead, on threads this runtime sized.
 * Off by default, because it changes what the game does rather than how it
 * runs.
 */
static void hle_no_thread_pump(CPU *c, HleId id)
{
    static unsigned char said;
    if (!said) {
        said = 1;
        fprintf(stderr, "[hle] refusing %s - its worker threads would run "
                        "lifted code on a stack nobody here chose\n",
                hle_name(id));
    }
    c->eax = 0x80004005u;              /* E_FAIL */
}

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
    /* A hook procedure is a window procedure by another name: USER32 calls it
     * on the guest's behalf, from inside its own message dispatch, and an
     * unthunked one runs the original bytes - which reach their IAT and fault
     * on a sentinel with nothing in the trail to say who called them. Mario
     * Kart installs one and it took a fault at `ReleaseSemaphore`'s sentinel
     * to find it. */
    ptrs += (unsigned)hle_bind("SetWindowsHookExW", hle_hook_proc);
    ptrs += (unsigned)hle_bind("SetWindowsHookExA", hle_hook_proc);
    ptrs += (unsigned)hle_bind("EnumWindows", hle_enum_windows);
    hle_bind("GetSystemMetrics", hle_get_system_metrics);
    hle_bind("LoadLibraryW", hle_load_library);
    hle_bind("LoadLibraryA", hle_load_library);
    hle_bind("CreateFileW", hle_create_file);
    hle_bind("CreateFileA", hle_create_file);
    hle_bind("SetupComm", hle_setup_comm);
    hle_bind("PurgeComm", hle_purge_comm);
    hle_bind("SetCommState", hle_set_comm_state);
    hle_bind("GetCommState", hle_get_comm_state);
    hle_bind("SetCommMask", hle_set_comm_mask);
    hle_bind("SetCommTimeouts", hle_set_comm_timeouts);
    hle_bind("GetCommTimeouts", hle_get_comm_timeouts);
    hle_bind("GetCommModemStatus", hle_get_comm_modem_status);
    hle_bind("CancelIoEx", hle_cancel_io_ex);
    hle_bind("WriteFile", hle_write_file);
    hle_bind("WriteFileEx", hle_write_file_ex);
    hle_bind("ReadFile", hle_read_file);
    hle_bind("ReadFileEx", hle_read_file_ex);
    hle_bind("CloseHandle", hle_close_handle);
    hle_bind("MessageBoxW", hle_message_box);
    hle_bind("MessageBoxA", hle_message_box);
    ptrs += (unsigned)hle_bind("CreateThread", hle_create_thread);
    ptrs += (unsigned)hle_bind("_beginthreadex", hle_create_thread);

    hle_bind("OutputDebugStringA", hle_debug_string);
    hle_bind("OutputDebugStringW", hle_debug_string);

    exits += (unsigned)hle_bind("abort", hle_give_up);
    exits += (unsigned)hle_bind("exit", hle_give_up);
    exits += (unsigned)hle_bind("_exit", hle_give_up);
    exits += (unsigned)hle_bind("_cexit", hle_give_up);
    exits += (unsigned)hle_bind("_amsg_exit", hle_give_up);
    exits += (unsigned)hle_bind("_invoke_watson", hle_give_up);
    exits += (unsigned)hle_bind("TerminateProcess", hle_give_up);
    /* The C++ ones. A game that throws and is not caught reaches
     * `terminate()`, which ends the process through `__fastfail` - no
     * exception, no handler, no message, exit code 0xC0000409 and an empty
     * log. It looks exactly like a hang that stopped. */
    exits += (unsigned)hle_bind("?terminate@@YAXXZ", hle_give_up);
    exits += (unsigned)hle_bind("_purecall", hle_give_up);
    exits += (unsigned)hle_bind("_wassert", hle_give_up);
    exits += (unsigned)hle_bind("_invalid_parameter_noinfo", hle_give_up);
    /* Not an abort, but the other way a run ends without saying anything: the
     * game decides to stop. PostQuitMessage ends the message loop and
     * ExitThread ends a thread without unwinding - and when the last one goes,
     * so does the process, with whatever code it passed. A clean exit code 0
     * and an empty log is what that looks like from outside. */
    hle_bind("_CxxThrowException", hle_cxx_throw);
    ptrs += (unsigned)hle_bind("CreateWindowExW", hle_create_window);
    ptrs += (unsigned)hle_bind("CreateWindowExA", hle_create_window);
    ptrs += (unsigned)hle_bind("SetWindowPos", hle_set_window_pos);
    ptrs += (unsigned)hle_bind("Direct3DCreate9Ex", hle_d3d_create9ex);
    if (getenv("ES3_NO_THREAD_PUMP"))
        hle_bind("D3DX10CreateThreadPump", hle_no_thread_pump);
    /* These two end a thread, and they must not do it standing on the guest's
     * emulated stack - the teardown frees it. See hle_call_native_noreturn. */
    exits += (unsigned)hle_bind("ExitThread", hle_thread_exit);
    exits += (unsigned)hle_bind("_endthreadex", hle_thread_exit);
    exits += (unsigned)hle_bind("PostQuitMessage", hle_give_up);
    exits += (unsigned)hle_bind("UnhandledExceptionFilter", hle_give_up);

    fprintf(stderr,
            "[hle] %u initialiser table(s) walked here so their entries run "
            "lifted, %u callback pointer(s) thunked, %u exit path(s) traced\n",
            tables, ptrs, exits);
}
