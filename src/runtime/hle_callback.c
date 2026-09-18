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
    /*
     * And the whole of this thread's real stack, not a megabyte around wherever
     * it happened to be the first time it crossed.
     *
     * That window was the bug that cost most of a week. es3_teb_cover only
     * widens, so the range recorded on the first crossing is the range the
     * thread keeps - and a guest thread with a 32 MB stack crosses near the
     * top, gets [top-1MB, top+4K], and then descends. The moment esp goes
     * below StackLimit, RtlDispatchException rejects every handler it finds,
     * including the __try inside OutputDebugStringA that is supposed to
     * swallow DBG_PRINTEXCEPTION_C. Nothing catches it, nothing reports it -
     * an informational exception reaches no vectored handler worth printing
     * and no unhandled filter - and the process ends with 0x40010006 as its
     * exit code. Through MSYS that arrives as "exit 6", which is a number
     * belonging to nothing in the source and was chased as one for a long
     * time.
     *
     * teb_limit is DeallocationStack, the real bottom, which is why it is read
     * above rather than StackLimit.
     */
    es3_teb_cover(teb_limit, teb_base);
    {
        /* Sixty-four, because this game has more than sixteen and the ones
         * past the end were the interesting ones - a thread nobody knew about
         * running an update before its subsystem had been built. With the
         * address it came in at, so `ES3_WATCH_VA` has something to aim at. */
        static volatile LONG seen[64];
        LONG self = (LONG)GetCurrentThreadId();
        int i;
        /* Make an overflow on this thread survivable long enough to be
         * reported. Without a guarantee the guard page is the last page: the
         * kernel raises STATUS_STACK_OVERFLOW, has nowhere to build the
         * exception frame, and ends the process on the spot - no vectored
         * handler, no unhandled filter, no Windows Error Reporting record, and
         * an exit code that belongs to nothing in the source.
         *
         * Outside the loop below, and not once per thread, because that loop
         * only has room to remember sixty-four and this game churns more: the
         * sixty-fifth thread onwards would have entered lifted code with no
         * guarantee at all, which is precisely the case whose deaths cannot be
         * seen. Setting it again on a thread that has it is a no-op. */
        ULONG guarantee = 64u << 10;
        SetThreadStackGuarantee(&guarantee);
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

/*
 * A guest function pointer that real code will call, planted where it lives.
 *
 * es3_callback() covers the pointers this runtime can see go past: an import
 * handler knows which argument is a function and swaps a thunk in. It cannot
 * cover a pointer that lifted code pushes itself - and the interesting ones
 * are exactly those, because they are arguments to COM methods rather than to
 * imports. Mario Kart's input is one:
 *
 *     007400DC  push 0x73ff60             ; the DIEnumDevicesCallback
 *     007400E6  mov  edx, [ecx + 0x10]    ; IDirectInput8::EnumDevices
 *     007400EC  call edx
 *
 * 0x0073FF60 is a guest address handed straight to the real DINPUT8.dll,
 * which calls it as machine code. The original bytes are still mapped there,
 * so the callback "runs" - as unlifted code, off an import table full of
 * runtime sentinels. The enumeration finds a controller, calls the callback,
 * and the game learns nothing: no device, no GetDeviceState, no input, and
 * not one error anywhere.
 *
 * Nothing in a static recompilation ever executes the guest image, though.
 * The lifted C is the program and the image is data - so the address is free
 * to become a real jump to a thunk, which is what this does. After it, that
 * address means the same thing to real code as it does to lifted code.
 *
 * rel32 always reaches: both ends are in this process's 32-bit address space.
 */
int es3_plant_callback(uint32_t guest_va)
{
#ifdef _WIN32
    unsigned char *at = (unsigned char *)(uintptr_t)guest_va;
    uint32_t t = es3_callback(guest_va);
    DWORD old;

    if (!t) return 0;
    if (!VirtualProtect(at, 5, PAGE_EXECUTE_READWRITE, &old)) {
        fprintf(stderr, "[callback] cannot make %08X writable to plant a "
                        "jump to its thunk\n", guest_va);
        return 0;
    }
    at[0] = 0xE9;                                  /* jmp rel32 */
    *(int32_t *)(at + 1) = (int32_t)(t - (guest_va + 5));
    FlushInstructionCache(GetCurrentProcess(), at, 5);
    (void)old;
    /*
     * And it STAYS executable, which is the half of this that took longest.
     *
     * guest_load() maps the whole image PAGE_READWRITE on purpose: with the
     * bytes non-executable, real code that calls an unthunked guest pointer
     * faults at a guest address and crash.c turns the fault back into a
     * dispatch. That trap catches every API that simply calls the pointer.
     *
     * It does not catch an API that CHECKS the pointer first. DirectInput is
     * one: IDirectInput8::EnumDevices validates its callback, finds a page
     * with no execute permission, decides the argument is bad and returns
     * without calling anything. No callback, no devices, and a HRESULT the
     * game does not look at - so the whole controller simply is not there.
     * Restoring the old protection here reproduced that exactly, with the
     * correct jump sitting at the address unread.
     *
     * So the planted stub keeps execute permission. The cost is that the rest
     * of that one page is executable too, and an unthunked callback landing
     * in it would run raw bytes instead of faulting - a narrow trade for the
     * page that has a real stub on it, and the only way a validating API can
     * be satisfied.
     */

    /* Keep es3_guest_diff() honest: this runtime just rewrote the game's
     * code, and without this the next LoadLibrary would report it as the
     * DLL's doing. */
    es3_guest_resnapshot(guest_va, 5);
    fprintf(stderr, "[callback] %08X now jumps to its own lifted code, so a "
                    "real DLL handed that pointer reaches it\n"
                    "           thunk %08X, bytes %02X %02X %02X %02X %02X, "
                    "lands on %08X\n", guest_va, t,
            at[0], at[1], at[2], at[3], at[4],
            (uint32_t)(guest_va + 5 + *(int32_t *)(at + 1)));
    {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(at, &mbi, sizeof mbi))
            fprintf(stderr, "           page %08X protect %lX%s\n",
                    (uint32_t)(uintptr_t)mbi.BaseAddress, mbi.Protect,
                    (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                    PAGE_EXECUTE_READWRITE |
                                    PAGE_EXECUTE_WRITECOPY))
                        ? " (executable)"
                        : " (NOT executable - a real DLL calling this will"
                          " fault instead)");
    }
    return 1;
#else
    (void)guest_va;
    return 0;
#endif
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
/* Sixteen, measured, not chosen: at 8 MB this game overflowed a worker eight
 * seconds into the boot and the process was gone with the log stopping
 * mid-line; at 16 it boots. Not more - at 32, thirty worker threads reserve a
 * gigabyte, the guest's own allocations start failing instead, and the run
 * dies earlier and somewhere that looks nothing like a stack. */
#define THREAD_STACK_SIZE (16u << 20)

/* ES3_THREAD_STACK_MB raises the floor without a rebuild. It is a floor that
 * has had to move once already, and the symptom when it is too low - a process
 * that is simply gone, with a log that stops mid-line - looks like anything
 * but a stack, so the knob is worth having where the next person will find it.
 * Reservation only: thirty worker threads at 32 MB cost a gigabyte of address
 * space and not one page of memory. */
static uint32_t thread_stack_size(void)
{
    static uint32_t cached;
    const char *e;
    if (cached) return cached;
    e = getenv("ES3_THREAD_STACK_MB");
    cached = e && atoi(e) > 0 ? (uint32_t)atoi(e) << 20 : THREAD_STACK_SIZE;
    return cached;
}

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

/*
 * How big the window is allowed to be: the desktop's work area, less the
 * frame, and not a fixed 1280x720.
 *
 * A fixed cap looks harmless and crops the picture. The swap chain is made at
 * the size the GAME asked for - 1360x768 for this cabinet - and DXGI's flip
 * models blit that back buffer into the client area one pixel to one pixel,
 * with no scaling. A client area smaller than the back buffer therefore does
 * not shrink the picture, it shows the top-left corner of it: the right-hand
 * side and the bottom of a cabinet screen are simply missing.
 *
 * So shrink only when the window genuinely will not fit next to the taskbar,
 * which for a 768-line cabinet on any ordinary desktop it does.
 *
 * ES3_MAX_W / ES3_MAX_H override, for a small screen or a deliberate crop.
 */
static void window_cap(int *maxw, int *maxh)
{
    RECT wa;
    const char *ew = getenv("ES3_MAX_W"), *eh = getenv("ES3_MAX_H");

    if (SystemParametersInfoA(SPI_GETWORKAREA, 0, &wa, 0)) {
        *maxw = wa.right - wa.left;
        *maxh = wa.bottom - wa.top;
    } else {
        *maxw = GetSystemMetrics(SM_CXSCREEN);
        *maxh = GetSystemMetrics(SM_CYSCREEN);
    }
    /* Room for the frame, so the outer window still fits after it is grown. */
    *maxw -= GetSystemMetrics(SM_CXSIZEFRAME) * 2;
    *maxh -= GetSystemMetrics(SM_CYSIZEFRAME) * 2 +
             GetSystemMetrics(SM_CYCAPTION);
    if (ew) *maxw = atoi(ew);
    if (eh) *maxh = atoi(eh);
    if (*maxw < 320) *maxw = 320;
    if (*maxh < 240) *maxh = 240;
}

/*
 * Alt must not stop the game.
 *
 * The window the game asked for was WS_POPUP: no caption, no system menu,
 * and Alt meant nothing to it. windowed() trades that for
 * WS_OVERLAPPEDWINDOW so the thing can be moved and closed on a desktop,
 * and WS_SYSMENU comes with it - so now a tap on Alt is SC_KEYMENU,
 * DefWindowProc opens the system menu, and the menu's modal loop owns the
 * thread that pumps messages. The game does not crash and does not quit; it
 * simply stops, until something dismisses the menu. From the outside that
 * reads as "Alt pauses it and input does nothing", which is exactly what it
 * is, and it is this runtime's doing rather than the game's.
 *
 * Subclassing is enough: swallow the two system commands that open a menu
 * and hand everything else to the window procedure the game installed. Only
 * the window whose style was actually changed, and only the first one -
 * every other window keeps its own procedure, and one saved pointer cannot
 * serve two.
 */
static WNDPROC g_game_wndproc;
static int g_wndproc_unicode;

static LRESULT CALLBACK es3_menu_eater(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if (m == WM_SYSCOMMAND && ((w & 0xFFF0) == SC_KEYMENU ||
                               (w & 0xFFF0) == SC_MOUSEMENU))
        return 0;
    return g_wndproc_unicode ? CallWindowProcW(g_game_wndproc, h, m, w, l)
                             : CallWindowProcA(g_game_wndproc, h, m, w, l);
}

static void es3_no_alt_menu(HWND h)
{
    if (g_game_wndproc || !h) return;
    g_wndproc_unicode = IsWindowUnicode(h);
    g_game_wndproc = (WNDPROC)(uintptr_t)(g_wndproc_unicode
        ? SetWindowLongPtrW(h, GWLP_WNDPROC, (LONG_PTR)(uintptr_t)es3_menu_eater)
        : SetWindowLongPtrA(h, GWLP_WNDPROC, (LONG_PTR)(uintptr_t)es3_menu_eater));
    if (!g_game_wndproc) return;
    fprintf(stderr, "[hle] and Alt will not open its system menu, which would "
                    "stop the frame loop until the menu closed\n");
}

static void hle_create_window(CPU *c, HleId id)
{
    int want_menu_fix = 0;
    if (windowed()) {
        uint32_t style = A32(3);
        int w = (int)A32(6), h = (int)A32(7), maxw, maxh;
        window_cap(&maxw, &maxh);
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
        if (w > maxw) w = maxw;
        if (h > maxh) h = maxh;

        /*
         * And grow it by the frame, because CreateWindowEx is given the
         * OUTER size and the swap chain is made at the client size.
         *
         * Without this the game presents a 1280x720 back buffer into a
         * client area that is the frame narrower and the title bar shorter,
         * and a desktop-sized slice of the right edge and the bottom of the
         * picture is simply not on screen - which is exactly what it looks
         * like: a cabinet screen with its right side and bottom cut off.
         * WS_POPUP had no frame, so the game was right and this clamp was
         * wrong the moment it traded the style.
         */
        {
            RECT r; r.left = 0; r.top = 0; r.right = w; r.bottom = h;
            int cw = w, ch = h;
            static unsigned char told;
            if (AdjustWindowRectEx(&r, (DWORD)style, A32(9) != 0,
                                   (DWORD)A32(0))) {
                w = r.right - r.left;
                h = r.bottom - r.top;
            }
            if (!told) {
                told = 1;
                fprintf(stderr, "[hle] its picture is %dx%d, so the window is "
                                "%dx%d and the client area is the whole "
                                "picture (cap %dx%d)\n",
                        cw, ch, w, h, maxw, maxh);
            }
        }
        wr32(c->esp + 4 + 4 * 6, (uint32_t)w);
        wr32(c->esp + 4 + 4 * 7, (uint32_t)h);
        wr32(c->esp + 4 + 4 * 4, 64);                 /* x */
        wr32(c->esp + 4 + 4 * 5, 64);                 /* y */
        want_menu_fix = 1;
    }
    hle_call_native(c, id);
    if (want_menu_fix && c->eax) es3_no_alt_menu((HWND)(uintptr_t)c->eax);
}

/* SetWindowPos(hwnd, after, x, y, cx, cy, flags) - arguments 4 and 5. */
static void hle_set_window_pos(CPU *c, HleId id)
{
    if (windowed()) {
        int w = (int)A32(4), h = (int)A32(5), maxw, maxh;
        window_cap(&maxw, &maxh);
        if (w > maxw || h > maxh) {
            HWND hw = (HWND)(uintptr_t)A32(0);
            RECT r;
            if (w > maxw) w = maxw;
            if (h > maxh) h = maxh;
            /* Outer size again, and the same crop if it is not grown by the
             * frame - see hle_create_window. The style has to be read off the
             * window because this call does not carry one. */
            r.left = 0; r.top = 0; r.right = w; r.bottom = h;
            if (hw && AdjustWindowRectEx(&r,
                    (DWORD)GetWindowLongPtrA(hw, GWL_STYLE),
                    GetMenu(hw) != NULL,
                    (DWORD)GetWindowLongPtrA(hw, GWL_EXSTYLE))) {
                w = r.right - r.left;
                h = r.bottom - r.top;
            }
            wr32(c->esp + 4 + 4 * 4, (uint32_t)w);
            wr32(c->esp + 4 + 4 * 5, (uint32_t)h);
        }
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
                want >> 10, thread_stack_size() >> 20);
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
    wr32(c->esp + 4 + 4 * 1, thread_stack_size());
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

/*
 * The card reader, watched rather than answered.
 *
 * Mario Kart's IC card unit is on a COM port that jvs.c deliberately does not
 * claim (0x005BD830 picks it by name), because answering a card reader in JVS
 * is worse than not answering it: the game reports -301, turns it into E07-11,
 * and that error's row in the mode table suppresses the frame loop's task tick
 * - a black screen instead of a game.
 *
 * Which means the protocol has to be learned before it can be spoken, and the
 * cheapest way to learn it is to let the port work exactly as it does now and
 * print what crosses it. On this machine COM3 and COM4 are Bluetooth serial
 * ports: they open, they accept writes, and they never answer, so the reader
 * is already talking into a void. This just makes the void legible.
 *
 * ES3_TRACE_CARD to switch on. Nothing here changes what the game is told.
 */
static struct { uint32_t h; int port; } g_card_h[8];
static int g_card_n;

static int card_trace(void)
{
    static int on = -1;
    if (on < 0) on = getenv("ES3_TRACE_CARD") != NULL;
    return on;
}

/* A COM handle the runtime did not claim, remembered so traffic on it can be
 * recognised later by handle alone - the name is only available at open. */
static void card_note_open(const char *name, uint32_t h)
{
    const char *p = name;
    int n;

    if (!card_trace() || !name || !h || h == 0xFFFFFFFFu) return;
    if (p[0] == '\\' && p[1] == '\\' && p[2] == '.' && p[3] == '\\') p += 4;
    if (!((p[0] == 'C' || p[0] == 'c') && (p[1] == 'O' || p[1] == 'o') &&
          (p[2] == 'M' || p[2] == 'm') && p[3] >= '0' && p[3] <= '9')) return;
    n = p[3] - '0';
    if (p[4] >= '0' && p[4] <= '9') n = n * 10 + (p[4] - '0');
    if (g_card_n < 8) {
        g_card_h[g_card_n].h = h;
        g_card_h[g_card_n].port = n;
        g_card_n++;
        fprintf(stderr, "[card] watching COM%d (handle %08X)\n", n, h);
    }
}

static int card_port_of(uint32_t h)
{
    int i;
    if (!card_trace() || !h) return 0;
    for (i = 0; i < g_card_n; i++)
        if (g_card_h[i].h == h) return g_card_h[i].port;
    return 0;
}

/* Bytes both ways, hex and ASCII. Length matters as much as content here: a
 * reader protocol is usually framed, and the frame shows up as a repeated
 * first byte and a length that agrees with it. */
static void card_dump(int port, const char *dir, uint32_t buf, uint32_t n)
{
    const unsigned char *p = (const unsigned char *)(uintptr_t)buf;
    uint32_t i;

    if (!p || !n) return;
    if (n > 64) n = 64;
    fprintf(stderr, "[card] COM%d %s %u:", port, dir, n);
    for (i = 0; i < n; i++) fprintf(stderr, " %02X", p[i]);
    fprintf(stderr, "  |");
    for (i = 0; i < n; i++)
        fputc(p[i] >= 0x20 && p[i] < 0x7F ? (char)p[i] : '.', stderr);
    fprintf(stderr, "|\n");
    fflush(stderr);
}

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

    /* And the card reader, on a different port, answered by card.c. Claimed
     * here rather than left to the host because the I/O emulator the JConfig
     * tree ships answers this port itself, badly - see card.c. */
    h = name ? es3_card_open(name) : 0;
    if (h) { SetLastError(0); JVS_RET(c, h, 7); return; }

    /* ES3_TRACE_FILES: every distinct path the game opens, once each, with
     * whether it got a handle. "Does the game read this file at all" is the
     * first question whenever editing one of its files changes nothing, and
     * without this it is unanswerable from outside. */
    if (name && getenv("ES3_TRACE_FILES") && !file_trace_boring(name)) {
        static char seen[64][160];
        static int nseen;
        int i;
        for (i = 0; i < nseen && strcmp(seen[i], name); i++) {}
        if (i == nseen && nseen < 64) {
            strncpy(seen[nseen], name, sizeof seen[0] - 1);
            seen[nseen][sizeof seen[0] - 1] = 0;
            nseen++;
            hle_call_native(c, id);
            fprintf(stderr, "[file] %s -> %s\n", name,
                    c->eax == 0xFFFFFFFFu ? "no" : "opened");
            card_note_open(name, c->eax);
            return;
        }
    }
    hle_call_native(c, id);
    card_note_open(name, c->eax);
}

/* Configuring a port that is not a port. Every one of these succeeds, because
 * the thing they configure - baud, parity, buffer sizes, timeouts - is a
 * property of a wire this board does not have. */
static void comm_ok(CPU *c, HleId id, int argc)
{
    if (es3_jvs_is_port(A32(0)) || es3_card_is_port(A32(0))) {
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
    if (es3_card_is_port(A32(0))) { es3_card_cancel(); SetLastError(0); JVS_RET(c, 1, 2); return; }
    if (es3_jvs_is_port(A32(0))) { es3_jvs_cancel(); SetLastError(0); JVS_RET(c, 1, 2); return; }
    hle_call_native(c, id);
}

/* GetCommState and GetCommTimeouts are asked for a structure, and a caller
 * that reads back what it set is entitled to something coherent. Zeroed with
 * the size field right is coherent; the game overwrites both immediately. */
static void hle_get_comm_state(CPU *c, HleId id)
{
    if (es3_jvs_is_port(A32(0)) || es3_card_is_port(A32(0))) {
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
    if (es3_jvs_is_port(A32(0)) || es3_card_is_port(A32(0))) {
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
    if (es3_jvs_is_port(A32(0)) || es3_card_is_port(A32(0))) {
        uint32_t p = A32(1);
        if (p) wr32(p, 0x0020);            /* MS_DSR_ON */
        SetLastError(0);
        JVS_RET(c, 1, 2);
        return;
    }
    hle_call_native(c, id);
}

/* Who in the game is talking to the port.
 *
 * Which guest function owns a serial conversation is most of the question
 * when the bytes on it are not the protocol the runtime is answering, and it
 * is one read: the return address the caller pushed is on top of the guest
 * stack. Printed once per distinct caller, under ES3_TRACE_JVS. */
static void jvs_note_caller(CPU *c)
{
    static uint32_t seen[8];
    static int n;
    uint32_t from;
    int i;
    if (!getenv("ES3_TRACE_JVS")) return;
    from = rd32(c->esp);
    for (i = 0; i < n; i++) if (seen[i] == from) return;
    if (n < 8) seen[n++] = from;
    fprintf(stderr, "[jvs] the port is being driven from %08X\n", from);
}

/* Who in the game is talking to the card reader.
 *
 * Same question as jvs_note_caller, for the other port: the game reads a card
 * and decides it is not a banapassport without ever asking its server, so the
 * code that makes that decision is downstream of whoever drives this
 * conversation. Printed once per distinct caller under ES3_TRACE_CARD.
 *
 * It names one frame, and one frame is not always the answer. Here it printed
 * 007B00D7, which is inside a generic "write all of this buffer" helper at
 * 007B0090 that loops on the WriteFile pointer in 0081D0D0 - true, and about
 * the C runtime rather than about cards. The reader driver was found by taking
 * that address into the lifted source and walking the call graph up instead:
 *
 *   007B0090  write the whole buffer      (six call sites, five senders)
 *   007ABE40  write one PN53x frame       (preamble, length, payload, sum)
 *   007A9AA0  -> 007A9A80 / 007A9BAC      no direct callers: reached by pointer
 *   007AA3C0  the reader's state machine, which installs 007A9A80 as a
 *             callback at 007AA470 and keeps its state around 00943550
 *
 * So the address below is where to start, not where to look. */
static void card_note_caller(CPU *c)
{
    static uint32_t seen[8];
    static int n;
    uint32_t from;
    int i;
    if (!getenv("ES3_TRACE_CARD")) return;
    from = rd32(c->esp);
    for (i = 0; i < n; i++) if (seen[i] == from) return;
    if (n < 8) seen[n++] = from;
    fprintf(stderr, "[card] the reader is being driven from %08X\n", from);
    fflush(stderr);
}

/* WriteFile(h, buf, n, written, ovl) - the request goes straight into the
 * board, which answers into the pipe the reads come out of. */
static void hle_write_file(CPU *c, HleId id)
{
    if (es3_jvs_is_port(A32(0))) {
        uint32_t n = A32(2), written = A32(3);
        jvs_note_caller(c);
        es3_jvs_write(A32(1), n);
        if (written) wr32(written, n);
        SetLastError(0);
        JVS_RET(c, 1, 5);
        return;
    }
    if (es3_card_is_port(A32(0))) {
        uint32_t n = A32(2), written = A32(3);
        card_note_caller(c);
        es3_card_write(A32(1), n);
        if (written) wr32(written, n);
        SetLastError(0);
        JVS_RET(c, 1, 5);
        return;
    }
    {
        int port = card_port_of(A32(0));
        if (port) card_dump(port, "<-", A32(1), A32(2));
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
        jvs_note_caller(c);
        es3_jvs_write(A32(1), n);
        if (ovl) { wr32(ovl, 0); wr32(ovl + 4, n); }
        es3_jvs_complete_write(ovl, n, A32(4));
        SetLastError(0);
        JVS_RET(c, 1, 5);
        return;
    }
    if (es3_card_is_port(A32(0))) {
        uint32_t n = A32(2), ovl = A32(3);
        card_note_caller(c);
        es3_card_write(A32(1), n);
        if (ovl) { wr32(ovl, 0); wr32(ovl + 4, n); }
        es3_card_complete_write(ovl, n, A32(4));
        SetLastError(0);
        JVS_RET(c, 1, 5);
        return;
    }
    {
        int port = card_port_of(A32(0));
        if (port) card_dump(port, "<-", A32(1), A32(2));
    }
    hle_call_native(c, id);
}

static void hle_read_file(CPU *c, HleId id)
{
    int port;
    uint32_t buf, read;

    if (es3_jvs_is_port(A32(0))) {
        uint32_t got = es3_jvs_read(A32(1), A32(2)), read2 = A32(3);
        if (read2) wr32(read2, got);
        SetLastError(0);
        JVS_RET(c, 1, 5);
        return;
    }
    if (es3_card_is_port(A32(0))) {
        uint32_t got = es3_card_read(A32(1), A32(2)), read2 = A32(3);
        if (read2) wr32(read2, got);
        SetLastError(0);
        JVS_RET(c, 1, 5);
        return;
    }
    /* Captured before the call: ReadFile is stdcall, so by the time it returns
     * the arguments are no longer on the guest's stack. */
    port = card_port_of(A32(0));
    buf  = A32(1);
    read = A32(3);
    hle_call_native(c, id);
    if (port && c->eax && read)
        card_dump(port, "->", buf, rd32(read));
}

/* ReadFileEx(h, buf, n, ovl, routine) - posted, not performed. It completes
 * when the board has that many bytes to give, by an APC on this thread, which
 * is where the game's completion routine expects to run. */
static void hle_read_file_ex(CPU *c, HleId id)
{
    if (es3_card_is_port(A32(0))) {
        es3_card_post_read(A32(1), A32(2), A32(3), A32(4));
        SetLastError(0);
        JVS_RET(c, 1, 5);
        return;
    }
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
    if (es3_jvs_is_port(A32(0)) || es3_card_is_port(A32(0))) { SetLastError(0); JVS_RET(c, 1, 1); return; }
    hle_call_native(c, id);
}

/* A DLL the game loads itself may rewrite the game's code - see
 * es3_guest_diff(). Diff right after it lands, while nothing else has run. */
/*
 * The I/O emulator a JConfig tree ships, which a recompilation must not load.
 *
 * These DLLs exist to give a cabinet game a gamepad, and they do it by
 * rewriting the running game's code - so on a static recompilation they patch
 * bytes nothing executes and change nothing. That was already known and
 * looked harmless.
 *
 * It is not harmless. JVSEmuMK also detours DirectInput8Create and hands the
 * game its OWN IDirectInput8, whose EnumDevices enumerates nothing and
 * returns 1. That is deliberate on a patched binary - the emulator intends to
 * supply input through the game code it rewrote, so it wants the game's own
 * DirectInput to find nothing. On a recompilation the rewritten code never
 * runs, so all that is left is the half that disables the real path:
 *
 *     [from 007400EE] 72D834B0 [JVSEmuMK.DLL+0x34B0](..., 4, 0073FF60, ...) = 1
 *
 * with the emulator out of the way, the same call is DINPUT8.dll+0x4410 -
 * IDirectInput8W::EnumDevices - and the game's callback runs and finds the
 * controller.
 *
 * So refuse it. The game's stub takes a failed LoadLibrary in its stride, and
 * what it wanted the DLL for is a thing this runtime does not need.
 *
 * ES3_LOAD_IO_EMULATOR=1 loads it anyway, which is how to see a title that
 * genuinely depends on one.
 */
static int refuse_io_emulator(const char *name)
{
    static const char *const EMU[] = { "JVSEmuMK", "JVSEmu", "jvsemu" };
    size_t i;
    const char *leaf;
    /* Off by default: the emulator also stands in for the drive board, and
     * without it the boot sits on DRIVE UNIT SERIAL NUMBER for ever. What it
     * does to DirectInput is undone in hle_dinput8_create() instead, which
     * keeps the half that works. ES3_NO_IO_EMULATOR=1 refuses it outright. */
    if (!name || !getenv("ES3_NO_IO_EMULATOR")) return 0;
    leaf = strrchr(name, '\\');
    if (!leaf) leaf = strrchr(name, '/');
    leaf = leaf ? leaf + 1 : name;
    for (i = 0; i < sizeof EMU / sizeof EMU[0]; i++) {
        size_t n = strlen(EMU[i]);
        if (_strnicmp(leaf, EMU[i], n) == 0 &&
            (leaf[n] == 0 || _stricmp(leaf + n, ".dll") == 0))
            return 1;
    }
    return 0;
}

/* The game loads thousands of assets under Data/, and they are never the
 * question. ES3_TRACE_FILES_ALL keeps them. */
static int file_trace_boring(const char *n)
{
    if (getenv("ES3_TRACE_FILES_ALL")) return 0;
    while (*n == '.' || *n == '/' || *n == '\\') n++;
    return (n[0] == 'D' || n[0] == 'd') && (n[1] == 'a') && (n[2] == 't') &&
           (n[3] == 'a') && (n[4] == '/' || n[4] == '\\');
}

/*
 * ES3_TRACE_FILES, for the CRT half.
 *
 * A game opens files two ways and only one of them is CreateFile. This one
 * matters because the cabinet's own data - the operator settings among it -
 * goes through the CRT: fopen_s(FILE**, path, mode). Argument 1 is the path.
 */
static void hle_fopen_s(CPU *c, HleId id)
{
    const char *name = es3_arg_string(A32(1));
    if (name && getenv("ES3_TRACE_FILES") && !file_trace_boring(name)) {
        static char seen[64][160];
        static int nseen;
        int i;
        for (i = 0; i < nseen && strcmp(seen[i], name); i++) {}
        if (i == nseen && nseen < 64) {
            strncpy(seen[nseen], name, sizeof seen[0] - 1);
            seen[nseen][sizeof seen[0] - 1] = 0;
            nseen++;
            hle_call_native(c, id);
            fprintf(stderr, "[file] fopen %s -> %s\n", name,
                    c->eax == 0 ? "opened" : "no");
            return;
        }
    }
    hle_call_native(c, id);
}

/*
 * Give the game back the real DirectInput.
 *
 * The I/O emulator imports DirectInput8Create, GetProcAddress and
 * VirtualProtect, and what it does with them is detour
 * dinput8!DirectInput8Create in place so the GAME's call returns the
 * emulator's own IDirectInput8 - one whose EnumDevices reports nothing and
 * returns 1. On the patched binary that is coherent: the emulator feeds input
 * through the game code it rewrote and does not want the game finding devices
 * by itself. On a recompilation the rewritten code never runs, so the detour
 * is pure loss, and it is invisible - the game asks for controllers, is told
 * there are none, and reports nothing.
 *
 * The forwarding address is resolved at startup, before the emulator is
 * loaded, so the original prologue can be kept and put back at the moment the
 * game actually calls. Restoring it leaves the emulator loaded and every other
 * thing it does intact - including the drive board, which the boot needs.
 *
 * ES3_KEEP_DINPUT_DETOUR leaves the hook alone, which is how to watch the
 * enumeration find a controller and hand it to nobody.
 */
static unsigned char g_di8_orig[16];
static unsigned char *g_di8_addr;

void es3_dinput8_snapshot(void)
{
    HMODULE m = LoadLibraryA("dinput8.dll");
    if (!m) return;
    g_di8_addr = (unsigned char *)(void *)GetProcAddress(m, "DirectInput8Create");
    if (g_di8_addr) memcpy(g_di8_orig, g_di8_addr, sizeof g_di8_orig);
}

/*
 * ES3_TRACE_IOBOARD: how far the game's own USB I/O enumeration gets.
 *
 * An ES3 cabinet's switches, wheel and pedals arrive on a Namco I/O board -
 * USB VID 0x0B9A, PID 0x0C10, which Mario Kart names as literals at
 * 0x007A8743. The game finds it the ordinary Windows way:
 * SetupDiGetClassDevsW on an interface GUID, SetupDiEnumDeviceInterfaces,
 * SetupDiGetDeviceInterfaceDetailW for the device path, CreateFileW on that
 * path, then DeviceIoControl.
 *
 * On a desktop the first of those finds nothing and the rest never happen, so
 * a port has two choices: answer the board COUNT and leave the board
 * unopened - which is what this one did, and it is exactly why the game has
 * an I/O board it never reads a single switch from - or present a synthetic
 * device and let the game's own driver code run against it.
 *
 * The second is the right answer for a platform with more than one title on
 * it, and it needs the board's IOCTL protocol, which nothing documents. So
 * measure before building: let the real enumeration run and print every call
 * and what it answered. Whatever the game asks for after the last thing that
 * succeeds is the next thing that has to exist.
 */
static int io_trace(void)
{
    static int on = -1;
    if (on < 0) on = getenv("ES3_TRACE_IOBOARD") != NULL;
    return on;
}

static void ioboard_new_scan(void);

static void hle_setupdi_classdevs(CPU *c, HleId id)
{
    /*
     * A scan is starting, so forget which port had the board.
     *
     * The claim used to be pinned to the hub HANDLE, and Windows recycles
     * handle numbers: a closed hub's number comes back as a different hub, so
     * the board landed on more than one of them in a single pass - the game
     * counted 2 on one run and 4 on the next, and wants exactly 1 - while on
     * later passes the handle differed and the claim was refused altogether,
     * counting 0.
     *
     * The scan is the right unit, and SetupDiGetClassDevsW opens one. Claim
     * the first empty port after each of these and there is exactly one
     * board every time, whatever the handles happen to be. It is also
     * title-agnostic, which a hook on one game's enumeration would not be.
     */
    ioboard_new_scan();
    hle_call_native(c, id);
    if (io_trace())
        fprintf(stderr, "[io] SetupDiGetClassDevsW(flags %X) -> %08X%s\n",
                A32(3), c->eax,
                c->eax == 0xFFFFFFFFu ? "  INVALID_HANDLE_VALUE" : "");
}

static void hle_setupdi_enum_iface(CPU *c, HleId id)
{
    uint32_t idx = A32(3);
    hle_call_native(c, id);
    if (io_trace())
        fprintf(stderr, "[io] SetupDiEnumDeviceInterfaces(#%u) -> %u%s\n",
                idx, c->eax, c->eax ? "" : "  (no more devices)");
}

static void hle_setupdi_iface_detail(CPU *c, HleId id)
{
    uint32_t detail = A32(2), want = A32(3);
    hle_call_native(c, id);
    if (io_trace()) {
        fprintf(stderr, "[io] SetupDiGetDeviceInterfaceDetailW(size %u) -> %u",
                want, c->eax);
        if (c->eax && detail)
            fprintf(stderr, "  path %ls",
                    (const wchar_t *)(uintptr_t)(detail + 4u));
        fprintf(stderr, "\n");
    }
}

/*
 * A Namco I/O board on a port that has nothing in it.
 *
 * The game finds its board by walking the real USB tree, and every step of
 * that walk works on a desktop - measured with ES3_TRACE_IOBOARD. What it
 * never finds is a device with VID 0x0B9A, PID 0x0C10, because none is
 * plugged in. So rather than answer the board COUNT and leave the board
 * unopened - which is what a stand-in in a game project used to do, and why
 * the game had an I/O board it never read a switch from - say that one port
 * has a board in it and let the game's own driver code do the rest.
 *
 * 0x007A7D40 is the port walk, and its tests are explicit about what a board
 * looks like. With the request buffer at [ebp-0x174]:
 *
 *     007A7F1C  cmp dword ptr [ebp - 0x155], 1   ; ConnectionStatus
 *     007A7F2C  mov cx, word ptr [ebp - 0x168]   ; idVendor
 *     007A7F38  cmp cx, ax                       ; ...against the wanted one
 *     007A7F40  mov ax, word ptr [ebp - 0x166]   ; idProduct
 *     007A7FB4  inc dword ptr [edx]              ; a match bumps the count
 *
 * which are offsets 31, 12 and 14 of USB_NODE_CONNECTION_INFORMATION_EX -
 * ConnectionStatus, and idVendor/idProduct inside the USB_DEVICE_DESCRIPTOR
 * that starts at 4. DeviceIsHub at 24 decides whether the walk recurses into
 * the port, so a board must say it is not a hub or the walk goes looking for
 * children that do not exist.
 *
 * Exactly one port, and only a port Windows reports as EMPTY: rewriting a
 * port with a real device on it would point the game at that device, and
 * the first thing it does after a match is open it.
 *
 * ES3_IOBOARD=1 turns this on. Off by default while the protocol underneath
 * it is still being worked out - with it on, a game project's board-count
 * stand-in should step aside (ES3_NO_BOARD=1) so the real walk runs.
 */
#define ES3_IOB_VID 0x0B9Au           /* Namco */
#define ES3_IOB_PID 0x0C10u

/* USB_NODE_CONNECTION_INFORMATION_EX, by byte. */
#define IOB_VENDOR   12u
#define IOB_PRODUCT  14u
#define IOB_CONFIG   22u
#define IOB_SPEED    23u
#define IOB_IS_HUB   24u
#define IOB_STATUS   31u

static int ioboard_on(void)
{
    static int on = -1;
    if (on < 0) on = getenv("ES3_IOBOARD") != NULL;
    return on;
}

/* Claim one empty port, once, and remember which so the answer is stable:
 * the game asks about the same port more than once and must be told the
 * same thing every time. */
static uint32_t g_iob_port = 0xFFFFFFFFu, g_iob_hub;

static void ioboard_new_scan(void)
{
    g_iob_port = 0xFFFFFFFFu;
    g_iob_hub  = 0;
}

static void ioboard_claim(uint32_t hub, uint32_t port, uint32_t buf,
                          uint32_t len)
{
    uint32_t status;

    if (!ioboard_on() || !buf || len < 35u) return;

    status = rd32(buf + IOB_STATUS);

    /* One hub AND one port, because a port number alone is not a place: the
     * walk asks every hub about its own ports, so keying on the number would
     * put a board on each of them and the game wants exactly one. Ports are
     * numbered from 1 - a 0 here is a buffer the walk has not filled in, and
     * claiming it would be claiming nothing. */
    if (port < 1u) return;

    if (g_iob_port == 0xFFFFFFFFu) {
        if (status != 0) return;              /* something is really there */
        g_iob_hub  = hub;
        g_iob_port = port;
        /* Once, not once per scan: the walk runs continuously. */
        {
            static int said;
            if (!said) {
                said = 1;
                fprintf(stderr, "[io] hub %08X port %u is empty; putting a "
                                "Namco I/O board there (VID %04X PID %04X), "
                                "one per scan\n",
                        hub, port, ES3_IOB_VID, ES3_IOB_PID);
            }
        }
    } else {
        /*
         * One rewrite per scan, and not a second on the strength of the hub
         * handle matching.
         *
         * The walk asks each hub about each of its ports once, and the count
         * the game reads is one per port that answered like a board. So
         * exactly one rewritten answer per scan is exactly one board - and
         * that is the only way to say it that a recycled handle cannot
         * break. Keying the repeat on (hub, port) instead let another hub's
         * port 1 match a reused handle number and be rewritten too, which
         * the game counted as a second board: 2 on one run, 4 on the next.
         */
        return;
    }

    wr8(buf + 4u, 18);                        /* bLength */
    wr8(buf + 5u, 1);                         /* bDescriptorType = DEVICE */
    wr16(buf + IOB_VENDOR, (uint16_t)ES3_IOB_VID);
    wr16(buf + IOB_PRODUCT, (uint16_t)ES3_IOB_PID);
    /*
     * And the string indices, which is where the cabinet's ID comes from.
     *
     * The device descriptor the game reads is the one inside this struct -
     * it never asks for a device descriptor separately - so leaving
     * iSerialNumber at the zero Windows put there means a board with no
     * serial, and the game writes a blank cabinet ID over whatever was in
     * +0x498 and then raises mode 0x52 comparing it with what it remembers.
     * Naming the strings here is what makes it ask for string 3.
     */
    wr8(buf + 4u + 14u, 1);                   /* iManufacturer */
    wr8(buf + 4u + 15u, 2);                   /* iProduct */
    wr8(buf + 4u + 16u, 3);                   /* iSerialNumber */
    wr8(buf + 4u + 17u, 1);                   /* bNumConfigurations */
    wr16(buf + 4u + 2u, 0x0200);              /* bcdUSB 2.00 */
    wr8(buf + 4u + 4u, 0xFF);                 /* vendor class */
    wr8(buf + 4u + 7u, 64);                   /* bMaxPacketSize0 */
    wr8(buf + IOB_CONFIG, 1);
    wr8(buf + IOB_SPEED, 1);                  /* full speed */
    wr8(buf + IOB_IS_HUB, 0);                 /* not a hub: do not recurse */
    wr32(buf + IOB_STATUS, 1);                /* DeviceConnected */
}

/*
 * Answer the board's descriptors.
 *
 * 0x220410 is IOCTL_USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION and its input is
 * a USB_DESCRIPTOR_REQUEST: ConnectionIndex at 0, an eight-byte setup packet
 * at 4, and room for the answer from 12. wValue carries the descriptor type
 * in its high byte and the index in its low.
 *
 * The real call cannot succeed - there is no device on the port we claimed -
 * so this answers instead, and the trace said precisely what to answer: a
 * configuration descriptor, index 0, nine bytes. Nine is the header alone,
 * which a caller reads to learn wTotalLength before asking for the rest, so
 * both sizes have to work from the same bytes.
 *
 * The shape is a vendor-class interface with one bulk pipe each way, which is
 * what a JVS-over-USB node looks like: the board name is NA-JV, JVSEmuMK
 * carries its JVS identity string, and jvs.c already speaks that protocol -
 * so this is the transport for a conversation the runtime can already hold.
 *
 * Returns non-zero when it answered, and the caller then reports success.
 */
static int ioboard_descriptor(uint32_t hub, uint32_t inbuf, uint32_t outbuf,
                              uint32_t outlen, uint32_t bytesret)
{
    static const unsigned char DEVICE[18] = {
        18, 1, 0x00, 0x02,          /* USB 2.00 */
        0xFF, 0x00, 0x00, 64,       /* vendor class, 64-byte EP0 */
        0x9A, 0x0B,                 /* idVendor  0x0B9A Namco */
        0x10, 0x0C,                 /* idProduct 0x0C10 */
        0x00, 0x01,                 /* bcdDevice 1.00 */
        1, 2, 3,                    /* iManufacturer/iProduct/iSerial */
        1                           /* bNumConfigurations */
    };
    static const unsigned char CONFIG[32] = {
        9, 2, 32, 0, 1, 1, 0, 0x80, 50,        /* configuration, 32 total */
        9, 4, 0, 0, 2, 0xFF, 0, 0, 0,          /* interface, vendor class */
        7, 5, 0x81, 2, 64, 0, 0,               /* bulk IN  */
        7, 5, 0x02, 2, 64, 0, 0                /* bulk OUT */
    };
    const unsigned char *src;
    uint32_t port, wValue, wLength, type, have, room, n;

    if (!ioboard_on() || !inbuf || !outbuf) return 0;
    if (g_iob_port == 0xFFFFFFFFu || hub != g_iob_hub) return 0;
    port = rd32(inbuf);
    if (port != g_iob_port) return 0;

    wValue  = rd16(inbuf + 4u + 2u);
    wLength = rd16(inbuf + 4u + 6u);
    type    = wValue >> 8;

    /* String descriptors: index 0 is the language list, the rest are the
     * text the device descriptor points at. The board's own name is NA-JV -
     * the string the PCB startup screen prints - and the maker tag in both
     * the game and JVSEmuMK is NBGI. */
    static unsigned char str_buf[64];
    if (type == 1u)      { src = DEVICE; have = sizeof DEVICE; }
    else if (type == 2u) { src = CONFIG; have = sizeof CONFIG; }
    else if (type == 3u) {
        static const char *const TEXT[4] = { 0, "NBGI.", "NA-JV", "271000020001" };
        uint32_t idx = wValue & 0xFFu, k;
        if (idx == 0u) {
            str_buf[0] = 4; str_buf[1] = 3;
            str_buf[2] = 0x09; str_buf[3] = 0x04;   /* en-US */
            have = 4;
        } else if (idx < 4u && TEXT[idx]) {
            const char *t = TEXT[idx];
            uint32_t len = (uint32_t)strlen(t);
            if (len > 30u) len = 30u;
            str_buf[0] = (unsigned char)(2u + len * 2u);
            str_buf[1] = 3;
            for (k = 0; k < len; k++) {
                str_buf[2 + k * 2] = (unsigned char)t[k];
                str_buf[3 + k * 2] = 0;
            }
            have = 2u + len * 2u;
        } else {
            return 0;
        }
        src = str_buf;
    }
    else return 0;

    if (outlen < 12u) return 0;
    room = outlen - 12u;
    n = wLength < have ? wLength : have;
    if (n > room) n = room;
    memcpy((void *)(uintptr_t)(outbuf + 12u), src, n);
    if (bytesret) wr32(bytesret, 12u + n);

    {
        static int said[4];
        if (type < 4u && !said[type]) {
            said[type] = 1;
            fprintf(stderr, "[io] answered the board's %s descriptor, "
                            "%u of %u bytes\n",
                    type == 1u ? "device"
                  : type == 2u ? "configuration" : "string", n, have);
        }
    }
    return 1;
}

/*
 * A name for the board, and a Config Manager that will admit to it.
 *
 * Enumeration alone is not enough to make the game open a board. Having
 * matched one, it asks the hub for that port's driver key
 * (IOCTL_USB_GET_NODE_CONNECTION_DRIVERKEY_NAME, 0x220420) and then hands
 * the result to 0x007A81F0, which calls CM_Locate_DevNodeW and returns false
 * unless the Config Manager resolves it:
 *
 *     007A823A  call dword ptr [0x81d4f0]   ; CM_Locate_DevNodeW
 *     007A8240  test eax, eax
 *     007A8242  je 0x7a8254                 ; CR_SUCCESS: keep going
 *     007A8244  xor al, al                  ; anything else: not a board
 *
 * A port with nothing really in it has no driver key and no devnode, so the
 * walk finds the board and then disowns it. Both halves have to be answered
 * together: a name nobody can resolve is no better than no name.
 *
 * The name is deliberately one that cannot occur naturally, so the devnode
 * hook can accept exactly it and nothing else - a CM_Locate_DevNodeW that
 * said yes to everything would make every unplugged device look present.
 */
static const wchar_t k_iob_key[] = L"ES3-SYNTHETIC-NAMCO-IO-BOARD";

/* USB_NODE_CONNECTION_DRIVERKEY_NAME: ConnectionIndex, ActualLength, then
 * the name. */
static int ioboard_driverkey(uint32_t hub, uint32_t inbuf, uint32_t outbuf,
                             uint32_t outlen, uint32_t bytesret)
{
    uint32_t need = (uint32_t)(sizeof k_iob_key);
    if (!ioboard_on() || !inbuf || !outbuf) return 0;
    /* Port only, not the handle: handle numbers are recycled, and pinning
     * on one is what made the claim itself land on two hubs at once. Within
     * a scan we have claimed exactly one port, and the driver key is only
     * asked of a port the walk already decided was a board. */
    (void)hub;
    if (g_iob_port == 0xFFFFFFFFu) return 0;
    if (rd32(inbuf) != g_iob_port) return 0;
    if (outlen < 8u) return 0;

    /*
     * All three fields, and the returned count.
     *
     * The first version wrote ActualLength and the name and nothing else,
     * which is not what a caller sees from the real driver: ConnectionIndex
     * is echoed back, and DeviceIoControl's lpBytesReturned says how much of
     * the buffer was filled. Code that checks either - and USB enumeration
     * code usually checks both, because the size query depends on it - reads
     * a zero and concludes the call did nothing.
     */
    wr32(outbuf + 0u, g_iob_port);            /* ConnectionIndex, echoed */
    /*
     * ActualLength, and the eight bytes the caller loses on the way back.
     *
     * Measured: answering a size query with 8 + name brought the second call
     * back with a buffer eight bytes SMALLER than that, so the caller is
     * subtracting the header it then fails to re-add. Refusing the short
     * buffer made it ask the size again, forever - two calls of 10 bytes and
     * two of 58 per scan, and no name ever fetched. Reporting the figure
     * that makes its arithmetic land on 8 + name is the difference between
     * a loop and a board. ES3_IOB_ACTUAL overrides it if some other caller
     * ever does this properly.
     */
    {
        const char *w = getenv("ES3_IOB_ACTUAL");
        wr32(outbuf + 4u, w ? (uint32_t)strtoul(w, NULL, 0) : need + 16u);
    }

    if (outlen < 8u + need) {                 /* a size query: length only */
        if (bytesret) wr32(bytesret, 8u);
        if (io_trace())
            fprintf(stderr, "[io] driverkey for port %u: given %u bytes of "
                            "buffer, need %u\n", g_iob_port, outlen,
                    8u + need);
        return 1;
    }

    memcpy((void *)(uintptr_t)(outbuf + 8u), k_iob_key, need);
    if (bytesret) wr32(bytesret, 8u + need);
    {
        static int said;
        if (!said) {
            said = 1;
            fprintf(stderr, "[io] gave the board a driver key for port %u: "
                            "ES3-SYNTHETIC-NAMCO-IO-BOARD (%u bytes of %u)\n",
                    g_iob_port, 8u + need, outlen);
            fflush(stderr);
        }
    }
    return 1;
}

/* CM_Locate_DevNodeW(pdnDevInst, pDeviceID, ulFlags) - CR_SUCCESS is 0. */
static void hle_cm_locate_devnode(CPU *c, HleId id)
{
    uint32_t out = A32(0), name = A32(1);

    /* Every call, matched or not. "Never reached with our name" and "reached
     * with a name we do not recognise" are different problems and the hook
     * that only spoke on a match could not tell them apart. */
    if (io_trace()) {
        static int shown;
        if (shown < 8) {
            shown++;
            fprintf(stderr, "[io] CM_Locate_DevNodeW(%ls)\n",
                    name ? (const wchar_t *)(uintptr_t)name : L"(null)");
            fflush(stderr);
        }
    }

    if (ioboard_on() && name &&
        wcsstr((const wchar_t *)(uintptr_t)name, k_iob_key) != NULL) {
        static int said;
        if (!said) {
            said = 1;
            fprintf(stderr, "[io] the Config Manager is asked about the "
                            "synthetic board; saying it exists\n");
        }
        if (out) wr32(out, 0x0B9A0C10u);       /* a devnode of our own */
        c->eax = 0;                            /* CR_SUCCESS */
        c->esp += 4 + 4 * 3;
        return;
    }
    hle_call_native(c, id);
}

static void hle_device_io_control(CPU *c, HleId id)
{
    /* Every argument read BEFORE the call. DeviceIoControl is stdcall with
     * eight of them, so the callee pops 32 bytes and A32(n) afterwards reads
     * past the frame - which is exactly how the out buffer came back as
     * null the first time this was written. */
    uint32_t h = A32(0), code = A32(1), inlen = A32(3);
    uint32_t outbuf = A32(4), outlen = A32(5), inbuf = A32(2);
    /* The port being asked about, read now: on an empty port the driver
     * zeroes the whole output struct, ConnectionIndex included, so
     * afterwards every empty port looks like port 0 on every hub. The
     * caller's ConnectionIndex in the input buffer is the only place the
     * question survives. */
    uint32_t req_port = inbuf ? rd32(inbuf) : 0u;
    uint32_t bytesret = A32(6);
    hle_call_native(c, id);
    /* 0x220448 is GET_NODE_CONNECTION_INFORMATION_EX and 0x22040C the older
     * GET_NODE_CONNECTION_INFORMATION the walk falls back to; both answer
     * into the same struct, and both are how the game decides what is on a
     * port. */
    if (c->eax && (code == 0x00220448u || code == 0x0022040Cu))
        ioboard_claim(h, req_port, outbuf, outlen);
    /* The name calls: a port the game means to open has to have a path, and
     * these are where it asks for one. Say whether ours is being asked and
     * what it got, because a board it cannot name is a board it cannot
     * open - which is exactly where the enumeration currently stops. */
    if (ioboard_on() && (code == 0x00220414u || code == 0x00220420u) &&
        inbuf && g_iob_port != 0xFFFFFFFFu) {
        static int shown;
        uint32_t idx = rd32(inbuf);
        if (shown < 8) {
            shown++;
            fprintf(stderr, "[io] %s for port %u%s -> %s\n",
                    code == 0x00220414u ? "connection name" : "driverkey name",
                    idx, idx == g_iob_port ? " (OURS)" : "",
                    c->eax ? "ok" : "FAILED");
        }
    }
    if (code == 0x00220420u &&
        ioboard_driverkey(h, inbuf, outbuf, outlen, bytesret)) {
        SetLastError(0);
        c->eax = 1;
    }
    if (!c->eax && code == 0x00220410u &&
        ioboard_descriptor(h, inbuf, outbuf, outlen, bytesret)) {
        SetLastError(0);
        c->eax = 1;
    }
    if (io_trace())
        fprintf(stderr, "[io] DeviceIoControl(h %08X, code %08X, in %u, "
                        "out %u) -> %u\n", h, code, inlen, outlen, c->eax);
}

static void hle_dinput8_create(CPU *c, HleId id)
{
    if (g_di8_addr && !getenv("ES3_KEEP_DINPUT_DETOUR") &&
        memcmp(g_di8_addr, g_di8_orig, sizeof g_di8_orig) != 0) {
        DWORD old;
        if (VirtualProtect(g_di8_addr, sizeof g_di8_orig,
                           PAGE_EXECUTE_READWRITE, &old)) {
            memcpy(g_di8_addr, g_di8_orig, sizeof g_di8_orig);
            VirtualProtect(g_di8_addr, sizeof g_di8_orig, old, &old);
            FlushInstructionCache(GetCurrentProcess(), g_di8_addr,
                                  sizeof g_di8_orig);
            fprintf(stderr, "[io] something detoured DirectInput8Create; put "
                            "it back, so the game gets the real DirectInput "
                            "and finds its controller "
                            "(ES3_KEEP_DINPUT_DETOUR to leave it)\n");
        }
    }
    hle_call_native(c, id);
}

static void hle_load_library(CPU *c, HleId id)
{
    const char *name = es3_arg_string(A32(0));
    char kept[96];
    strncpy(kept, name ? name : "a library", sizeof kept - 1);
    kept[sizeof kept - 1] = 0;

    if (refuse_io_emulator(name)) {
        static unsigned char said;
        if (!said) {
            said = 1;
            fprintf(stderr,
                "[io] not loading %s. It patches the game's own code, which a\n"
                "     recompilation does not run - and it also replaces\n"
                "     DirectInput with one that reports no controllers, which\n"
                "     a recompilation very much does run. Refusing it gives\n"
                "     the game back its own gamepad support "
                "(ES3_LOAD_IO_EMULATOR=1 to load it).\n", kept);
        }
        SetLastError(ERROR_MOD_NOT_FOUND);
        c->eax = 0;
        c->esp += 4 + 4;              /* the return address and one argument */
        return;
    }

    hle_call_native(c, id);
    if (c->eax) es3_guest_diff(kept);
}

/*
 * Not the host's network settings.
 *
 * A cabinet owns its machine, so the game renews its DHCP lease on the way up
 * and logs "IP Renewed." That is fine on a cabinet and is not fine here: this
 * is somebody's workstation, the lease being renewed is theirs, and if they
 * happen to be connected over Remote Desktop the renewal can take the
 * connection with it. It is the same class of problem as the game maximising
 * itself over the display - correct behaviour for the hardware it was written
 * for, damage on the hardware it is standing on.
 *
 * NO_ERROR without doing anything. The machine already has an address; the
 * game only wants to know it succeeded. ES3_ALLOW_DHCP if you really mean it.
 */
static void hle_ip_renew(CPU *c, HleId id)
{
    static int allow = -1, said;
    if (allow < 0) allow = getenv("ES3_ALLOW_DHCP") != NULL;
    if (allow) { hle_call_native(c, id); return; }
    if (!said) {
        said = 1;
        fprintf(stderr, "[hle] the game wants to renew this machine's DHCP "
                        "lease; telling it that worked without touching the "
                        "network (ES3_ALLOW_DHCP to allow it).\n");
    }
    c->eax = 0;                       /* NO_ERROR */
    c->esp += 4 + 4 * 1;              /* __stdcall, one argument */
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
    hle_bind("IpRenewAddress", hle_ip_renew);
    if (!getenv("ES3_NO_ALLNET"))
        hle_bind("gethostbyname", es3_hle_gethostbyname);
    if (!getenv("ES3_NO_ALLNET"))
        hle_bind("getaddrinfo", es3_hle_getaddrinfo);
    if (!getenv("ES3_NO_ALLNET")) {
        /* Not trace-only: the connect hook is what puts the address the
         * resolvers invented back on loopback. */
        hle_bind("connect", es3_hle_connect);
        hle_bind("sendto", es3_hle_sendto);
        hle_bind("WSAIoctl", es3_hle_wsaioctl);
        hle_bind("WinHttpConnect", es3_hle_winhttp_connect);
        hle_bind("WinHttpOpenRequest", es3_hle_winhttp_open_request);
    }
    if (getenv("ES3_TRACE_NET")) {
        hle_bind("send", es3_hle_send);
        hle_bind("bind", es3_hle_bind);
        hle_bind("recvfrom", es3_hle_recvfrom);
    }
    es3_dinput8_snapshot();
    hle_bind("DirectInput8Create", hle_dinput8_create);
    hle_bind("fopen_s", hle_fopen_s);
    hle_bind("CM_Locate_DevNodeW", hle_cm_locate_devnode);
    hle_bind("SetupDiGetClassDevsW", hle_setupdi_classdevs);
    hle_bind("SetupDiEnumDeviceInterfaces", hle_setupdi_enum_iface);
    hle_bind("SetupDiGetDeviceInterfaceDetailW", hle_setupdi_iface_detail);
    hle_bind("DeviceIoControl", hle_device_io_control);
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
