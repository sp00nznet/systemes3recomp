/*
 * guest.c - put an ES3 process where the recompiled code expects one.
 *
 * Lifted code holds real addresses in its registers, so the game's sections
 * have to live at the virtual addresses they were linked for. An ES3 title is
 * a PE32 with ImageBase 0x00400000 and no IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
 * - it was built for a machine with ASLR off, which is what the cabinet ran -
 * so this reserves that range outright and nothing needs relocating.
 *
 * Only the section table is honoured. The real loader would then walk the
 * import directory and bind every IAT slot to a function in a DLL it mapped;
 * here every slot gets a sentinel instead, and dispatch() answers it. See
 * es3_rt.h for why the boundary is drawn there.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#include "es3_rt.h"
#include "hybrid.h"
#include "recomp_iat.h"
#if __has_include("recomp_image.h")
#include "recomp_image.h"
#endif

/* src/runtime/hle_callback.c - the real -> lifted side of the boundary. */
uint64_t es3_hybrid_invoke(uint32_t ova, hybrid_regs *r, uint32_t *real_args);

#define PAGE       0x1000u
#define STACK_SZ   (8u << 20)

/* A return address the guest can never reach. The PE entry point is
 * mainCRTStartup, which exits through ExitProcess and does not return - if it
 * ever does, dispatch() stops on this rather than on whatever the stack
 * happened to contain. */
#define GUEST_RETURN_SENTINEL 0xDEADBE00u

static uint32_t g_entry;
static uint32_t g_base;
static uint32_t g_stack_pointer;
static uint32_t g_image_size;

uint32_t g_image_delta = 0;       /* cpu.h's GVA(): we map where it asked */

static uint32_t rd32le(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint32_t rd16le(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}

#ifdef _WIN32
/* Tell this thread's TEB about a stack region, or nothing that uses SEH works
 * on it.
 *
 * Windows validates an exception handler by checking that its frame lies
 * between NT_TIB.StackLimit and StackBase. Lifted code never runs on the
 * thread stack the TEB describes: the main thread runs on the guest stack this
 * file allocates, and a worker thread runs on hybrid's per-thread arena. A
 * handler registered from either is rejected, RtlDispatchException finds
 * nobody, and the exception is unhandled.
 *
 * That is not a corner case. It is `OutputDebugStringA`, which raises
 * DBG_PRINTEXCEPTION_C and catches it itself: the first debug line the game
 * printed ended the process with exit code 0x40010006, after 1,171 guest
 * calls, with no fault and nothing in the log. It is also every `__try` in the
 * game, in the CRT, and in Direct3D.
 *
 * ponytail: widened to span everything rather than swapped at each boundary
 * crossing. The host's own C frames are live on the real thread stack the
 * whole time the guest runs, so both have to validate, and the unmapped gap
 * between them costs nothing because this is a range check and not a walk.
 * Swap per crossing if something ever needs the bounds to be exact.
 *
 * Per thread, because a TEB is. Every thread that runs lifted code has to do
 * this once, which for a worker thread is its first crossing.
 */
void es3_teb_cover(uint32_t lo, uint32_t hi)
{
    /* ES3_NO_TEB_COVER isolates the other half of a window that will not
     * create: USER32 does look at these bounds, and a range spanning both
     * stacks with unmapped space between them is not what it expects.
     * Without the cover no `__try` in the guest can catch anything, so this
     * is a diagnostic and never a setting. */
    static int off = -1;
    if (off < 0) off = getenv("ES3_NO_TEB_COVER") != NULL;
    if (off) return;

    if (lo < __readfsdword(0x08)) __writefsdword(0x08, lo);   /* StackLimit */
    if (hi > __readfsdword(0x04)) __writefsdword(0x04, hi);   /* StackBase  */
}

/*
 * Can this process make a window at all?
 *
 * The game's two CreateWindowExW calls both return NULL with
 * ERROR_NOT_ENOUGH_MEMORY, and no window procedure is entered before they do -
 * so nothing about the guest's class or its callback is reached. That leaves
 * the process itself as the suspect, and one plain Win32 window settles it:
 * if this fails too, the cause is something this runtime did to the process
 * (the relaunch, the reserved image range, the TEB) and not the game.
 *
 * Called from guest_load, before a single guest instruction runs.
 */
#define ES3_WINDOW_W 1280
#define ES3_WINDOW_H 720

/*
 * A dead man's switch for the screen.
 *
 * The runtime forces every Direct3D device windowed and clamps every window it
 * creates, and both of those depend on recognising the right call. This does
 * not depend on anything: it looks at what is actually on the display, ten
 * times a second, and ends the process if this program has covered it.
 *
 * That matters because the failure it guards against is not a crash. A
 * recompiled arcade game that goes exclusive fullscreen takes the whole
 * machine away from the person running it, who is usually reading a log next
 * to it and has no way to get the desktop back. Being wrong about a vtable
 * slot should cost a run, not a session.
 *
 * ES3_FULLSCREEN turns the whole thing off, this included.
 */
static DWORD WINAPI screen_watchdog(void *unused)
{
    int cx = GetSystemMetrics(SM_CXSCREEN), cy = GetSystemMetrics(SM_CYSCREEN);
    unsigned caught = 0, ticks = 0;
    /* ES3_STALL=<seconds>: how often to say where every thread is. This thread
     * already exists and already wakes ten times a second, so the periodic
     * report rides on it rather than starting a second one. */
    const char *stall = getenv("ES3_STALL");
    unsigned period = stall ? (unsigned)atoi(stall) * 10u : 0;
    (void)unused;
    for (;;) {
        HWND h = NULL;
        Sleep(100);
        /* Ten times a second, not once per report: a poked value is one
         * the game keeps overwriting, and a boot that races it takes a
         * different path on every run. */
        es3_apply_pokes();
        if (period && ++ticks % period == 0) es3_report_threads();
        while ((h = FindWindowExA(NULL, h, NULL, NULL)) != NULL) {
            DWORD pid = 0;
            RECT r;
            GetWindowThreadProcessId(h, &pid);
            if (pid != GetCurrentProcessId() || !IsWindowVisible(h)) continue;
            if (!GetWindowRect(h, &r)) continue;
            if (r.right - r.left < cx || r.bottom - r.top < cy) continue;

            /* Put it back rather than end the run. The game maximises itself
             * at some point after creation - through the window, not through
             * Direct3D, so none of the call-level clamps see it - and a run
             * that dies here tells nobody anything about what it was drawing.
             * Shrinking it costs the game nothing it will notice. */
            if (++caught <= 4)
                fprintf(stderr, "\n[screen] the game made its window %ldx%ld, "
                                "the size of the display; putting it back to "
                                "%dx%d.\n", r.right - r.left, r.bottom - r.top,
                        ES3_WINDOW_W, ES3_WINDOW_H);
            ShowWindow(h, SW_RESTORE);
            SetWindowPos(h, HWND_NOTOPMOST, 64, 64, ES3_WINDOW_W, ES3_WINDOW_H,
                         SWP_NOACTIVATE);

            /* Unless it will not stay put. Then it is a fight this cannot win,
             * and leaving somebody without a desktop is worse than losing the
             * run. */
            if (caught > 40) {
                fprintf(stderr, "\n[screen] it keeps covering the display. "
                                "Ending it rather than leaving you without a "
                                "desktop -\n         set ES3_FULLSCREEN=1 if "
                                "you meant it.\n");
                fflush(stderr);
                TerminateProcess(GetCurrentProcess(), 3);
            }
        }
    }
}

/*
 * Is there a Direct3D display in this session at all?
 *
 * This is the first thing to know about a recompiled game that shows nothing,
 * and it has nothing to do with the recompilation. A title built on DXUT -
 * which this one is - enumerates adapters, skips any DXGI adapter reporting no
 * outputs, and if nothing is left puts up a modal
 *
 *     mkart3 - Could not find any compatible Direct3D devices.
 *
 * and waits for an OK that a cabinet was never going to give it. From outside
 * that is a hung process with a black window, which is indistinguishable from
 * a hundred other failures, and it cost most of a session to tell apart.
 *
 * Over a Remote Desktop session there is no display device to find: on this
 * machine Direct3DCreate9 reports zero adapters, Direct3DCreate9Ex returns
 * D3DERR_NOTAVAILABLE, and DXGI enumerates six adapters with zero outputs
 * between them. The game is right and there is nothing to fix in it.
 *
 * So ask the same questions the game is about to ask, before it asks them, and
 * say the answer in one line. Through LoadLibrary and the vtable indices
 * rather than d3d9.h and dxgi.h, so the runtime gains no build dependency for
 * a diagnostic.
 */
static int d3d9_adapters(void)
{
    HMODULE m = LoadLibraryA("d3d9.dll");
    void *(__stdcall * create)(unsigned);
    void *d3d;
    int n;
    if (!m) return -1;
    create = (void *(__stdcall *)(unsigned))GetProcAddress(m, "Direct3DCreate9");
    if (!create) return -1;
    d3d = create(32);                               /* D3D_SDK_VERSION */
    if (!d3d) return 0;
    /* IDirect3D9: 4 GetAdapterCount, 2 Release. */
    n = (int)(*(unsigned(__stdcall ***)(void *))d3d)[4](d3d);
    (*(unsigned long(__stdcall ***)(void *))d3d)[2](d3d);
    return n;
}

static int dxgi_outputs(int *adapters)
{
    HMODULE m = LoadLibraryA("dxgi.dll");
    long(__stdcall * create)(const GUID *, void **);
    GUID iid = { 0x7b7166ec, 0x21c7, 0x44ae,
                 { 0xb2, 0x1a, 0xc9, 0xae, 0x32, 0x1a, 0xe3, 0x69 } };
    void *f = NULL, *a = NULL;
    unsigned i = 0, outs = 0;

    *adapters = 0;
    if (!m) return -1;
    create = (long(__stdcall *)(const GUID *, void **))
             GetProcAddress(m, "CreateDXGIFactory");
    if (!create || create(&iid, &f) < 0) return -1;

    /* IDXGIFactory: 7 EnumAdapters.  IDXGIAdapter: 7 EnumOutputs. */
    while ((*(long(__stdcall ***)(void *, unsigned, void **))f)[7](f, i, &a) >= 0) {
        void *o = NULL;
        unsigned j = 0;
        while ((*(long(__stdcall ***)(void *, unsigned, void **))a)[7](a, j, &o) >= 0) {
            (*(unsigned long(__stdcall ***)(void *))o)[2](o);
            j++; outs++;
        }
        (*(unsigned long(__stdcall ***)(void *))a)[2](a);
        i++;
    }
    (*(unsigned long(__stdcall ***)(void *))f)[2](f);
    *adapters = (int)i;
    return (int)outs;
}

/*
 * The address of IDXGIAdapter::EnumOutputs, so it can be recognised later.
 *
 * The game reaches DXGI entirely through GetProcAddress and vtable slots, so
 * when it calls a method there is no name to match on - only an address. But
 * it is the same dxgi.dll in the same process, so the vtable of an adapter
 * WE create holds the same addresses the game will call. Read slot 7 once and
 * keep it; hle_call_address() compares against it.
 *
 * Same trick as es3_d3d_note_factory() uses for Direct3D 9's CreateDeviceEx,
 * and it is the only way to name a COM method in a recompiled process.
 */
/* And IDXGIFactory::CreateSwapChain, slot 10, for the same reason: it is how
 * the game's swap chain first becomes visible to this runtime, and the swap
 * chain is where both the fullscreen flag and the finished frame live. */
uint32_t es3_dxgi_create_swapchain_addr(void)
{
    static uint32_t addr;
    static int done;
    HMODULE m;
    long(__stdcall * create)(const GUID *, void **);
    GUID iid = { 0x7b7166ec, 0x21c7, 0x44ae,
                 { 0xb2, 0x1a, 0xc9, 0xae, 0x32, 0x1a, 0xe3, 0x69 } };
    void *f = NULL;

    if (done) return addr;
    done = 1;
    m = LoadLibraryA("dxgi.dll");
    if (!m) return 0;
    create = (long(__stdcall *)(const GUID *, void **))
             GetProcAddress(m, "CreateDXGIFactory");
    if (!create || create(&iid, &f) < 0) return 0;
    addr = (uint32_t)(uintptr_t)(*(void ***)f)[10];
    (*(unsigned long(__stdcall ***)(void *))f)[2](f);
    return addr;
}

uint32_t es3_dxgi_enum_outputs_addr(void)
{
    static uint32_t addr;
    static int done;
    HMODULE m;
    long(__stdcall * create)(const GUID *, void **);
    GUID iid = { 0x7b7166ec, 0x21c7, 0x44ae,
                 { 0xb2, 0x1a, 0xc9, 0xae, 0x32, 0x1a, 0xe3, 0x69 } };
    void *f = NULL, *a = NULL;

    if (done) return addr;
    done = 1;
    m = LoadLibraryA("dxgi.dll");
    if (!m) return 0;
    create = (long(__stdcall *)(const GUID *, void **))
             GetProcAddress(m, "CreateDXGIFactory");
    if (!create || create(&iid, &f) < 0) return 0;
    if ((*(long(__stdcall ***)(void *, unsigned, void **))f)[7](f, 0, &a) >= 0) {
        addr = (uint32_t)(uintptr_t)(*(void ***)a)[7];   /* EnumOutputs */
        (*(unsigned long(__stdcall ***)(void *))a)[2](a);
    }
    (*(unsigned long(__stdcall ***)(void *))f)[2](f);
    return addr;
}

void es3_report_display(void)
{
    int d9 = d3d9_adapters(), adapters = 0, outs = dxgi_outputs(&adapters);
    int remote = GetSystemMetrics(SM_REMOTESESSION);

    if (d9 > 0 || outs > 0) {
        fprintf(stderr, "[display] Direct3D 9 sees %d adapter(s); DXGI sees %d "
                        "adapter(s) with %d output(s).\n", d9, adapters, outs);
        return;
    }
    fprintf(stderr,
        "\n[display] THERE IS NO DIRECT3D DISPLAY IN THIS SESSION.\n"
        "          Direct3D 9 reports %d adapter(s); DXGI reports %d adapter(s)\n"
        "          with %d output(s) between them.%s\n"
        "          The game is built on DXUT, which skips an adapter that has\n"
        "          no output, finds nothing left, and puts up a modal\n"
        "          \"Could not find any compatible Direct3D devices\" that\n"
        "          nothing is going to click. It will not draw anything here,\n"
        "          and that is the session rather than the port: run it on the\n"
        "          console, on a session with a display attached.\n\n",
        d9, adapters, outs,
        remote ? "  This is a remote session." : "");
    fflush(stderr);
}

/* ES3_PEEK gets a thread of its own.
 *
 * It shared the watchdog's, and a thread report on this game suspends and
 * walks ninety-five threads - slow enough that peeks arrived twice in ten
 * minutes with a twenty-second period set. A peek is wanted while the game is
 * RUNNING, so it must not queue behind anything that is slow when it is. */
static DWORD WINAPI peek_watchdog(void *unused)
{
    const char *stall = getenv("ES3_STALL");
    unsigned seconds = stall ? (unsigned)atoi(stall) : 5u;
    (void)unused;
    if (!seconds) seconds = 5u;
    for (;;) {
        Sleep(seconds * 1000u);
        es3_report_peeks();
        es3_watch_mem_tick();
        fflush(stderr);
    }
}

void es3_start_screen_watchdog(void)
{
    HANDLE t;
    if (getenv("ES3_PEEK") || getenv("ES3_WATCH_MEM")) {
        t = CreateThread(NULL, 0, peek_watchdog, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    if (getenv("ES3_FULLSCREEN")) return;
    t = CreateThread(NULL, 0, screen_watchdog, NULL, 0, NULL);
    if (t) CloseHandle(t);
}

/*
 * The guest runs on a thread of our own, with a stack sized for it.
 *
 * Lifted code is far heavier on the real stack than the code it stands for -
 * one C function per guest function, a dispatch() frame between each pair, a
 * local for every emulated temporary - so the thread that carries the game's
 * call graph needs hundreds of megabytes where the original needed one.
 *
 * The obvious way to get that is /STACK, and /STACK is the wrong knob: it is
 * the reservation for EVERY thread in the process, including the ones real
 * libraries make for themselves. Direct3D, DirectInput, Media Foundation and
 * COM between them start four, and at a quarter of a gigabyte each that is a
 * gigabyte of a two-gigabyte address space gone before the game has loaded a
 * texture - which arrives, eventually, as operator new throwing bad_alloc.
 *
 * So /STACK stays modest, which is all a library thread needs even when it
 * calls back into lifted code, and the deep one is asked for here by name.
 * STACK_SIZE_PARAM_IS_A_RESERVATION is the whole point of the call:
 * without it dwStackSize only says how much to COMMIT and the reservation
 * comes from /STACK again.
 */
#define ES3_GUEST_STACK (256u << 20)

static uint32_t g_guest_stack_lo;
extern unsigned long g_guest_tid;   /* crash.c, for the thread report */

static CPU *g_entry_cpu;

static DWORD WINAPI guest_thread(void *unused)
{
    (void)unused;
    /* This thread's own TEB, not the one guest_init_cpu covered. Without it
     * the guest's first __try is rejected by RtlDispatchException and the run
     * ends on the first OutputDebugString - which is what it did. */
    g_guest_tid = GetCurrentThreadId();
    es3_teb_cover(g_guest_stack_lo, g_guest_stack_lo + STACK_SZ);
    dispatch(g_entry_cpu, guest_entry());
    return 0;
}

void es3_enter_guest(CPU *c)
{
    HANDLE t;
    g_entry_cpu = c;
    t = CreateThread(NULL, ES3_GUEST_STACK, guest_thread, NULL,
                     0x00010000u /* STACK_SIZE_PARAM_IS_A_RESERVATION */, NULL);
    if (!t) {
        fprintf(stderr, "[host] no room for a %u MB guest stack (error %lu); "
                        "running on this thread instead\n",
                ES3_GUEST_STACK >> 20, GetLastError());
        guest_thread(NULL);
        return;
    }
    /* The guest's exit path is ExitProcess, so this wait does not normally
     * end. It is here for the case where the entry point returns, which
     * mainCRTStartup does not do and host.c reports if it ever does. */
    WaitForSingleObject(t, INFINITE);
    CloseHandle(t);
}

void es3_window_selftest(void)
{
    WNDCLASSW wc;
    HWND h;
    ATOM a;

    memset(&wc, 0, sizeof wc);
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.lpszClassName = L"es3_window_selftest";
    SetLastError(0);
    a = RegisterClassW(&wc);
    fprintf(stderr, "[wintest] RegisterClassW = %04X (error %lu)\n",
            a, GetLastError());

    SetLastError(0);
    h = CreateWindowExW(0, L"es3_window_selftest", L"es3", WS_OVERLAPPEDWINDOW,
                        CW_USEDEFAULT, CW_USEDEFAULT, 320, 240,
                        NULL, NULL, GetModuleHandleW(NULL), NULL);
    fprintf(stderr, "[wintest] CreateWindowExW = %p (error %lu)\n",
            (void *)h, GetLastError());
    if (h) DestroyWindow(h);
    UnregisterClassW(L"es3_window_selftest", GetModuleHandleW(NULL));
}

#endif

static void *reserve(uint32_t addr, uint32_t size)
{
#ifdef _WIN32
    void *p = VirtualAlloc((LPVOID)(uintptr_t)addr, size,
                           MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (p) return p;
    /* Already reserved - by our own parent, before this process's loader ran.
     * See guest_reserve_image(). Commit inside the existing reservation. */
    return VirtualAlloc((LPVOID)(uintptr_t)addr, size,
                        MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#else
    void *p = mmap((void *)(uintptr_t)addr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    return p == MAP_FAILED ? NULL : p;
#endif
}

#ifdef _WIN32
/*
 * Reserving 0x00400000 is not something a process can do for itself.
 *
 * Moving the host image off 0x00400000 (see the CMake's /BASE) is necessary
 * and not sufficient: it frees the address, and then the loader immediately
 * fills it. By the time any user code runs - before the entry point, before a
 * TLS callback, before a static initialiser - ntdll has created the process
 * heap and mapped the NLS sections bottom-up, and they land at 0x060000,
 * 0x200000, 0x400000, 0x450000, 0x4D0000, 0x540000, 0x670000 ... straight
 * through the range an ES3 image needs. Measured, not assumed.
 *
 * The one moment the range is free is inside a process whose image is mapped
 * and whose loader has not started - which is exactly what CREATE_SUSPENDED
 * gives you, from outside. So if the reservation fails, this relaunches
 * itself suspended, reserves the range in the child through VirtualAllocEx,
 * resumes it, and exits with the child's status.
 *
 * The alternative was to map the image somewhere else and relocate it. cpu.h
 * has GVA() for exactly that, and it handles addresses embedded in
 * *instructions* - but not the ones embedded in *data*: a vtable slot read
 * with rd32 and handed to dispatch() would arrive relocated, and dispatch's
 * table is keyed by original VA. That is a much larger change than a second
 * process.
 */
#define ES3_CHILD_ENV "ES3_IMAGE_RESERVED"

static int relaunch_reserving(uint32_t base, uint32_t size)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    wchar_t *cmd;
    DWORD code = 1;

    if (GetEnvironmentVariableW(L"" ES3_CHILD_ENV, NULL, 0) != 0) {
        fprintf(stderr,
            "cannot reserve %#x..%#x even in a fresh process.\n"
            "  Something else in this process has the range, or the host is a\n"
            "  64-bit build. Configure with: cmake -B build -A Win32\n",
            base, base + size);
        return -1;
    }

    cmd = GetCommandLineW();
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    SetEnvironmentVariableW(L"" ES3_CHILD_ENV, L"1");
    if (!CreateProcessW(NULL, cmd, NULL, NULL, TRUE, CREATE_SUSPENDED,
                        NULL, NULL, &si, &pi)) {
        fprintf(stderr, "cannot relaunch to reserve the image range (%lu)\n",
                GetLastError());
        return -1;
    }
    /* The child's image is mapped; its loader has not run, so nothing of its
     * own is in the way yet. Reserve only - the child commits and fills it. */
    if (!VirtualAllocEx(pi.hProcess, (LPVOID)(uintptr_t)base, size,
                        MEM_RESERVE, PAGE_READWRITE)) {
        fprintf(stderr, "cannot reserve %#x..%#x in the child (%lu)\n",
                base, base + size, GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        return -1;
    }
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    exit((int)code);
}
#endif

/*
 * Is this the executable the lifted code was made from?
 *
 * The generated C and the mapped image are two halves of one program. The C
 * was compiled from one file's instructions; at run time it reads its
 * constants, its vtables and its strings out of whatever file guest_load() is
 * pointed at. If those are different files the result is not a crash, it is a
 * program that behaves like neither.
 *
 * This game's tree ships two executables of exactly the same size, 33 bytes
 * apart, and one of those differences is at the entry point: the patched build
 * jumps to a stub that does LoadLibraryW(L"JVSEmuMK") - the cabinet's I/O
 * emulator - and the clean build does not. Lift the patched one, run the clean
 * one, and the lifted stub runs while the string it points at is a run of
 * zeros in the image actually mapped. The game asks the loader for a DLL with
 * no name, gets nothing, and falls back to a serial port with no board on it.
 *
 * Nothing about that looks wrong from outside. It boots, it loads, it runs a
 * frame loop. So: fingerprint the file the build came from, check the one
 * being loaded, and say so.
 *
 * A warning and not a refusal, because "which of these four builds is this"
 * is a real question people will want to ask by just trying it - but it is
 * loud, and it names both files.
 */
static uint64_t file_fingerprint(const unsigned char *p, size_t n)
{
    uint64_t h = 0xCBF29CE484222325ULL;
    size_t i;
    for (i = 0; i < n; i++) h = (h ^ p[i]) * 0x100000001B3ULL;
    return h;
}

static void check_image(const char *path, const unsigned char *img, size_t len)
{
#ifdef ES3_IMAGE_HASH
    uint64_t got = file_fingerprint(img, len);
    const char *leaf = strrchr(path, '\\');
    const char *leaf2 = strrchr(path, '/');
    if (leaf2 > leaf) leaf = leaf2;
    leaf = leaf ? leaf + 1 : path;

    if (got == (uint64_t)ES3_IMAGE_HASH && len == (size_t)ES3_IMAGE_SIZE) return;

    fprintf(stderr,
        "\n[image] THIS IS NOT THE EXECUTABLE THIS BUILD WAS LIFTED FROM.\n"
        "        lifted from  %s  (%u bytes, %016llX)\n"
        "        loading      %s  (%u bytes, %016llX)\n"
        "        The generated C is this program's instructions and the file "
        "above is where it\n"
        "        reads every constant, vtable and string. Two builds that "
        "differ by a handful of\n"
        "        bytes still disagree about what those are, and the result "
        "runs without ever\n"
        "        looking wrong. Re-lift from the file you mean to run, or run "
        "the one it was\n"
        "        lifted from.\n\n",
        ES3_IMAGE_NAME, (unsigned)ES3_IMAGE_SIZE,
        (unsigned long long)ES3_IMAGE_HASH,
        leaf, (unsigned)len, (unsigned long long)got);
    fflush(stderr);
#else
    (void)path; (void)img; (void)len;
#endif
}

int guest_load(const char *exe_path)
{
    FILE *f;
#ifdef _WIN32
    es3_start_screen_watchdog();
    es3_report_display();
    if (getenv("ES3_WINTEST")) es3_window_selftest();
#endif
    f = fopen(exe_path, "rb");
    if (!f) { perror(exe_path); return -1; }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *img = (unsigned char *)malloc((size_t)(len > 0 ? len : 1));
    if (!img || len <= 0 || fread(img, 1, (size_t)len, f) != (size_t)len) {
        fprintf(stderr, "%s: short read\n", exe_path);
        free(img); fclose(f); return -1;
    }
    fclose(f);

    if (len < 0x40 || img[0] != 'M' || img[1] != 'Z') {
        fprintf(stderr, "%s: not a PE\n", exe_path); free(img); return -1;
    }
    uint32_t pe = rd32le(img + 0x3C);
    if (pe + 0x78 > (uint32_t)len || memcmp(img + pe, "PE\0\0", 4) != 0) {
        fprintf(stderr, "%s: no PE signature\n", exe_path); free(img); return -1;
    }
    if (rd16le(img + pe + 4) != 0x014C) {
        fprintf(stderr, "%s: not i386 - ES3 titles are 32-bit x86\n", exe_path);
        free(img); return -1;
    }

    unsigned nsections  = rd16le(img + pe + 6);
    unsigned opt_size   = rd16le(img + pe + 20);
    const unsigned char *opt = img + pe + 24;
    g_base      = rd32le(opt + 28);
    g_entry     = g_base + rd32le(opt + 16);
    uint32_t image_size = rd32le(opt + 56);
    g_image_size = image_size;
    uint32_t hdr_size   = rd32le(opt + 60);

    /* One reservation for the whole image, then the sections copied into it.
     * Section by section would leave the gaps between them unmapped, and the
     * game reads across those: .rdata tables run right up to the end of their
     * page and MSVC's CRT walks structures that straddle a boundary. */
    if (!reserve(g_base, image_size)) {
#ifdef _WIN32
        /* Does not return on success: it relaunches and exits with the
         * child's status. See relaunch_reserving(). */
        free(img);
        return relaunch_reserving(g_base, image_size);
#else
        fprintf(stderr,
            "cannot map %#x..%#x.\n"
            "  This is the usual symptom of a 64-bit host: the image wants low\n"
            "  memory that only exists as an address in a 32-bit process.\n",
            g_base, g_base + image_size);
        free(img); return -1;
#endif
    }
    memset((void *)(uintptr_t)g_base, 0, image_size);
    memcpy((void *)(uintptr_t)g_base, img, hdr_size < (uint32_t)len ? hdr_size : (uint32_t)len);

    const unsigned char *sec = img + pe + 24 + opt_size;
    check_image(exe_path, img, (size_t)len);

    for (unsigned i = 0; i < nsections; i++, sec += 40) {
        uint32_t vaddr  = rd32le(sec + 12);
        uint32_t rsize  = rd32le(sec + 16);
        uint32_t roff   = rd32le(sec + 20);
        if (!rsize || roff + rsize > (uint32_t)len) continue;   /* .bss: already zero */
        memcpy((void *)(uintptr_t)(g_base + vaddr), img + roff, rsize);
        /* Remember the executable one, so a DLL that rewrites the game's code
         * later can be caught doing it - see es3_guest_diff(). Code only: the
         * game writes to its own data constantly and legitimately. */
        if (rd32le(sec + 36) & 0x20000000u)      /* IMAGE_SCN_MEM_EXECUTE */
            es3_guest_snapshot(g_base + vaddr, g_base + vaddr + rsize);
    }
    free(img);

#ifdef _WIN32
    /*
     * And now take execute away from all of it.
     *
     * The game's original machine code is mapped, because data and code share
     * pages and the lifted code reads its own constants out of them. What must
     * never happen is the host EXECUTING it: those bytes reach an IAT full of
     * sentinels, and the fault that follows names an import nobody called with
     * no way back to who did.
     *
     * It happens whenever a real library is handed a pointer to guest code
     * that this runtime did not thunk. The window procedure and the thread
     * entry are arguments, so hle_callback.c can wrap them; a COM interface
     * the game implements is not - Mario Kart hands D3DX10's thread pump an
     * ID3DX10DataLoader whose vtable is seven guest addresses, and D3DX10
     * calls them on its own worker threads. There is no argument to wrap.
     *
     * With the pages non-executable, that call faults with an execute
     * violation at a guest address instead - which crash.c turns back into a
     * dispatch. One handler covers every unthunked callback there will ever
     * be, including the ones nobody has found yet.
     */
    {
        DWORD old;
        if (!getenv("ES3_GUEST_EXECUTABLE") &&
            !VirtualProtect((LPVOID)(uintptr_t)g_base, image_size,
                            PAGE_READWRITE, &old))
            fprintf(stderr, "[guest] could not take execute off the image (%lu) - "
                            "an unthunked callback will fault on a sentinel "
                            "instead of being dispatched\n", GetLastError());
    }
#endif

    /* Point every IAT slot at its sentinel. This is what turns the game's
     * `call dword ptr [__imp_CreateFileW]` into a call the runtime answers. */
    {
        unsigned n = 0;
#define PATCH(slot_va, id) do { wr32((uint32_t)(slot_va), HLE_ADDR(id)); n++; } while (0);
        IAT_SLOTS(PATCH)
#undef PATCH
        if (!n) fprintf(stderr, "[guest] warning: no IAT slots patched - "
                                "every import call will land in the image\n");
    }

    /* A dedicated guest stack. It is not the host thread's, so the TEB's
     * StackBase/StackLimit do not describe it - which matters only to
     * stack-overflow recovery, and a working game never gets there.
     * ponytail: committed 8 MB up front, which is what the cabinet gave the
     * game; grow it on a guard-page fault if a title ever needs more. */
    uint32_t stack_lo;
#ifdef _WIN32
    {
        void *p = VirtualAlloc(NULL, STACK_SZ, MEM_RESERVE | MEM_COMMIT,
                               PAGE_READWRITE);
        if (!p) { fprintf(stderr, "cannot allocate the guest stack\n"); return -1; }
        stack_lo = (uint32_t)(uintptr_t)p;
    }
#else
    {
        void *p = mmap(NULL, STACK_SZ, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) { fprintf(stderr, "cannot allocate the guest stack\n"); return -1; }
        stack_lo = (uint32_t)(uintptr_t)p;
    }
#endif
    memset((void *)(uintptr_t)stack_lo, 0, STACK_SZ);

    /* Leave a page of slack at the top: the CRT reads a little above its own
     * frame while setting up, and a stack pointer at the very last mapped byte
     * turns that into an access violation before main. */
    g_stack_pointer = stack_lo + STACK_SZ - PAGE;
    g_stack_pointer &= ~0xFu;

#ifdef _WIN32
    /* And remember it, because the thread that ends up RUNNING the guest is
     * not this one - see es3_enter_guest() - and a TEB is per thread. */
    g_guest_stack_lo = stack_lo;
    es3_teb_cover(stack_lo, stack_lo + STACK_SZ);
#endif
#if 0
    /* Tell the TEB about the guest stack, or nothing that uses SEH works.
     *
     * Windows validates an exception handler by checking that its frame lies
     * between NT_TIB.StackLimit and StackBase. Lifted code runs on a stack this
     * runtime allocated, which is nowhere near the thread stack the TEB
     * describes - so a handler registered while the guest is running is
     * rejected, RtlDispatchException finds nobody, and the exception is
     * unhandled.
     *
     * That is not a corner case. It is `OutputDebugStringA`, which raises
     * DBG_PRINTEXCEPTION_C and catches it itself: the first debug line the game
     * printed killed the process with exit code 0x40010006, after 1,171 guest
     * calls, with no fault and nothing in the log. It is also every `__try` in
     * the game, in the CRT, and in Direct3D.
     *
     * ponytail: widened to span both stacks rather than swapped at each
     * boundary crossing. The host's own C frames are live on the real thread
     * stack the whole time the guest runs, so both have to validate, and the
     * range between them is unmapped - which costs nothing, because this test
     * is a range check and not a walk. Swap per crossing if something ever
     * needs the bounds to be exact.
     */
#endif

    /* The other direction across the boundary: a real library function calling
     * back into guest code. hybrid mints a real address per guest function and
     * runs each nested call on a private arena rather than the host stack -
     * the host's own C frames keep descending while lifted code runs, and the
     * two would interleave. See src/runtime/hle_callback.c for who needs it. */
    /* A megabyte per crossing, out of sixteen. The defaults are 32 KB and
     * 8 MB, and 32 KB is not a stack: a worker thread that enters lifted code
     * through a callback runs the game's own call graph on that frame, and
     * real library code called back out of it runs there too. Mario Kart's
     * eight engine threads ran off the end of theirs and the process died on a
     * guard page nobody could grow.
     *
     * Four megabytes a frame, sixteen of arena - four nested crossings.
     *
     * A frame is a whole emulated thread stack, not a call frame: the callback
     * runs the game's own call graph on it, and one megabyte was not enough.
     * It ran off the bottom into the arena's uncommitted pages, and because
     * the REAL esp is in there too while a forwarded import runs, the kernel
     * then could not dispatch the fault - the process ended with 0xC0000005
     * and no handler of any kind, which took a self-debugger to see at all.
     *
     * Both numbers are reservations, committed a frame at a time, and hybrid
     * hands an arena back when its thread exits - so the cost is address
     * space, which /LARGEADDRESSAWARE made affordable. */
    if (!hybrid_init(es3_hybrid_invoke, 2u << 20, 32u << 20)) {
        fprintf(stderr, "cannot set up the real -> lifted boundary\n");
        return -1;
    }
    return 0;
}

void guest_patch_import(HleId id, uint32_t value)
{
    /* One import can occupy several slots, and every one of them has to change
     * - the linker emits a second when the same name is referenced from a
     * different object, and a data import missed in one slot faults the first
     * time that reference is used, which may be much later than the other. */
#define PATCH(slot_va, sid) if ((HleId)(sid) == id) wr32((uint32_t)(slot_va), value);
    IAT_SLOTS(PATCH)
#undef PATCH
}

uint32_t guest_entry(void)      { return g_entry; }
uint32_t guest_image_base(void) { return g_base; }
/*
 * What a loaded DLL did to the game's code.
 *
 * These game trees ship an I/O emulator - JVSEmuMK.dll here - and the patched
 * builds load it from a stub spliced onto the entry point. It imports nothing
 * but GetProcAddress and VirtualProtect, which is the shape of something that
 * rewrites code in memory, and what it rewrites is the GAME's own routines:
 * the serial I/O layer is replaced in place by one that reads a gamepad.
 *
 * A static recompilation cannot be patched that way and never notices. The
 * lifted C was compiled from the original bytes and is what actually runs; the
 * guest image is data. So the DLL loads, patches nothing that matters, and the
 * game goes on talking to a serial port that is not there.
 *
 * That is a dead end for running the emulator as-is, and a very good source of
 * information: the addresses it patches are exactly the routines the cabinet's
 * own authors considered the I/O interface. Snapshot the code at load, diff it
 * after, and the report names them.
 *
 * Code only. The guest writes to its own .data constantly and legitimately.
 */
static unsigned char *g_code_copy;
static uint32_t g_code_lo, g_code_hi;

void es3_guest_snapshot(uint32_t lo, uint32_t hi)
{
    if (g_code_copy || hi <= lo) return;
    g_code_copy = (unsigned char *)malloc(hi - lo);
    if (!g_code_copy) return;
    g_code_lo = lo;
    g_code_hi = hi;
    memcpy(g_code_copy, (const void *)(uintptr_t)lo, hi - lo);
}

void es3_guest_diff(const char *when)
{
    const unsigned char *now = (const unsigned char *)(uintptr_t)g_code_lo;
    uint32_t i, n = g_code_hi - g_code_lo;
    unsigned runs = 0;

    if (!g_code_copy) return;
    for (i = 0; i < n; i++) {
        if (now[i] == g_code_copy[i]) continue;
        {
            uint32_t s = i, k;
            while (i < n && now[i] != g_code_copy[i]) i++;
            if (!runs++)
                fprintf(stderr, "\n[patch] %s rewrote the game's code:\n", when);
            fprintf(stderr, "  %08X  %u byte(s)\n    was:", g_code_lo + s, i - s);
            for (k = s; k < i && k < s + 16; k++)
                fprintf(stderr, " %02X", g_code_copy[k]);
            fprintf(stderr, "\n    now:");
            for (k = s; k < i && k < s + 16; k++) fprintf(stderr, " %02X", now[k]);
            fprintf(stderr, "\n");
            /* Refresh, so a second diff reports only what is new. */
            memcpy(g_code_copy + s, now + s, i - s);
            if (runs > 40) {
                fprintf(stderr, "  ...stopping after 40\n");
                break;
            }
        }
    }
    if (runs)
        fprintf(stderr, "  %u patched range(s). Lifted code runs from the "
                        "ORIGINAL bytes, so none of this has any effect - but "
                        "the addresses\n  are what the cabinet's own authors "
                        "treated as the I/O interface, which is worth knowing.\n\n",
                runs);
    else if (when)
        fprintf(stderr, "[patch] %s changed no guest code.\n", when);
    fflush(stderr);
}

uint32_t guest_image_size(void) { return g_image_size; }

void guest_init_cpu(CPU *c)
{
    memset(c, 0, sizeof *c);
    c->esp = g_stack_pointer;
    c->eip = g_entry;
    push32(c, GUEST_RETURN_SENTINEL);
}
