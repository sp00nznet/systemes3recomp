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

int guest_load(const char *exe_path)
{
    FILE *f;
#ifdef _WIN32
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
    for (unsigned i = 0; i < nsections; i++, sec += 40) {
        uint32_t vaddr  = rd32le(sec + 12);
        uint32_t rsize  = rd32le(sec + 16);
        uint32_t roff   = rd32le(sec + 20);
        if (!rsize || roff + rsize > (uint32_t)len) continue;   /* .bss: already zero */
        memcpy((void *)(uintptr_t)(g_base + vaddr), img + roff, rsize);
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
uint32_t guest_image_size(void) { return g_image_size; }

void guest_init_cpu(CPU *c)
{
    memset(c, 0, sizeof *c);
    c->esp = g_stack_pointer;
    c->eip = g_entry;
    push32(c, GUEST_RETURN_SENTINEL);
}
