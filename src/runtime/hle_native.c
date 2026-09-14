/*
 * hle_native.c - hand the game the libraries, do not reimplement them.
 *
 * An ES3 cabinet is a Windows PC. Of the ~495 functions a title imports, all
 * but a couple of dozen come from Windows itself or from a Microsoft
 * redistributable - kernel32, user32, gdi32, ole32, ws2_32, winhttp, winmm,
 * Media Foundation, DirectInput 8, Direct3D 9 and 10, D3DX, and the Visual C++
 * 2010 runtime. Every one of those is on the host machine already, and the
 * host process is itself a 32-bit Windows process running on the same ABI.
 *
 * So the right body for `CreateFileW` is CreateFileW. Not a reimplementation
 * of it, not a translation layer over it: the real function, called with the
 * arguments the game pushed, on the stack the game pushed them on.
 *
 * That is what pcrecomp's runtime/hybrid does, and it is why this file is
 * eighty lines rather than eight thousand. `hybrid_call_machine` loads the
 * emulated register block, points the real esp at the guest frame, calls the
 * real code and reads eax/edx/esp back - including whatever the callee's own
 * `ret N` popped, which is a better answer about the stack purge than any
 * table. LoadLibrary/GetProcAddress finds the target; the derived purge table
 * is not needed on this path at all.
 *
 * What is deliberately NOT here:
 *
 *   * The cabinet-only DLLs. JVS I/O, the card reader, the camera, the network
 *     authentication - none of them exist on a desktop, GetProcAddress finds
 *     nothing, and there is nothing honest to forward to. They are hle_board.c
 *     and they are the actual work of an ES3 port.
 *
 *   * ponytail: callbacks. A real library function that calls back into game
 *     code - a window procedure, a qsort comparator, a D3D callback - arrives
 *     at a guest VA that the host will execute as machine code, and the
 *     original bytes are still mapped, so it silently runs the *unlifted*
 *     original. pcrecomp's hybrid_thunk() is the fix and is already in the
 *     submodule; wire it in when the first title needs one. The first is
 *     always the window procedure.
 */

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include "es3_rt.h"
#include "hybrid.h"

#ifdef _WIN32

/* The resolved real function for each import, filled by hle_bind_native. */
static FARPROC g_native[HLE_COUNT];

/* How many x87 arguments this import takes, filled once at bind time.
 *
 * Almost nothing in the Win32/CRT/D3DX world passes arguments in x87
 * registers - except MSVC's own `_CI*` helpers, which pass *only* that way.
 * The compiler emits them for `pow(x, y)` and friends whenever it cannot
 * inline the x87 sequence, and Mario Kart Arcade GP DX imports nine.
 *
 * This is a table, and a table is the thing to avoid - but the arity of a
 * helper that takes nothing on the stack cannot be derived from the stack, and
 * `ret` says nothing about st(0). It is a closed set, it is named by
 * convention, and a wrong entry here is silently wrong arithmetic - so it is
 * written out rather than guessed. The *return* side needs no table at all:
 * hybrid_fpu_depth() before and after says whether the callee left one. */
static unsigned char g_fpu_args[HLE_COUNT];

static const struct { const char *name; unsigned char argc; } CI_HELPERS[] = {
    { "_CIacos",  1 }, { "_CIasin",  1 }, { "_CIatan",  1 }, { "_CIatan2", 2 },
    { "_CIcos",   1 }, { "_CIcosh",  1 }, { "_CIexp",   1 }, { "_CIfmod",  2 },
    { "_CIlog",   1 }, { "_CIlog10", 1 }, { "_CIpow",   2 }, { "_CIsin",   1 },
    { "_CIsinh",  1 }, { "_CIsqrt",  1 }, { "_CItan",   1 }, { "_CItanh",  1 },
};

/* One handler for every forwarded import - which id it is arrives as an
 * argument, so there is no need to generate hundreds of identical stubs. */
/* ---- calling a real function the game got at run time ----
 *
 * The IAT is not the only way a real address reaches lifted code. A COM
 * interface is a pointer to a vtable of real function addresses, and
 * `Direct3DCreate9`, `CoCreateInstance` and every `QueryInterface` hand one
 * back; so does `GetProcAddress`. The game then calls through it, the lifter
 * emits `dispatch(c, <that address>)`, and dispatch has never heard of it.
 *
 * It is the exact mirror of the callback problem, and it has the same answer:
 * cross the boundary. The address is real code, so run it as real code, on the
 * guest's own frame, through the same marshalling an import uses.
 *
 * The test is whether the page is executable and outside the guest image.
 * VirtualQuery is far too slow to do per call - a game makes thousands of COM
 * calls a frame - so the answer is cached by REGION: a DLL's code is one
 * region, and a handful of them covers every library a title loads.
 */
#define HOST_REGIONS 64
static struct { uint32_t lo, hi; } g_host_code[HOST_REGIONS];
static unsigned g_host_n;

int es3_is_host_code(uint32_t va)
{
    MEMORY_BASIC_INFORMATION mbi;
    uint32_t base = guest_image_base();
    unsigned i;

    if (va >= base && va < base + guest_image_size()) return 0;
    if (va < 0x10000u) return 0;

    for (i = 0; i < g_host_n; i++)
        if (va >= g_host_code[i].lo && va < g_host_code[i].hi) return 1;

    if (!VirtualQuery((LPCVOID)(uintptr_t)va, &mbi, sizeof mbi)) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    if (!(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                         PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return 0;

    /* Cache it. Full is not an error - it degrades to a VirtualQuery per call,
     * which is slow and still correct, and 64 regions is more than a game
     * loads. */
    if (g_host_n < HOST_REGIONS) {
        g_host_code[g_host_n].lo = (uint32_t)(uintptr_t)mbi.BaseAddress;
        g_host_code[g_host_n].hi = g_host_code[g_host_n].lo + (uint32_t)mbi.RegionSize;
        g_host_n++;
    }
    return 1;
}

/*
 * Never let it take the screen.
 *
 * Clamping CreateWindowEx is not enough and it is worth writing down why: the
 * window the game makes is only where the picture goes. What takes the display
 * is Direct3D, when the game calls IDirect3D9Ex::CreateDeviceEx with
 * D3DPRESENT_PARAMETERS.Windowed = FALSE - and that is not an import. It is a
 * vtable slot on an interface the game got back at run time, so it arrives
 * here as hle_call_address() with a real function pointer and nothing to match
 * on by name.
 *
 * So match on the address. The factory comes back from Direct3DCreate9Ex,
 * which IS an import, and its vtable has CreateDevice at slot 16 and
 * CreateDeviceEx at slot 20. Record those two, and when either is about to be
 * called, set Windowed and drop the fullscreen display mode the Ex form
 * requires to be NULL when windowed.
 *
 * ES3_FULLSCREEN turns this off for someone who actually wants the cabinet
 * behaviour and has a spare screen.
 */
static uint32_t g_d3d_create_device, g_d3d_create_device_ex;

void es3_d3d_note_factory(uint32_t iface)
{
    uint32_t vt;
    if (!iface || g_d3d_create_device_ex) return;
    vt = rd32(iface);
    if (!vt) return;
    g_d3d_create_device    = rd32(vt + 4 * 16);
    g_d3d_create_device_ex = rd32(vt + 4 * 20);
    fprintf(stderr, "[d3d] CreateDevice at %08X, CreateDeviceEx at %08X\n",
            g_d3d_create_device, g_d3d_create_device_ex);
}

/*
 * ES3_TRACE_D3D: the first call to each slot of the device's vtable.
 *
 * A black window with a working device in it is one of two things - a game
 * that is not drawing, or a game that is drawing and never presenting - and
 * from outside they look identical. The vtable says which: IDirect3DDevice9
 * has Present at slot 17, BeginScene at 41, EndScene at 42 and Clear at 43. If
 * none of those is ever reached, nothing is being asked of the renderer at all
 * and the problem is upstream of the graphics entirely.
 *
 * There are no names at run time, only addresses, so the slots are read out of
 * the interface the game was handed and matched by address.
 */
#define D3D_DEV_SLOTS 120
static uint32_t g_dev_slot[D3D_DEV_SLOTS];
static unsigned char g_dev_seen[D3D_DEV_SLOTS];
static int g_trace_d3d = -1;

void es3_d3d_note_device(uint32_t iface)
{
    uint32_t vt;
    int i;
    if (g_trace_d3d < 0) g_trace_d3d = getenv("ES3_TRACE_D3D") != NULL;
    if (!g_trace_d3d || !iface || g_dev_slot[0]) return;
    vt = rd32(iface);
    if (!vt) return;
    for (i = 0; i < D3D_DEV_SLOTS; i++) g_dev_slot[i] = rd32(vt + 4 * i);
    fprintf(stderr, "[d3d] device vtable at %08X; watching %d slots\n",
            vt, D3D_DEV_SLOTS);
}

static const char *dev_slot_name(int i)
{
    switch (i) {
    case 3:  return "TestCooperativeLevel";
    case 16: return "Reset";
    case 17: return "Present";
    case 41: return "BeginScene";
    case 42: return "EndScene";
    case 43: return "Clear";
    default: return "";
    }
}

static void note_device_call(uint32_t target)
{
    int i;
    if (g_trace_d3d <= 0 || !g_dev_slot[0]) return;
    for (i = 0; i < D3D_DEV_SLOTS; i++) {
        if (g_dev_slot[i] != target || g_dev_seen[i]) continue;
        g_dev_seen[i] = 1;
        fprintf(stderr, "[d3d] device slot %d %s\n", i, dev_slot_name(i));
        return;
    }
}

/* D3DPRESENT_PARAMETERS: Windowed is at +0x20, the refresh rate at +0x30. */
static void force_windowed(CPU *c, uint32_t target)
{
    static int off = -1;
    uint32_t pp;
    if (off < 0) off = getenv("ES3_FULLSCREEN") != NULL;
    if (off || !g_d3d_create_device_ex) return;
    if (target != g_d3d_create_device && target != g_d3d_create_device_ex) return;

    pp = A32(5);
    if (!pp) return;
    if (!rd32(pp + 0x20)) {
        static unsigned char said;
        if (!said) {
            said = 1;
            fprintf(stderr, "[d3d] the game asked for an exclusive fullscreen "
                            "device at %ux%u; making it windowed instead "
                            "(ES3_FULLSCREEN=1 to allow it)\n",
                    rd32(pp), rd32(pp + 4));
        }
        wr32(pp + 0x20, 1);          /* Windowed = TRUE */
        wr32(pp + 0x30, 0);          /* a windowed device must ask for 0 Hz */
        if (target == g_d3d_create_device_ex)
            wr32(c->esp + 4 + 4 * 6, 0);   /* pFullscreenDisplayMode = NULL */
    }
}

/*
 * The same thing for DXGI, which is the one that actually decides here.
 *
 * force_windowed() above only knows Direct3D 9, and this game renders with
 * Direct3D 10: it loads d3d10.dll and dxgi.dll by name, resolves
 * D3D10CreateDevice and CreateDXGIFactory with GetProcAddress, and asks the
 * factory for a swap chain. Nothing in that chain is an import, and the
 * factory never passes through a call this runtime can match by name - so
 * there is no vtable slot to record the way Direct3DCreate9Ex let us record
 * CreateDevice.
 *
 * Match the argument instead. IDXGIFactory::CreateSwapChain(this, pDevice,
 * pDesc, ppSwapChain) is the only call into dxgi.dll whose third argument is a
 * DXGI_SWAP_CHAIN_DESC, and that structure identifies itself: a real window
 * handle at +44 and a BOOL at +48. Both have to check out before anything is
 * written.
 *
 *   DXGI_SWAP_CHAIN_DESC
 *     +0  BufferDesc   (DXGI_MODE_DESC, 28 bytes)
 *     +28 SampleDesc   (8)
 *     +36 BufferUsage
 *     +40 BufferCount
 *     +44 OutputWindow
 *     +48 Windowed          <- this
 *     +52 SwapEffect
 *     +56 Flags
 *
 * Windowed = FALSE is a full-screen mode change on the display the window is
 * on, which is the whole thing the screen watchdog exists to prevent and the
 * one route it cannot undo by resizing a window.
 */
static uint32_t g_dxgi_lo, g_dxgi_hi;

static int in_dxgi(uint32_t target)
{
    MEMORY_BASIC_INFORMATION mi;
    wchar_t w[MAX_PATH];
    const wchar_t *leaf;

    if (target >= g_dxgi_lo && target < g_dxgi_hi) return 1;
    if (g_dxgi_lo) return 0;                 /* known, and this is not it */
    if (!VirtualQuery((LPCVOID)(uintptr_t)target, &mi, sizeof mi) ||
        mi.Type != MEM_IMAGE) return 0;
    if (!GetModuleFileNameW((HMODULE)mi.AllocationBase, w, MAX_PATH)) return 0;
    leaf = wcsrchr(w, L'\\');
    if (_wcsicmp(leaf ? leaf + 1 : w, L"dxgi.dll") != 0) return 0;
    g_dxgi_lo = (uint32_t)(uintptr_t)mi.AllocationBase;
    g_dxgi_hi = g_dxgi_lo + 0x00200000u;     /* generous; only used as a filter */
    return 1;
}

static void force_windowed_dxgi(CPU *c, uint32_t target)
{
    static int off = -1;
    uint32_t desc;

    if (off < 0) off = getenv("ES3_FULLSCREEN") != NULL;
    if (off || !in_dxgi(target)) return;

    desc = A32(2);                            /* pDesc, past `this` */
    if (!desc || desc < 0x10000u) return;
    {
        /* VirtualQuery rather than IsBadReadPtr, which probes by faulting:
         * every call raises a first-chance access violation that the vectored
         * handler then reports, and this one would run on every DXGI call. */
        MEMORY_BASIC_INFORMATION mi;
        if (!VirtualQuery((LPCVOID)(uintptr_t)desc, &mi, sizeof mi) ||
            mi.State != MEM_COMMIT ||
            (mi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) ||
            desc + 60 > (uint32_t)(uintptr_t)mi.BaseAddress +
                        (uint32_t)mi.RegionSize) return;
    }
    if (!IsWindow((HWND)(uintptr_t)rd32(desc + 44))) return;
    if (rd32(desc + 48) > 1) return;          /* not a BOOL: not this call */

    if (rd32(desc + 48) == 0) {
        static unsigned char said;
        if (!said) {
            said = 1;
            fprintf(stderr, "[dxgi] the game asked for an exclusive fullscreen "
                            "swap chain at %ux%u; making it windowed instead "
                            "(ES3_FULLSCREEN=1 to allow it)\n",
                    rd32(desc), rd32(desc + 4));
        }
        wr32(desc + 48, 1);                   /* Windowed = TRUE */
    }
}

/*
 * ES3_TRACE_HOSTCALLS: every real function the guest calls that is not an
 * import, once each.
 *
 * Imports are named and traceable; a COM method is not. The game gets
 * Direct3D 10 and DXGI through LoadLibrary and GetProcAddress, and everything
 * it then does with them - create the swap chain, set state, draw, present -
 * is a vtable slot. dispatch() recognises those as host code and sends them
 * here, which makes this the one place the whole renderer is visible.
 *
 * That settles the question a black window asks. "d3d10.dll+0x1a2b0, once" is
 * a device that was created and never used; the same line arriving every frame
 * is a game that is drawing and the problem is elsewhere.
 *
 * Direct-mapped and lossy on purpose: one load per call to decide whether this
 * address has been seen, and a collision costs a duplicate line, not a wrong
 * answer.
 */
static int g_trace_host = -1;
static uint32_t g_host_seen[4096];

static void note_host_call(uint32_t target)
{
    unsigned slot;
    MEMORY_BASIC_INFORMATION mi;
    wchar_t w[MAX_PATH];
    const wchar_t *leaf;
    char name[64];

    if (g_trace_host < 0) g_trace_host = getenv("ES3_TRACE_HOSTCALLS") != NULL;
    if (!g_trace_host) return;

    slot = (target >> 2) & 4095u;
    if (g_host_seen[slot] == target) return;
    g_host_seen[slot] = target;

    if (!VirtualQuery((LPCVOID)(uintptr_t)target, &mi, sizeof mi) ||
        mi.Type != MEM_IMAGE ||
        !GetModuleFileNameW((HMODULE)mi.AllocationBase, w, MAX_PATH)) {
        fprintf(stderr, "[hostcall] %08X (not in a module)\n", target);
        return;
    }
    leaf = wcsrchr(w, L'\\');
    WideCharToMultiByte(CP_ACP, 0, leaf ? leaf + 1 : w, -1,
                        name, sizeof name, NULL, NULL);
    /* With the base, because the trail records these as bare addresses and the
     * only way to turn a trail full of them back into module+offset afterwards
     * is to have been told where each module sits. */
    fprintf(stderr, "[hostcall] %s+0x%X  (base %08X)\n", name,
            target - (uint32_t)(uintptr_t)mi.AllocationBase,
            (uint32_t)(uintptr_t)mi.AllocationBase);
}

void hle_call_address(CPU *c, uint32_t target)
{
    hybrid_regs r;

    r.eax = c->eax; r.ecx = c->ecx; r.edx = c->edx; r.ebx = c->ebx;
    r.esp = c->esp; r.ebp = c->ebp; r.esi = c->esi; r.edi = c->edi;

    force_windowed(c, target);
    force_windowed_dxgi(c, target);
    note_device_call(target);
    note_host_call(target);

    hybrid_call_machine(&r, target);

    /*
     * IDXGIAdapter::EnumOutputs came back empty. Hand it a display.
     *
     * A DXUT title builds its list of usable device settings from the display
     * modes an adapter's outputs report, so an adapter with none contributes
     * nothing and DXUT ends with "Could not find any compatible Direct3D
     * devices" in a modal box. That is what a session with no attached display
     * looks like - and windowed Direct3D works in one perfectly well, so the
     * enumeration is the only thing that failed. See dxgi_output.c.
     *
     * Only for output 0, and only when the real call actually found nothing:
     * on a machine with a monitor this never fires.
     */
    if (target && target == es3_dxgi_enum_outputs_addr() &&
        (uint32_t)r.eax == 0x887A0002u /* DXGI_ERROR_NOT_FOUND */ &&
        A32(1) == 0) {
        uint32_t pp = A32(2), fake = es3_fake_output();
        if (pp && fake) { wr32(pp, fake); r.eax = 0; }
    }

    /* The one COM result worth a line: whether the renderer exists. Everything
     * the game draws depends on it, and a device that failed leaves a window
     * that is simply black - which looks exactly like a game that has not got
     * there yet. */
    if (target && (target == g_d3d_create_device ||
                   target == g_d3d_create_device_ex)) {
        static unsigned char said;
        if (!said) {
            said = 1;
            fprintf(stderr, "[d3d] CreateDevice%s returned %08X\n",
                    target == g_d3d_create_device_ex ? "Ex" : "", r.eax);
        }
        if (r.eax == 0) {
            uint32_t ppdev = A32(target == g_d3d_create_device_ex ? 7 : 6);
            if (ppdev) es3_d3d_note_device(rd32(ppdev));
        }
    }

    c->eax = r.eax;
    c->edx = r.edx;
    c->esp = r.esp;    /* the real callee's own `ret N` did the unwinding */
}

static void native_thunk(CPU *c, HleId id) { hle_call_native(c, id); }

/*
 * A forwarded import that never comes back, called the ordinary way.
 *
 * hybrid_call_machine points the REAL esp at the guest's frame, which is
 * exactly right for a function that returns: the arguments are there, and the
 * callee's own `ret N` says how much to unwind. It is exactly wrong for one
 * that does not return.
 *
 * `_endthreadex` runs the CRT's thread teardown, and part of that teardown is
 * the FLS destructor that frees this thread's callback arena - which is the
 * memory the guest frame, and therefore the real esp, is standing on. The
 * teardown gets a few calls further and then a plain `ret` in ntdll reads
 * unmapped memory. That is a stack the kernel cannot dispatch an exception on,
 * so there is no handler, no filter and no log: the process is simply gone
 * with 0xC0000005 eight seconds into the boot.
 *
 * So call it as C, from the host's own stack. Nothing needs marshalling back,
 * because there is no back.
 */
void hle_call_native_noreturn(CPU *c, HleId id)
{
    typedef void (__stdcall *exit_fn)(unsigned);
    exit_fn f = (exit_fn)g_native[id];
    unsigned code = A32(0);
    if (!f) { fprintf(stderr, "[hle] %s is not bound\n", hle_name(id)); abort(); }
    f(code);
    abort();                 /* it said it would not return */
}

/* The first call to each import, in order, when ES3_TRACE_IMPORTS is set.
 *
 * The dispatch trail says what guest code did; this says what it asked the
 * world for, which is a different and often more useful question. A game that
 * is alive but showing nothing has usually stopped somewhere identifiable in
 * that sequence - it got as far as CreateWindowExW and not Direct3DCreate9,
 * say - and the blocked thread itself is invisible, because a thread waiting
 * inside real Win32 code dispatches nothing. */
static unsigned char g_first[HLE_COUNT];
static int g_trace = -1;

/* ES3_TRACE_CALLS=Name,Name,... - every call to those, with its arguments and
 * its result. The first-call list says how far the game got; this says what
 * happened when it got there, which is the next question and usually the last
 * one. A window that comes back 0x0 with a 0x0 rectangle is not a mystery once
 * you can see the arguments that made it. */
static unsigned char g_watch[HLE_COUNT];

/* The libraries where a 32-bit argument equal to the guest's image base can
 * only be an HINSTANCE. USER32, DINPUT8, GDI32 and the D3D family take module
 * handles and never take a pointer into a PE header as data. KERNEL32 does
 * both - VirtualQuery(0x00400000) is a sincere question about the guest image -
 * so it is deliberately not on the list. */
static int takes_hinstance(const char *dll)
{
    return _strnicmp(dll, "USER32", 6) == 0 ||
           _strnicmp(dll, "DINPUT", 6) == 0 ||
           _strnicmp(dll, "GDI32",  5) == 0 ||
           _strnicmp(dll, "d3d",    3) == 0;
}

/* An argument that is really a filename.
 *
 * `[call] fopen_s(0683C8E4, 008D9EC8, 00888BC8, 0)` says nothing; the same
 * line with "Data/System/Model/cube.bin" in it says everything, and the whole
 * question of why a load failed usually turns on which path was asked for.
 *
 * Deliberately conservative: readable memory, printable ASCII, terminated
 * inside 120 bytes, and at least four characters - so an integer that happens
 * to be a valid pointer does not come back as a two-letter word. Anything it
 * declines still prints as hex. */
const char *es3_arg_string(uint32_t va)
{
    static char buf[128];
    const char *p = (const char *)(uintptr_t)va;
    unsigned i;
    MEMORY_BASIC_INFORMATION mi;

    if (va < 0x10000u) return NULL;
    if (!VirtualQuery((LPCVOID)(uintptr_t)va, &mi, sizeof mi) ||
        mi.State != MEM_COMMIT || (mi.Protect & PAGE_NOACCESS)) return NULL;
    for (i = 0; i < sizeof buf - 1; i++) {
        char ch = p[i];
        if (ch == 0) break;
        if ((unsigned char)ch < 0x20 || (unsigned char)ch > 0x7E) return NULL;
        buf[i] = ch;
    }
    if (i >= 4 && i < sizeof buf - 1) { buf[i] = 0; return buf; }

    /*
     * Then UTF-16, because this game is a W-API program and almost every
     * string it passes is wide. Read as bytes it is one character and a null,
     * so the loop above stops at i == 1 and declines - and the argument that
     * mattered most, the text of the MessageBoxW the game puts up when it will
     * not start, printed as a bare pointer.
     *
     * Converted with the ANSI code page rather than copied: this title is
     * Japanese and its messages are too, so the useful thing to put in the log
     * is whatever the console can render of them.
     */
    {
        const wchar_t *w = (const wchar_t *)(uintptr_t)va;
        unsigned n;
        int k;
        for (n = 0; n < 200; n++) {
            if ((const char *)(w + n + 1) >
                (const char *)mi.BaseAddress + mi.RegionSize) return NULL;
            if (w[n] == 0) break;
            if (w[n] < 0x20 && w[n] != '\n' && w[n] != '\r' && w[n] != '\t')
                return NULL;
        }
        if (n < 2 || n >= 200) return NULL;
        k = WideCharToMultiByte(CP_ACP, 0, w, (int)n, buf,
                                (int)sizeof buf - 1, NULL, NULL);
        if (k <= 0) return NULL;
        buf[k] = 0;                  /* it converts a length, not a terminator */
        return buf;
    }
}

/* Said once per import, not once per call. */
static unsigned char g_hinst_said[HLE_COUNT];
static int g_watch_set;

static void watch_init(void)
{
    const char *list = getenv("ES3_TRACE_CALLS");
    unsigned i;
    g_watch_set = 1;
    if (!list) return;
    for (i = 0; i < HLE_COUNT; i++) {
        const char *n = hle_name((HleId)i), *p = strstr(list, n);
        size_t len = strlen(n);
        /* A whole comma-separated field, so "Sleep" does not match
         * "SleepEx" and "memcpy" does not match "wmemcpy". */
        if (p && (p == list || p[-1] == ',') && (p[len] == 0 || p[len] == ','))
            g_watch[i] = 1;
    }
}

void hle_call_native(CPU *c, HleId id)
{
    hybrid_regs r;

    if (g_trace < 0) g_trace = getenv("ES3_TRACE_IMPORTS") != NULL;
    if (g_trace && !g_first[id]) {
        g_first[id] = 1;
        fprintf(stderr, "[import] %s (%s)\n", hle_name(id), hle_dll(id));
    }
    int n = g_fpu_args[id];
    int depth_before;

    /* Move the guest's x87 arguments onto the host stack, top first. The CPU
     * model keeps st(0) at c->st[c->fpu_top] and grows downward, the same way
     * the hardware does. */
    if (n) {
        double st[8];
        int i;
        for (i = 0; i < n; i++)
            st[i] = c->st[(c->fpu_top + i) & 7];
        hybrid_fpu_push(st, n);
        c->fpu_top = (c->fpu_top + n) & 7;      /* the guest's copies are consumed */
    }
    depth_before = hybrid_fpu_depth() - n;

    /*
     * Re-state the stack bounds, here, every time.
     *
     * es3_teb_cover() writes NT_TIB.StackLimit so that a handler registered
     * from the guest's stack validates - and StackLimit is not ours to keep.
     * The kernel owns it: it moves it down on a guard-page hit and back up
     * when a stack is trimmed, so a cover applied once at a thread's first
     * crossing is undone later by something that has nothing to do with us.
     * The symptom is silent and total. OutputDebugString raises 0x40010006
     * and catches it in its own __try; with the bounds reset, no frame on the
     * guest stack is eligible, nobody catches it, and the process ends with
     * 40010006 for an exit code and a log that simply stops.
     *
     * This is the moment it matters - a forwarded import is exactly where real
     * code runs on the guest's stack and registers a handler on it - so the
     * cover is reapplied rather than remembered. Two reads and usually no
     * write, against a call that is about to cross into a DLL.
     */
    es3_teb_cover(c->esp - (64u << 10), c->esp + 0x1000u);

    r.eax = c->eax; r.ecx = c->ecx; r.edx = c->edx; r.ebx = c->ebx;
    r.esp = c->esp; r.ebp = c->ebp; r.esi = c->esi; r.edi = c->edi;

    /*
     * The guest's HINSTANCE is not a module this process loaded.
     *
     * An MSVC image knows its own base as `__ImageBase`, a link-time constant,
     * and hands it to Windows wherever an HINSTANCE is wanted - WinMain's
     * first argument, a window class, a resource lookup. Here that constant is
     * 0x00400000, which in this process is a region VirtualAlloc handed out.
     * The loader has never heard of it, so an API that validates it says so:
     * DirectInput8Create returns E_INVALIDARG, the game's input initialiser
     * returns false, and the whole chain of subsystem opens after it is
     * skipped - which surfaces, thirty thousand calls later, as a task
     * updating through a null singleton.
     *
     * So substitute this process's own module handle. The image base is the
     * PE header; nothing passes a pointer to that as data, and if something
     * ever does, ES3_NO_HINSTANCE_FIX turns this off and the symptom comes
     * straight back.
     *
     * Resources are the honest caveat: a FindResource against the host's
     * handle looks in the host's image, which has none of the game's. No ES3
     * title has asked yet - they ship their data in files - and when one does,
     * the answer is to serve the guest image's own resource directory rather
     * than to stop substituting.
     */
    if (!g_watch_set) watch_init();
    {
        static int off = -1;
        uint32_t gbase = guest_image_base();
        int purge = hle_purge(id);
        int na = purge / 4;
        int k;
        if (off < 0) off = getenv("ES3_NO_HINSTANCE_FIX") != NULL;
        /* Only where an HINSTANCE is what the argument means, and only where
         * the purge says exactly how many arguments there are.
         *
         * The first attempt applied it everywhere and guessed eight arguments
         * for anything cdecl. `memset(dst, 0, n)` has three, the fourth slot
         * on the guest stack happened to hold 0x00400000, and rewriting it
         * corrupted the caller's frame - a worse bug than the one being fixed,
         * arriving somewhere else entirely. KERNEL32 stays out for the same
         * reason from the other direction: VirtualQuery(0x00400000) is a
         * sincere question about the guest image and must be left alone. */
        if (off || purge <= 0 || !takes_hinstance(hle_dll(id))) na = 0;
        for (k = 0; k < na && k < 16; k++) {
            if (A32(k) != gbase) continue;
            if (!g_hinst_said[id]) {
                g_hinst_said[id] = 1;
                fprintf(stderr, "[hle] %s was given the guest's own image base "
                                "as argument %d - passing this process's module "
                                "handle instead\n", hle_name(id), k);
            }
            wr32(c->esp + 4 + 4 * (uint32_t)k,
                 (uint32_t)(uintptr_t)GetModuleHandleW(NULL));
        }
    }

    if (g_watch[id]) {
        int purge = hle_purge(id);
        int na = purge > 0 ? purge / 4 : 4;
        int k;
        fprintf(stderr, "[call] %s(", hle_name(id));
        for (k = 0; k < na && k < 12; k++) {
            uint32_t v = A32(k);
            const char *s = es3_arg_string(v);
            if (s) fprintf(stderr, "%s\"%s\"", k ? ", " : "", s);
            else   fprintf(stderr, "%s%08X", k ? ", " : "", v);
        }
        fprintf(stderr, ")");
    }

    {
        /* Clear it first, or the traced error is whatever the last unrelated
         * call left behind - which is how a red herring gets into a log. */
        if (g_watch[id]) SetLastError(0);
        hybrid_call_machine(&r, (uint32_t)(uintptr_t)g_native[id]);
    }

    c->eax = r.eax;
    c->edx = r.edx;
    c->esp = r.esp;          /* the real callee's own unwind - see hle_call */

    if (g_watch[id])
        fprintf(stderr, " = %08X   (last error %lu)\n", r.eax, GetLastError());

    /* A callee that returned a float left the host stack one deeper than it
     * found it. No table says which ones those are; the depth does. */
    {
        int extra = hybrid_fpu_depth() - depth_before;
        if (extra > 0) {
            double v = hybrid_fpu_pop();
            extra--;
            /* More than one left behind is not a float return - it is a
             * mismatch in this file's idea of the arity above. Say so rather
             * than leave an x87 stack that overflows eight calls later, in
             * code with nothing to do with the cause. */
            if (extra > 0) {
                fprintf(stderr, "[hle] %s left %d extra x87 values - "
                                "check its entry in CI_HELPERS\n",
                        hle_name(id), extra);
                while (extra-- > 0) (void)hybrid_fpu_pop();
            }
            fpush(c, v);
        }
    }
}

/* Which imports turned out to be variables rather than functions. */
static unsigned char g_is_data[HLE_COUNT];

int hle_is_data(HleId id) { return (unsigned)id < HLE_COUNT && g_is_data[id]; }

/* An import is DATA if the address the DLL exports is not executable.
 *
 * The C runtime exports plenty of these - `_fmode`, `_commode`, `_environ`,
 * `_iob`, `_pctype` - and a game does not call them, it dereferences them. So
 * their IAT slot must hold the real address in the real DLL, not a sentinel;
 * the first write through one is otherwise a fault on an unmapped page, and it
 * reads as a call to a function that never happened.
 *
 * Asking the page rather than keeping a list of names: the list would be wrong
 * for the next C runtime, and there is no reason to guess when the loader
 * already knows. VirtualQuery on what GetProcAddress returned is the answer.
 */
static int address_is_code(FARPROC p)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((LPCVOID)p, &mbi, sizeof mbi)) return 1;   /* assume code */
    return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

static void data_import_called(CPU *c, HleId id)
{
    (void)c;
    fprintf(stderr,
            "[hle] %s (%s) is a variable, not a function, and something called "
            "it.\n", hle_name(id), hle_dll(id));
    abort();
}

int hle_bind_native(HleId id)
{
    const char *name = hle_name(id);
    HMODULE h;
    FARPROC p;
    unsigned i;

    h = LoadLibraryA(hle_dll(id));
    if (!h) return 0;

    /* An ordinal-only import - the OKAO libraries are all of these - arrives
     * named `ordinal_N` and has to be looked up by number. Those DLLs are not
     * on a desktop, so this path is for the rare system DLL imported the same
     * way (COMCTL32 ordinal 17 is InitCommonControls). */
    if (strncmp(name, "ordinal_", 8) == 0)
        p = GetProcAddress(h, (LPCSTR)(uintptr_t)(unsigned)atoi(name + 8));
    else
        p = GetProcAddress(h, name);
    if (!p) return 0;

    if (!address_is_code(p)) {
        /* The slot holds the address of a variable in the real DLL, and the
         * game reaches it by dereferencing rather than calling. */
        g_is_data[id] = 1;
        guest_patch_import(id, (uint32_t)(uintptr_t)p);
        g_hle_handlers[id] = data_import_called;
        return 1;
    }

    for (i = 0; i < sizeof CI_HELPERS / sizeof CI_HELPERS[0]; i++)
        if (strcmp(name, CI_HELPERS[i].name) == 0) {
            g_fpu_args[id] = CI_HELPERS[i].argc;
            break;
        }

    g_native[id] = p;
    g_hle_handlers[id] = native_thunk;
    return 1;
}

void hle_register_native(void)
{
    unsigned i, bound = 0, missing = 0;
    for (i = 0; i < HLE_COUNT; i++)
        if (hle_bind_native((HleId)i)) bound++; else missing++;
    fprintf(stderr,
            "[hle] %u imports forwarded to the host's own DLLs, %u not found\n",
            bound, missing);
    if (missing)
        fprintf(stderr,
            "      The ones left are the cabinet: JVS I/O, the card reader, the\n"
            "      camera, the authentication. See docs/board-io.md. Each aborts\n"
            "      naming itself when the game first calls it.\n");
}

#else  /* !_WIN32 */

int  hle_bind_native(HleId id) { (void)id; return 0; }

void hle_register_native(void)
{
    fprintf(stderr,
        "[hle] not a Windows host: nothing to forward to. Every import needs a\n"
        "      hand-written body, and the first one called will say which.\n");
}

#endif
