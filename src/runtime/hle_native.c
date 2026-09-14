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

void hle_call_address(CPU *c, uint32_t target)
{
    hybrid_regs r;

    r.eax = c->eax; r.ecx = c->ecx; r.edx = c->edx; r.ebx = c->ebx;
    r.esp = c->esp; r.ebp = c->ebp; r.esi = c->esi; r.edi = c->edi;

    hybrid_call_machine(&r, target);

    c->eax = r.eax;
    c->edx = r.edx;
    c->esp = r.esp;    /* the real callee's own `ret N` did the unwinding */
}

static void native_thunk(CPU *c, HleId id) { hle_call_native(c, id); }

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

    r.eax = c->eax; r.ecx = c->ecx; r.edx = c->edx; r.ebx = c->ebx;
    r.esp = c->esp; r.ebp = c->ebp; r.esi = c->esi; r.edi = c->edi;

    if (!g_watch_set) watch_init();
    if (g_watch[id]) {
        int purge = hle_purge(id);
        int na = purge > 0 ? purge / 4 : 4;
        int k;
        fprintf(stderr, "[call] %s(", hle_name(id));
        for (k = 0; k < na && k < 8; k++)
            fprintf(stderr, "%s%08X", k ? ", " : "", A32(k));
        fprintf(stderr, ")");
    }

    hybrid_call_machine(&r, (uint32_t)(uintptr_t)g_native[id]);

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
