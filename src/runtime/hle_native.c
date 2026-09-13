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
static void native_thunk(CPU *c, HleId id)
{
    hybrid_regs r;
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

    hybrid_call_machine(&r, (uint32_t)(uintptr_t)g_native[id]);

    c->eax = r.eax;
    c->edx = r.edx;
    c->esp = r.esp;          /* the real callee's own unwind - see hle_call */

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
