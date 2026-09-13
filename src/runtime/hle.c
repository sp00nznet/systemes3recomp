/*
 * hle.c - the DLLs the board provided.
 *
 * An ES3 game imports from three worlds at once: Windows itself, the
 * DirectX/MSVCR100 redistributables, and a short list of DLLs that only exist
 * inside the cabinet. All of them leave through the IAT, and guest_load()
 * pointed every slot here.
 *
 * An id with no implementation aborts naming itself and the DLL it came from.
 * That is deliberate: a silent no-op turns a missing import into a graphical
 * glitch three hours later, and the name printed here is the next thing to
 * write.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "es3_rt.h"

#define HLE_NAME(id, name, dll, purge) name,
static const char *const g_names[] = { HLE_IMPORTS(HLE_NAME) };
#undef HLE_NAME

#define HLE_DLL(id, name, dll, purge) dll,
static const char *const g_dlls[] = { HLE_IMPORTS(HLE_DLL) };
#undef HLE_DLL

/* Argument bytes the real callee pops, derived per import by pcrecomp's
 * tools/pe/stdcall_argc.py. -1 means it could not be derived, and an import
 * like that must not be called: a guessed purge desynchronises the guest stack
 * and every value read after it is garbage. */
#define HLE_PURGE(id, name, dll, purge) purge,
static const int g_purge[] = { HLE_IMPORTS(HLE_PURGE) };
#undef HLE_PURGE

const char *hle_name(HleId id)
{
    return (unsigned)id < HLE_COUNT ? g_names[id] : "<bad id>";
}

const char *hle_dll(HleId id)
{
    return (unsigned)id < HLE_COUNT ? g_dlls[id] : "?";
}

HleHandler g_hle_handlers[HLE_COUNT];

int hle_bind(const char *name, HleHandler fn)
{
    for (unsigned i = 0; i < HLE_COUNT; i++)
        if (strcmp(g_names[i], name) == 0) { g_hle_handlers[i] = fn; return 1; }
    return 0;   /* this game does not import it - nothing to bind, not a fault */
}

int hle_purge(HleId id)
{
    return (unsigned)id < HLE_COUNT ? g_purge[id] : -1;
}

void hle_register_all(void)
{
    hle_register_native();
    hle_register_board();
}

void hle_call(CPU *c, HleId id)
{
    if ((unsigned)id >= HLE_COUNT) {
        fprintf(stderr, "[hle] call to id %u, which is out of range\n", (unsigned)id);
        abort();
    }
    if (!g_hle_handlers[id]) {
        const char *what = hle_board_note(g_dlls[id]);
        fprintf(stderr,
                "[hle] %s (%s) is not implemented.\n"
                "      %s\n"
                "      Give it a body:  hle_bind(\"%s\", my_%s);\n",
                g_names[id], g_dlls[id],
                what ? what : "Not a cabinet DLL - is the redistributable installed?",
                g_names[id], g_names[id]);
        abort();
    }

    uint32_t entry_esp = c->esp;
    g_hle_handlers[id](c, id);

    /* Set the frame rather than adjust it, so a handler that already unwound
     * for itself and one that ignored esp entirely both end up in the same
     * place. The native forwarder is the first kind: the real callee's own
     * `ret N` did the work, and its answer is better than the table's.
     *
     * A hand-written handler needs the table, and an import whose purge could
     * not be derived has no table entry to use. Guessing one desynchronises
     * the guest stack and the symptom shows up nowhere near the cause, so this
     * says so and stops instead. */
    if (g_purge[id] >= 0) {
        c->esp = entry_esp + 4u + (uint32_t)g_purge[id];
    } else if (c->esp == entry_esp) {
        fprintf(stderr,
                "[hle] %s (%s): the stack purge could not be derived and the\n"
                "      handler did not unwind, so the guest stack is unsafe to\n"
                "      resume on. Give the scan a copy of %s, or have the\n"
                "      handler set c->esp itself.\n",
                g_names[id], g_dlls[id], g_dlls[id]);
        abort();
    }
}
