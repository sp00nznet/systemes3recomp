/*
 * es3_rt64.h - the 64-bit ES3 runtime.
 *
 * The 32-bit runtime (src/runtime) exists because a Win32 arcade PE cannot be
 * run by a 64-bit host: the image wants a low base, the ABI differs from the
 * host's, and every import has to be reimplemented or thunked across the word
 * size. None of that is true here. Star Wars Battle Pods is a Win64 PE and this
 * is a Win64 host, so:
 *
 *   * the image loads at its own preferred base, 0x140000000, and the
 *     relocation delta is normally zero;
 *   * the guest's calling convention IS the host's, so an import is forwarded
 *     to the real DLL rather than reimplemented;
 *   * guest pointers are host pointers, so no address translation exists.
 *
 * What remains is genuinely ES3-specific: the arcade I/O the machine has and a
 * PC does not, and the few imports whose argument is guest CODE - a thread
 * entry point, a window procedure, a callback - which cannot be handed to a
 * native DLL because the address is lifted C, not machine code at that address.
 */
#ifndef ES3_RT64_H
#define ES3_RT64_H

#include "cpu64.h"

#include <stdint.h>

/* ---- the lifted image ----
 * recomp_entry_t and the table come from the generated recomp_dispatch.h, so
 * there is one definition rather than two that can disagree about a function
 * pointer's signature. */
#include "recomp_dispatch.h"

/* ---- loader ---- */
typedef struct {
    uint8_t *base;             /* where the image actually landed */
    uint64_t preferred;        /* what the PE asked for */
    uint64_t size;             /* SizeOfImage */
    uint64_t entry;            /* entry point VA, adjusted for the real base */
    uint64_t text_lo, text_hi; /* the range dispatch() treats as guest code */
} es3_image_t;

extern es3_image_t g_image;

/* Set by the loader; every GVA() in the lifted code adds it. */
extern int64_t g_image_delta;

int  es3_load_image(const char *path);
void es3_free_image(void);

/* ---- guest stack ---- */
uint64_t es3_alloc_stack(size_t bytes);

/* ---- dispatch ---- */
void dispatch(CPU *c, uint64_t target);
void dispatch_jmp(CPU *c, uint64_t target);

/* A target that is not a lifted function and not inside the image is a real
 * function in a real DLL, reached through the IAT. Returns 1 if it handled the
 * call. */
int  es3_native_call(CPU *c, uint64_t target);

/* Diagnostics: the name behind a native address, or NULL. */
const char *es3_import_name(uint64_t addr);

/* Imports the runtime intervenes in; resolved at load time. */
extern uint64_t g_addr_RaiseException;
extern uint64_t g_addr_initterm;
extern uint64_t g_addr_initterm_e;
extern uint64_t g_addr_CreateThread;
extern uint64_t g_addr_CreateFileW;
extern uint64_t g_addr_CreateFileA;
extern uint64_t g_addr_WriteFile;
extern int g_trace_files;
extern uint64_t g_addr_GetCommandLineW;
extern uint64_t g_addr_GetCommandLineA;
extern uint64_t g_addr_ReadFile;
extern uint64_t g_addr_GetFileSize;
extern uint64_t g_addr_GetFileSizeEx;

/* The command line the GUEST sees, which is not the runtime's. */
void es3_set_guest_cmdline(const char *exe, const char *args);

/* Enter a lifted function from the runtime - for a guest callback a real DLL
 * would otherwise call directly. */
void es3_call_guest(CPU *c, uint64_t target);

/* Bridge a native->guest call caught as a DEP execute fault. Returns 1 if it
 * handled the fault, in which case the thread should continue execution. */
struct _EXCEPTION_POINTERS;
int es3_bridge_callback(struct _EXCEPTION_POINTERS *ep);

/* ---- tracing ----
 * A recompiled game that stops has stopped SOMEWHERE, and with no symbols and
 * no debugger attached the only way to find out where is to have written it
 * down. The trail is a ring buffer in memory, dumped on a fault. */
void es3_trace(uint64_t va, const char *what);
void es3_trace_dump(const char *why);
void es3_trace_tail(int n);
void es3_install_crash_handler(void);

extern int g_trace_enabled;
extern uint64_t g_dispatch_limit;
extern uint64_t g_dispatch_count;
extern int g_swallow_raise;
extern uint64_t g_watch_serialize;
extern uint64_t g_watch_reader;
extern __declspec(thread) int g_watch_armed;
void es3_watch_reader(CPU *c, uint64_t pref);
extern uint64_t g_log_calls[8];
extern int g_n_log_calls;
void es3_log_call(CPU *c, uint64_t pref);

#endif /* ES3_RT64_H */
