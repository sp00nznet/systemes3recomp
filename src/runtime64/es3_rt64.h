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

/* --log-imports: one line the first time each import is really called. */
extern int g_log_imports;
void es3_note_import(uint64_t addr);

/* Imports the runtime intervenes in; resolved at load time. */
extern uint64_t g_addr_RaiseException;
extern uint64_t g_addr_CxxThrowException;
/* The cabinet service: RSSharedData and its six mutexes. See dispatch64.c. */
void es3_rs_service(void);
void es3_rs_dump(void);
extern size_t g_rs_size;
extern int g_io_board;
extern unsigned g_io_press_at;
extern int g_rs_poke;
extern int g_rs_dump_on;

/* Device enumeration, which is how this title looks for its I/O board. */
extern uint64_t g_addr_OpenFileMappingW, g_addr_LoadLibraryW, g_addr_LoadLibraryA;
extern uint64_t g_addr_MessageBoxW, g_addr_MessageBoxA;
extern uint64_t g_addr_GetSystemMetrics;
extern int g_screen_w, g_screen_h;
extern uint64_t g_addr_SetupDiGetClassDevsW, g_addr_SetupDiEnumDeviceInterfaces;
extern uint64_t g_addr_CM_Locate_DevNodeW;

/* The Sentinel dongle, imported by ordinal - see the note in dispatch64.c. */
extern uint64_t g_addr_hasp_login, g_addr_hasp_logout;
extern uint64_t g_addr_hasp_read, g_addr_hasp_decrypt;
extern uint64_t g_addr_initterm;
extern uint64_t g_addr_initterm_e;
extern uint64_t g_addr_CreateThread;
extern uint64_t g_addr_CreateFileW;
extern uint64_t g_addr_CreateFileA;
extern uint64_t g_addr_WriteFile;
extern int g_trace_files;
extern int g_guest_log;
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
void es3_dump_threads(void);
/* Reports which thread is spinning when the game stops presenting. */
void es3_start_watchdog(void);
void es3_note_file(const wchar_t *path);
void es3_dump_callstack(const char *why);
void es3_todo(uint64_t va, const char *text);

/* The CPU running lifted code on this thread; c->rip is the guest PC, kept
 * per basic block by the lifter. NULL when no lifted code is on the stack. */
extern __declspec(thread) CPU *g_cur_cpu;
void es3_install_crash_handler(void);

extern int g_trace_enabled;
extern uint64_t g_dispatch_limit;
extern uint64_t g_dispatch_count;
extern int g_swallow_raise;
extern uint64_t g_watch_serialize;
extern uint64_t g_watch_reader;
extern uint64_t g_watch_alloc;
extern uint64_t g_addr_scalable_malloc;
extern uint64_t g_addr_DirectInput8Create;
extern uint64_t g_addr_Direct3DCreate9;
extern __declspec(thread) int g_watch_armed;
void es3_watch_reader(CPU *c, uint64_t pref);
extern uint64_t g_log_calls[8];
extern int g_n_log_calls;
void es3_log_call(CPU *c, uint64_t pref);
extern uint64_t g_callees_of;
void es3_log_callee(uint64_t pref);

/* Guest C++ exception handling; the engine lives in pcrecomp's
 * runtime/recomp64_cpu/eh64.c and is declared by cpu64.h. */
extern uint64_t es3_eh_image_base;
extern int g_eh_trace;

/* Counts frames, because on a session with no display device a black window
 * proves nothing. */
void es3_d3d9_watch(void *d3d9);
/* "active" / "DISCONNECTED" - a disconnected session has no D3D adapter. */
const char *es3_session_state(void);
extern unsigned long long g_present_count;
extern unsigned long long g_capture_frame;
extern unsigned long long g_capture_every;
extern unsigned long long g_capture_max;

extern const char *g_find_string;
void es3_find_string(void);

#endif /* ES3_RT64_H */
