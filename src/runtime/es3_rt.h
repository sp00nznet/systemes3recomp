/*
 * es3_rt.h - runtime for statically recompiled Namco System ES3 games.
 *
 * The CPU model is pcrecomp's (pcrecomp/runtime/recomp32_cpu/cpu.h): an
 * explicit `CPU *c` threaded through every lifted function, flat memory where
 * a register holds a real 32-bit host address. The host must therefore be a
 * 32-bit build - an ES3 image is mapped at the virtual addresses it was linked
 * for, and those start at 0x00400000.
 *
 * What this header adds is the board. An ES3 game is a Win32 PE and most of
 * what it asks for is Windows, which the host already is; the interesting part
 * is the rest of the cabinet - the JVS I/O the wheel and coins arrive on, the
 * card reader, the camera that photographs the player, and the network
 * authentication that will never answer again.
 */
#ifndef ES3_RT_H
#define ES3_RT_H

/* Generated code calls abort() wherever an instruction did not lift, so the
 * declaration has to travel with the header the generated code includes. */
#include <stdint.h>
#include <stdlib.h>

/* An instruction the lifter could not express. cpu.h makes this a bare
 * abort(), which in a release build is __fastfail: no vectored handler sees
 * it, the process is gone, and the log is empty. Two million lines of
 * generated C need better than that, so it says which guest address and which
 * mnemonic, and prints how the guest got there. Defined before cpu.h, which
 * only supplies the default. */
#define RECOMP_TODO(va, text) es3_unlifted((va), (text))
void es3_unlifted(uint32_t va, const char *text);

#include "cpu.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- guest process ---- */

/* Map a PE's sections at their linked virtual addresses, point every IAT slot
 * at its HLE sentinel, and set up the guest stack. Returns 0, or -1 with the
 * reason on stderr. */
int  guest_load(const char *exe_path);

/* Entry point VA from the PE header, valid after guest_load. */
uint32_t guest_entry(void);

/* Initialise a CPU to enter the guest: esp at the top of the guest stack with
 * a sentinel return address below it, everything else zero. */
void guest_init_cpu(CPU *c);

/* Where the guest's image was actually mapped. Equal to the PE's ImageBase on
 * every ES3 title we have - none of them set IMAGE_DLLCHARACTERISTICS_
 * DYNAMIC_BASE, so they are all linked to load at 0x00400000 and nothing
 * relocates. cpu.h's GVA() reads g_image_delta, which stays 0 in that case. */
uint32_t guest_image_base(void);

/* SizeOfImage, so a pointer can be tested for being guest code at all. */
uint32_t guest_image_size(void);

/* Widen THIS thread's TEB stack bounds to include [lo, hi). Windows validates
 * an exception handler against those bounds, and lifted code never runs on the
 * stack the TEB describes - so without this no __try in the game, the CRT or
 * Direct3D can catch anything. Every thread that runs lifted code needs it
 * once; for a worker thread that is its first crossing. */
void es3_teb_cover(uint32_t lo, uint32_t hi);
void es3_window_selftest(void);

/* End the process if it ever covers the whole display. A safety net under the
 * windowed forcing, which depends on recognising calls; this depends on
 * nothing. See guest.c. */
void es3_start_screen_watchdog(void);

/* ---- the import boundary ----
 *
 * A PE reaches its libraries through the IAT: `call dword ptr [__imp_X]` reads
 * a function pointer out of a data slot and calls it. There is no loader here
 * to fill those slots with real addresses, so guest_load() writes a sentinel
 * into each one - HLE_ADDR(id) - and dispatch() routes that range to
 * hle_call().
 *
 * The boundary is drawn here rather than in the lifter because this catches
 * every way an import can be reached, not just a direct `call [__imp_X]`: the
 * `jmp [__imp_X]` thunks MSVC emits, a pointer copied out of the IAT and
 * called much later (the CRT does this), and the COM-style vtables D3D and the
 * OKAO libraries hand back. A lifter-side pattern match sees the first and
 * misses the rest. tools/recomp/driver.py has the long version.
 *
 * The range has to be outside the image and outside the heap, so that a
 * sentinel arriving at dispatch() can only have come out of an IAT slot.
 * tools/recomp/driver.py holds the same constant and the selftest checks
 * they agree - if they ever drift, every import call becomes an unresolved
 * dispatch at a plausible-looking address.
 */
#define HLE_BASE        0xE5300000u
#define HLE_STRIDE      4u
#define HLE_ADDR(id)    (HLE_BASE + HLE_STRIDE * (uint32_t)(id))
#define HLE_IS_ADDR(va) ((va) >= HLE_BASE && \
                         (va) < HLE_BASE + HLE_STRIDE * (uint32_t)HLE_COUNT)
#define HLE_ID_OF(va)   ((HleId)(((va) - HLE_BASE) / HLE_STRIDE))

/* Every import in the game gets an HLE_* id. recomp_imports.h is generated
 * from the PE and lists them with the DLL they came from and the number of
 * argument bytes the real function pops - see "the guest side of a call". */
#include "recomp_imports.h"

#define HLE_ENUM(id, name, dll, purge) id,
typedef enum { HLE_IMPORTS(HLE_ENUM) HLE_COUNT } HleId;
#undef HLE_ENUM

/* A library function's body. Reads its arguments off the guest stack and
 * leaves the return value in eax. It does not have to touch esp: hle_call()
 * sets the frame from the generated purge table afterwards, so every handler
 * is written the same way whether the real function was stdcall, cdecl or
 * __thiscall. An import whose purge could not be derived is callable only by a
 * handler that unwinds for itself - which the native forwarder does, because
 * the real callee's own `ret N` did it. */
typedef void (*HleHandler)(CPU *c, HleId id);

/* One slot per import. A game project fills in the ones it needs; the toolkit
 * ships the ones every ES3 title shares. A slot left null aborts naming
 * itself, which is the to-do list. */
extern HleHandler g_hle_handlers[];

void hle_call(CPU *c, HleId id);

/* Give a named import a body. Binding by name and not by HLE_* id is what
 * keeps a handler file title-agnostic: HLE_CreateFileW only exists as an
 * enumerator if *this* game imports CreateFileW, so a file that said
 * `g_hle_handlers[HLE_CreateFileW]` would fail to compile against a game that
 * does not. Binds every entry with that name - MSVC can emit one import in
 * more than one IAT slot - and returns how many, so 0 means the game does not
 * import it, which is not an error: most titles do not import most of them. */
int hle_bind(const char *name, HleHandler fn);

/* The same, qualified by DLL, and what a board handler must use. An import's
 * identity is (DLL, name): the OKAO Vision libraries export by ordinal only,
 * so eOkaoDt and eOkaoGn both import something called "ordinal_2" and they are
 * different functions. hle_bind() on that name would give face detection's
 * body to gender estimation. The DLL comparison is case-insensitive. */
int hle_bind_dll(const char *dll, const char *name, HleHandler fn);

/* Bind every handler the toolkit ships. A game project calls this once, then
 * binds its own on top. */
void hle_register_all(void);
void hle_register_native(void);    /* forward to the real DLL, where one exists */
void hle_register_callbacks(void); /* imports that take a pointer to guest code */
void hle_register_board(void);     /* JVS, card reader, camera, authentication */

/* An address real code can call that lands in the lifted function at
 * `guest_va`. Needed whenever a guest function pointer is handed to a real
 * library - a window procedure, a qsort comparator, an exception filter -
 * because the original bytes are still mapped at `guest_va` and the host would
 * run those instead, straight into an IAT full of sentinels.
 *
 * dispatch() turns a thunk back into its guest VA, so lifted code reading the
 * same slot still lands in lifted code. See src/runtime/hle_callback.c. */
uint32_t es3_callback(uint32_t guest_va);

/* Forward one import to the real function in the host's own copy of the DLL.
 * Returns 0 if the DLL or the export is not there - a cabinet-only DLL, or a
 * redistributable this machine does not have. */
int hle_bind_native(HleId id);

/* Rewrite every IAT slot belonging to one import. guest_load() fills them all
 * with sentinels, which is right for a function and wrong for an import that
 * is DATA - `_fmode`, `_commode`, `_environ` and the rest of the C runtime's
 * exported variables. The game does not call those, it dereferences them, so
 * their slot has to hold the real address in the real DLL. hle_bind_native()
 * tells them apart by asking whether the page GetProcAddress returned is
 * executable, and calls this for the ones that are not. */
void guest_patch_import(HleId id, uint32_t value);

/* Was this import resolved as data rather than a function? */
int hle_is_data(HleId id);

/* Is `va` executable memory outside the guest image - a real function the game
 * got at run time rather than through the IAT? A COM interface is a vtable of
 * these, and so is every GetProcAddress result. */
int es3_is_host_code(uint32_t va);

/* Run real code at `target` on the guest's own frame, through the same
 * marshalling an import uses. */
void hle_call_address(CPU *c, uint32_t target);

/* Do the forwarding call for an import that hle_bind_native() resolved. A
 * handler that only needs to adjust an argument before the real function sees
 * it - swapping a guest callback pointer for a thunk, say - delegates here
 * rather than reimplementing the call. */
void hle_call_native(CPU *c, HleId id);

/* Forward an import that never returns, from the HOST stack rather than the
 * guest's. Thread exit runs teardown that frees the very arena a guest frame
 * sits on - see the note in hle_native.c. */
void hle_call_native_noreturn(CPU *c, HleId id);

/* Remember an IDirect3D9Ex factory so its CreateDevice/CreateDeviceEx slots
 * can be recognised later and forced windowed - see hle_native.c. */
void es3_d3d_note_factory(uint32_t iface);

/* ES3_TRACE_D3D: record the device vtable so its slots can be named. */
void es3_d3d_note_device(uint32_t iface);

/* Name and originating DLL for an id, for diagnostics. */
const char *hle_name(HleId id);
const char *hle_dll(HleId id);

/* Argument bytes the real callee pops, or -1 if it could not be derived. */
int hle_purge(HleId id);

/* What a cabinet-only DLL actually is, or NULL if it is stock Windows. Turns
 * "eOkaoDt.dll ordinal_302 is not implemented" into something worth reading. */
const char *hle_board_note(const char *dll);

/* ---- the guest side of a call ----
 *
 * The lifter translates `call` into `push32(c, return_address); dispatch(...)`,
 * so on entry to a handler esp points at the return address and argument 0 is
 * the slot above it.
 *
 * Unwinding is hle_call()'s job, not the handler's, and it comes from the
 * generated purge table: Win32 is stdcall and the callee pops its arguments,
 * the MSVCR100 imports are cdecl and pop nothing, and a C++ member is
 * __thiscall and pops its stack arguments with `this` in ecx. Getting one of
 * those wrong desynchronises the guest stack and the symptom appears nowhere
 * near the cause - so the counts are derived rather than typed, by pcrecomp's
 * tools/pe/stdcall_argc.py, and an import whose count could not be derived
 * aborts instead of guessing.
 *
 * The exception, and the reason hle_call() assigns esp rather than adding to
 * it: a handler that forwards to the real function does not need the table at
 * all, because the real callee's own `ret N` already unwound the frame.
 */
#define A32(n)   rd32(c->esp + 4u + 4u * (unsigned)(n))
#define APTR(n)  ((void *)(uintptr_t)A32(n))
#define ASTR(n)  ((char *)(uintptr_t)A32(n))
#define AWSTR(n) ((wchar_t *)(uintptr_t)A32(n))
#define AI32(n)  ((int32_t)A32(n))
#define AF32(n)  hle_bits_to_float(A32(n))
#define RET(v)   (c->eax = (uint32_t)(uintptr_t)(v))
#define RET64(v) (c->eax = (uint32_t)((uint64_t)(v)), \
                  c->edx = (uint32_t)((uint64_t)(v) >> 32))

/* `this` for a __thiscall member: MSVC passes it in ecx, not on the stack. */
#define ATHIS    ((void *)(uintptr_t)c->ecx)

/* A float argument arrives as four bytes on the stack like any other slot.
 * A function and not a cast through a pointer: the cast is a strict-aliasing
 * violation that MSVC tolerates and other compilers optimise away. */
static inline float hle_bits_to_float(uint32_t bits)
{
    float f;
    memcpy(&f, &bits, sizeof f);
    return f;
}

/* A function returning float or double returns it in st(0) on 32-bit Windows,
 * not in an XMM register - the caller does `fstp` to take it. */
#define RETF(v)  fpush(c, (double)(v))

/* ---- lifted code ---- */

/* Address -> lifted function, and the import sentinels on the way past.
 * Generated: recomp_funcs_list.h is the X-macro of every VA that lifted. */
void dispatch(CPU *c, uint32_t va);
void dispatch_jmp(CPU *c, uint32_t va);

/* Is `va` a function this build lifted? For a host that wants to check before
 * handing the guest a callback address. */
int dispatch_has(uint32_t va);

/* Build the address-indexed dispatch table. Call once before the guest runs. */
void dispatch_build_index(void);

/* The guest function whose lifted body contains a host address - what a fault
 * in two million lines of generated C needs to be legible. */
uint32_t dispatch_owner(const void *host);

/* ES3_WATCH_VA support - see crash.c. */
int es3_watched(uint32_t va);
unsigned es3_dispatch_count(void);

/* What the address space is being spent on - printed when a C++ throw goes
 * uncaught, because on 32 bits the likeliest thrower is `operator new`. */
void es3_report_memory(void);

/* ES3_TRACE_STACK, read once at startup - see dispatch.c. */
void es3_stack_trace_init(void);

/* ES3_NO_TRAIL, read once at startup - see crash.c. */
void es3_trail_init(void);

/* ES3_TRACE_FROM, read once at startup - see dispatch.c. */
void es3_trace_from_init(void);

/* ES3_DEBUG=1: relaunch as our own debuggee and report every exception the
 * child takes, including the ones no handler inside it can see - a thread that
 * faults on a stack the kernel cannot dispatch on ends the process with no
 * notification at all. Returns 0 in the child; never returns in the parent.
 * See src/runtime/debug.c. */
int es3_debug_self(void);

/* ---- bring-up diagnostics (src/runtime/crash.c) ----
 *
 * A fault in lifted code shows a debugger `L_004A0550` in a two-million-line
 * generated file. These turn it into the guest's own terms: which functions
 * were dispatched, what address was reached for, and whether it was an import
 * sentinel - which is the signature of a callback running unlifted code.
 */
void es3_install_crash_handler(void);

/* Remember a CPU so the crash report can print it. The host's own, normally. */
void es3_watch_cpu(const CPU *c);

/* Print the simulated machine's state. The handler calls it; so can a shim
 * that has noticed something impossible. */
void es3_report_state(const char *why);

/* Called by dispatch() on every guest call, to keep the trail. */
void es3_note_dispatch(uint32_t va);

#ifdef __cplusplus
}
#endif
#endif /* ES3_RT_H */
