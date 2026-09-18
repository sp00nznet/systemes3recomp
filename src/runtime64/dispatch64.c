/*
 * dispatch64.c - turn a guest address into a call.
 *
 * Three things can be on the other side of a guest address:
 *
 *   1. a lifted function          -> call its C body
 *   2. a real function in a DLL   -> forward with the guest's arguments
 *   3. nothing we know about      -> say so loudly, with a trail
 *
 * Telling 1 from 2 is not done with sentinels, as the 32-bit runtime does. The
 * distinguishing property of an import here is simply that it is not a lifted
 * function and not inside the guest image, and testing THAT catches every way
 * an import can be reached: the IAT slot itself, a one-line `jmp [__imp_X]`
 * thunk, a function pointer copied out of the IAT and called an hour later, and
 * the vtables D3D and Wwise hand back full of addresses inside their own DLLs.
 */

#include "es3_rt64.h"
#include "thunk64.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>

int g_trace_enabled = 0;
uint64_t g_dispatch_limit = 0;      /* 0 = unlimited */
uint64_t g_dispatch_count = 0;
int g_swallow_raise = 0;
uint64_t g_watch_serialize = 0;
uint64_t g_watch_reader = 0;
uint64_t g_watch_alloc = 0;   /* --watch-serialize <va> */    /* diagnostic; see the RaiseException note */

/* Bringing a new image up, the trail matters more than the fault: a guest that
 * runs away ends up faulting somewhere unrelated to the mistake, and the last
 * few hundred dispatches before the limit say far more than the address it
 * eventually died on. */
/* ---- per-thread dispatch counters ----
 *
 * A guest thread that was created and entered is not necessarily a guest
 * thread that is DOING anything, and the two look identical from outside: the
 * shim logs "entering" for both, and neither ever returns. Counting dispatches
 * per thread separates them - a worker parked on an event it will never be
 * signalled on has a count that stops moving, and a thread that never got past
 * its first call has a count in single figures.
 */
#define TC_MAX 64
static struct { DWORD tid; volatile long n; uint64_t first; } g_tc[TC_MAX];
static volatile long g_tcn;
static __declspec(thread) int tc_slot = -1;

static void tc_bump(uint64_t pref)
{
    if (tc_slot < 0) {
        long s = InterlockedIncrement(&g_tcn) - 1;
        if (s >= TC_MAX) { tc_slot = TC_MAX - 1; return; }
        g_tc[s].tid = GetCurrentThreadId();
        g_tc[s].first = pref;
        tc_slot = (int)s;
    }
    g_tc[tc_slot].n++;
}

/* ---- a call stack for lifted code ----
 *
 * The dispatch ring records what RAN, in order, which answers "what happened
 * before this" and not "who called this". For a buffer that is allocated in
 * one place and used in another, the second question is the only one that
 * matters, and a ring of allocator churn cannot answer it.
 *
 * Every guest call goes through dispatch(), which calls the lifted body and
 * returns when it returns - so pushing on the way in and popping on the way
 * out gives a genuine call stack, per thread, for code that has no symbols and
 * no frame pointers. Gated on --trace because it costs two writes per call.
 */
#define CS_MAX 256
static __declspec(thread) uint64_t cs_stack[CS_MAX];
static __declspec(thread) int cs_depth;

/* The CPU whose lifted function is running on this thread right now.
 *
 * A fault handler has no other way to reach it: the CPU is a local in
 * dispatch() or in the thread shim, and the faulting frame is generated C with
 * no symbols. With this, the handler can read c->rip - which the lifter now
 * maintains per basic block - and name the guest instruction. */
__declspec(thread) CPU *g_cur_cpu;

int  es3_cs_depth_get(void) { return cs_depth; }
void es3_cs_depth_set(int d) { cs_depth = d; }

void es3_dump_callstack(const char *why)
{
    fprintf(stderr, "[stack] %s (depth %d, innermost first)\n", why, cs_depth);
    int n = cs_depth < 40 ? cs_depth : 40;
    for (int i = 0; i < n; i++) {
        uint64_t va = cs_stack[cs_depth - 1 - i];
        const char *nm = es3_import_name(va);
        fprintf(stderr, "   %#012llx %s\n", (unsigned long long)va, nm ? nm : "");
    }
}

void es3_dump_threads(void)
{
    long n = g_tcn < TC_MAX ? g_tcn : TC_MAX;
    fprintf(stderr, "[threads] %ld guest threads seen\n", n);
    for (long i = 0; i < n; i++)
        fprintf(stderr, "   tid %-6lu first=%#012llx dispatches=%ld\n",
                g_tc[i].tid, (unsigned long long)g_tc[i].first, g_tc[i].n);
}

static void check_limit(void)
{
    if (g_dispatch_limit && ++g_dispatch_count >= g_dispatch_limit) {
        es3_trace_dump("dispatch limit reached");
        fprintf(stderr, "[dispatch] stopped at the %llu-dispatch limit\n",
                (unsigned long long)g_dispatch_limit);
        exit(3);
    }
}

/* ---- the lifted-function index ----
 * Built once, sorted, then binary searched. The table the generator emits is
 * already in address order, but sorting here rather than trusting that keeps
 * the two files independent - and 90,818 entries is a 17-step search either
 * way. */
static const recomp_entry_t *g_sorted;
static uint32_t g_count;

static int cmp_entry(const void *a, const void *b)
{
    uint64_t x = ((const recomp_entry_t *)a)->va;
    uint64_t y = ((const recomp_entry_t *)b)->va;
    return (x > y) - (x < y);
}

static void ensure_index(void)
{
    if (g_sorted) return;
    g_count = recomp_dispatch_count;
    recomp_entry_t *t = (recomp_entry_t *)malloc(g_count * sizeof *t);
    memcpy(t, recomp_dispatch_table, g_count * sizeof *t);
    qsort(t, g_count, sizeof *t, cmp_entry);
    g_sorted = t;
}

static void (*lookup(uint64_t va))(CPU *)
{
    ensure_index();
    uint32_t lo = 0, hi = g_count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        if (g_sorted[mid].va < va) lo = mid + 1;
        else hi = mid;
    }
    if (lo < g_count && g_sorted[lo].va == va) return g_sorted[lo].fn;
    return NULL;
}

/* The lifted table is indexed by the address the image PREFERRED. If the image
 * had to be relocated, a guest pointer computed at runtime is a real address
 * and has to come back to that space before it can be looked up. */
static uint64_t to_preferred(uint64_t real)
{
    return (uint64_t)((int64_t)real - g_image_delta);
}

/* The thread shim is defined below, next to the note explaining it, but the
 * import interception that installs it lives in es3_native_call above it. */
typedef struct { uint64_t guest_fn, param; size_t stack; } thread_start_t;
static DWORD WINAPI es3_thread_shim(void *arg);

/* ---- the guest's command line ----
 *
 * GetCommandLineW returns the HOST process's command line, which is the
 * runtime's: "battlepods.exe SWArcGame-Win64-Shipping.exe --trace-files".
 * The guest then parses that as its own. UE3 reads the command line for the
 * map to load, the game name and every -switch it honours, so handing it the
 * runtime's arguments means it is configured by accident - and a stray token
 * is not diagnosed, it just changes behaviour.
 *
 * So the guest gets a command line of its own: argv[0] as the game would have
 * been launched, plus whatever --game-args supplies.
 */
static wchar_t g_guest_cmdline[2048];
static char    g_guest_cmdline_a[2048];

void es3_set_guest_cmdline(const char *exe, const char *args)
{
    _snwprintf(g_guest_cmdline, 2047, L"\"%hs\"%hs%hs",
               exe, args && *args ? " " : "", args ? args : "");
    g_guest_cmdline[2047] = 0;
    _snprintf(g_guest_cmdline_a, 2047, "\"%s\"%s%s",
              exe, args && *args ? " " : "", args ? args : "");
    g_guest_cmdline_a[2047] = 0;
    fprintf(stderr, "[main] guest command line: %ls\n", g_guest_cmdline);
}

/* ---- file tracing ----
 *
 * UE3 writes its own diagnosis. It logs what it loads, what it cannot find and
 * what it is about to fail on, then calls appError - so the log says in English
 * what a dispatch trail can only hint at. But it writes through WriteFile on a
 * handle, and a handle says nothing, so the paths have to be remembered from
 * the CreateFile that produced them.
 *
 * Off unless --trace-files, because it intercepts every file operation the game
 * performs and a UE3 startup performs a great many.
 */
int g_trace_files = 0;
int g_guest_log = 0;    /* --guest-log: echo OutputDebugString */

/* The private stack a bridged native->guest call runs on, and how much of the
 * caller's frame travels with it: the return address, the 32 bytes of shadow
 * space, and room for stack arguments beyond the fourth. 512 bytes covers
 * anything this game passes to a callback. */
#define BRIDGE_STACK    (1u << 20)
#define BRIDGE_ARGCOPY  512u

#define FT_MAX 8192
static struct { uint64_t h; wchar_t path[260]; int is_text; } g_ft[FT_MAX];
static long g_ftn;

static void ft_record(uint64_t h, const wchar_t *path)
{
    if (h == (uint64_t)(intptr_t)INVALID_HANDLE_VALUE || !path) return;
    long i = InterlockedIncrement(&g_ftn) - 1;
    if (i >= FT_MAX) {
        /* Silently forgetting handles makes the trace lie by omission - the
         * reads on a package simply stop appearing, which reads as "it never
         * read it". Say so once. */
        if (i == FT_MAX)
            fprintf(stderr, "[file] handle table full at %d; later opens are "
                            "not tracked\n", FT_MAX);
        return;
    }
    g_ft[i].h = h;
    wcsncpy(g_ft[i].path, path, 259);
    const wchar_t *dot = wcsrchr(path, L'.');
    g_ft[i].is_text = dot && (!_wcsicmp(dot, L".log") || !_wcsicmp(dot, L".txt"));
}

/* Searched BACKWARDS, newest first, and that is not a detail.
 *
 * Windows recycles handle VALUES: close a file and the next open can hand back
 * the same number for something else. Scanning forwards returns the oldest
 * file that ever held the handle, so a read gets attributed to a package that
 * was closed long ago. That produced a very convincing false result here - a
 * read on "Core.upk" whose first bytes were FF FE 5B 00, a UTF-16 BOM and a
 * '[', which is an INI file. The package was innocent; the tracer was wrong.
 */
static long ft_find(uint64_t h)
{
    long n = g_ftn < FT_MAX ? g_ftn : FT_MAX;
    for (long i = n - 1; i >= 0; i--)
        if (g_ft[i].h == h) return i;
    return -1;
}

static int ft_is_pkg(uint64_t h, const wchar_t **path)
{
    long i = ft_find(h);
    if (i < 0) return 0;
    if (path) *path = g_ft[i].path;
    const wchar_t *d = wcsrchr(g_ft[i].path, L'.');
    return d && !_wcsicmp(d, L".upk");
}

static int ft_is_text(uint64_t h, const wchar_t **path)
{
    long i = ft_find(h);
    if (i < 0) return 0;
    if (path) *path = g_ft[i].path;
    return g_ft[i].is_text;
}

/* ---- watching the buffer a package is actually read from ----
 *
 * UE3 does not read a cooked package through ReadFile at the point the summary
 * is parsed - it reads it out of memory. The archive underneath is an
 * FBufferReader:
 *
 *     memmove(V, (BYTE*)this->Data + this->Pos, Length);  Pos += Length;
 *
 * with Data at [this+0x88] and Pos at [this+0x90]. So when the engine says the
 * package tag is wrong, the question is not what the FILE contains - that has
 * been verified byte for byte - but what that buffer contains and where Pos is
 * pointing. Printing both, once, at the read the tag check is about to reject,
 * is the whole diagnosis.
 *
 * Armed by the summary parser so this fires on the one read that matters; the
 * reader itself runs constantly.
 */
__declspec(thread) int g_watch_armed;

/* ---- --log-call: report a named guest function whenever it runs ----
 *
 * The dispatch ring answers "what ran just before this", but not "did THIS
 * ever run", because the ring is a window and the answer is often outside it.
 * Absence from the ring is not absence from the program, and reading it that
 * way turns a missing window into a false conclusion. */
uint64_t g_log_calls[8];
int g_n_log_calls;

/* --log-callees-of: every function a named function calls, resolved.
 *
 * A virtual call has no target in the disassembly - `call [rax+0x28]` says
 * which SLOT, not which function - so the only way to learn what an engine
 * subsystem actually dispatches to is to watch it happen. With the shadow call
 * stack in place the parent frame is known, so this is a one-line filter. */
uint64_t g_callees_of;

void es3_log_callee(uint64_t pref)
{
    if (!g_callees_of || cs_depth < 2) return;
    if (cs_stack[cs_depth - 2] != g_callees_of) return;
    const char *nm = es3_import_name(pref);
    fprintf(stderr, "[callee] %#012llx <- called by %#012llx %s\n",
            (unsigned long long)pref, (unsigned long long)g_callees_of,
            nm ? nm : "");
}

void es3_log_call(CPU *c, uint64_t pref)
{
    for (int i = 0; i < g_n_log_calls; i++)
        if (g_log_calls[i] == pref) {
            /* The return address is sitting at the top of the guest stack -
             * the lifted caller pushed it before dispatching - so the exact
             * instruction that made this call is one read away. That is worth
             * far more than the trail: the trail says which functions ran, and
             * this says which LINE to go and disassemble. */
            fprintf(stderr, "[call] %#llx rcx=%#llx rdx=%#llx r8=%#llx "
                            "<- returns to %#llx\n",
                    (unsigned long long)pref, (unsigned long long)c->rcx,
                    (unsigned long long)c->rdx, (unsigned long long)c->r8,
                    (unsigned long long)rd64(c->rsp));
            /* The first few fields of *this. A function that returns
             * immediately does so because of one of them, and printing the
             * object is the difference between knowing THAT it exited early
             * and knowing WHY. */
            if (c->rcx) {
                __try {
                    fprintf(stderr, "       this[0x70]=%08X [0x74]=%08X "
                                    "[0x78]=%08X [0x7c]=%08X\n",
                            rd32(c->rcx + 0x70), rd32(c->rcx + 0x74),
                            rd32(c->rcx + 0x78), rd32(c->rcx + 0x7c));
                } __except (EXCEPTION_EXECUTE_HANDLER) { }
            }
            /* RCX as a wide string when it plausibly is one. UE3 passes
             * package and object names as TCHAR*, and a logged pointer says
             * nothing while the name it points at usually says everything. */
            if (c->rcx > 0x10000) {
                __try {
                    const wchar_t *w = (const wchar_t *)(uintptr_t)c->rcx;
                    int ok = 1, n = 0;
                    for (; n < 80 && w[n]; n++)
                        if (w[n] < 32 || w[n] > 0x7E) { ok = 0; break; }
                    if (ok && n >= 2)
                        fprintf(stderr, "       rcx -> L\"%.80ls\"\n", w);
                } __except (EXCEPTION_EXECUTE_HANDLER) { }
            }
            if (g_trace_enabled) es3_trace_tail(24);
            return;
        }
}

void es3_watch_reader(CPU *c, uint64_t pref)
{
    if (!g_watch_armed || !g_watch_reader || pref != g_watch_reader) return;
    g_watch_armed = 0;
    uint64_t self = c->rcx;
    uint64_t dataptr = rd64(self + 0x88);
    uint32_t pos = rd32(self + 0x90);
    /* The vtable identifies the class, and the class is what says which
     * constructor stored that Data pointer - the one piece of information a
     * memory dump of the buffer cannot give. */
    uint64_t vt = rd64(self);
    fprintf(stderr, "[bufreader] this=%#llx vtable=%#llx (image+%#llx) "
                    "Data=%#llx Pos=%u len=%llu\n",
            (unsigned long long)self, (unsigned long long)vt,
            (unsigned long long)(vt - (uint64_t)(uintptr_t)g_image.base),
            (unsigned long long)dataptr, pos, (unsigned long long)c->r8);
    fprintf(stderr, "[bufreader] Data is %s this\n",
            dataptr > self ? "ABOVE" : "BELOW");
    if (dataptr) {
        fprintf(stderr, "[bufreader] Data[0..15] :");
        for (int i = 0; i < 16; i++) fprintf(stderr, " %02X", rd8(dataptr + i));
        fprintf(stderr, "\n[bufreader] Data[Pos..] :");
        for (int i = 0; i < 16; i++) fprintf(stderr, " %02X", rd8(dataptr + pos + i));
        fprintf(stderr, "\n");
    }
}

/* ---- the native side ---- */

int es3_native_call(CPU *c, uint64_t target)
{
    HLEFRAME f;
    memset(&f, 0, sizeof f);

    /* At this point the lifted caller has pushed a return address, so c->rsp
     * points at it and c->rsp+8 is the shadow space - exactly the frame a
     * Win64 callee expects to see. The callee's own RET is what would have
     * removed the return address, and there is no lifted callee here to do it,
     * so this does it instead. Getting that wrong leaves the guest stack eight
     * bytes out with nothing to show for it. */
    uint64_t gsp = c->rsp;
    c->rsp = gsp + 8;

    if (g_log_imports) es3_note_import(target);

    /* ---- RaiseException(0x406D1388): the thread-name notification ----
     *
     * This is not a failure, it is a message to a debugger, and the standard
     * idiom that sends it wraps the call in the caller's own __try/__except:
     *
     *     __try { RaiseException(0x406D1388, 0, 4, &info); }
     *     __except (EXCEPTION_EXECUTE_HANDLER) { }
     *
     * Lifted code has no structured exception handling, so with the exception
     * actually raised there is nothing to catch it and it kills the process.
     * Swallowing it in a vectored handler does not work either: continuing
     * execution resumes inside RtlRaiseException and raises again.
     *
     * Not raising it in the first place is what the guest's own __except would
     * have amounted to, and it is a decision that belongs at the import
     * boundary rather than in an exception filter. Every other exception code
     * is forwarded untouched - a guest that really does raise something is
     * still a guest whose behaviour we want.
     */
    if (target == g_addr_GetCommandLineW) {
        c->rax = (uint64_t)(uintptr_t)g_guest_cmdline;
        return 1;
    }
    if (target == g_addr_GetCommandLineA) {
        c->rax = (uint64_t)(uintptr_t)g_guest_cmdline_a;
        return 1;
    }

    /* ---- the guest's C++ throw ----
     *
     * Caught HERE, at the call, and not in a vectored handler: at this point
     * the guest stack is intact and the host stack is an ordinary one, so the
     * longjmp that lands in the catching frame does not have to unwind out of
     * the middle of Windows' exception dispatch.
     *
     * void _CxxThrowException(void *object, _ThrowInfo *ti) - rcx, rdx.
     * es3_eh_throw returns only when no guest frame catches, and then the call
     * is forwarded and dies the way it used to. */
    if (target == g_addr_CxxThrowException)
        es3_eh_throw(c, rd64(gsp), c->rcx, c->rdx);

    /* ---- the Sentinel dongle ----
     *
     * System ES3 carries a USB HASP key, and its absence is the "19-21 USB
     * DONGLE ERROR 1" the game draws over the attract screen. The library is
     * present in the dump and loads; it is the KEY that is not here, so every
     * call returns HASP_HASP_NOT_FOUND and the game stops at the error.
     *
     * Answering HASP_STATUS_OK is the same kind of substitution as the rest of
     * this file: the machine this is running on does not have the hardware, so
     * the runtime is the hardware. hasp_read returns zeroes and hasp_decrypt
     * leaves the buffer alone, which is enough if the game only checks status
     * - and if it does not, the next screen will say so. */
    if (g_addr_hasp_login && target == g_addr_hasp_login) {
        if (c->r8) wr32(c->r8, 1);         /* a handle it can pass back */
        c->rax = 0;
        return 1;
    }
    if (g_addr_hasp_logout && target == g_addr_hasp_logout) {
        c->rax = 0;
        return 1;
    }
    if (g_addr_hasp_read && target == g_addr_hasp_read) {
        /* (handle, fileid, offset, length, buffer) - the fifth argument is on
         * the stack, above the shadow space.
         *
         * The block at file 0xfff0 offset 0xd00 is the licence record, and the
         * caller checks exactly two things in it: that the last two bytes are
         * a complement pair, and that the first five are the title id. It has
         * that id in its own frame, assembled just before the call - four
         * ASCII digits at +0x34 and a fifth at +0x38 - so the answer does not
         * have to be guessed or hard-coded per title. c->rsp is that frame
         * base here, the return address having already been consumed.
         *
         * This is the same substitution as everything else in this file: the
         * machine has hardware a PC does not, so the runtime is the hardware.
         * hasp_decrypt below is a no-op, so what is written here is what the
         * caller compares. */
        uint64_t buf = rd64(c->rsp + 0x20);
        uint64_t len = c->r9;
        if (buf && len && len < (1u << 20)) {
            memset((void *)(uintptr_t)buf, 0, (size_t)len);
            if (len >= 0x40) {
                for (int q = 0; q < 5; q++)
                    wr8(buf + q, rd8(c->rsp + 0x34 + q));
                wr8(buf + 0x3e, 0x5a);
                wr8(buf + 0x3f, (uint8_t)~0x5a);
                fprintf(stderr, "[hasp] licence record: id \"%.5s\"\n",
                        (const char *)(uintptr_t)buf);
            }
        }
        c->rax = 0;
        return 1;
    }
    if (g_addr_hasp_decrypt && target == g_addr_hasp_decrypt) {
        c->rax = 0;
        return 1;
    }

    if (target == g_addr_RaiseException) {
        if ((uint32_t)c->rcx == 0x406D1388u) {
            c->rax = 0;
            return 1;
        }
        /* Anything else is forwarded, but named first. Lifted code has no
         * structured exception handling, so a raise the guest expected to
         * catch itself will escape and look like a crash in ntdll - which is
         * a long way from the guest code that asked for it. */
        fprintf(stderr, "[raise] guest RaiseException(code=%#x, flags=%#x, "
                        "nargs=%u) from thread %lu\n",
                (unsigned)c->rcx, (unsigned)c->rdx, (unsigned)c->r8,
                GetCurrentThreadId());
        /* Dump the trail HERE, at the first one, not when the process finally
         * dies. By then the ring holds nothing but the main thread's spin loop
         * waiting on the worker this raise just killed - four thousand entries
         * of QueryPerformanceCounter and not one of the code that failed. */
        {
            static long once = 0;
            if (InterlockedExchange(&once, 1) == 0)
                es3_trace_dump("first guest RaiseException");
        }
        /* A DIAGNOSTIC, not a fix, and off unless asked for. Dropping the
         * raise pretends the guest's own __except caught it, which is true for
         * an idiom like the thread-name notification and false for a genuine
         * error - and there is no way to tell which from here. It exists to
         * answer one question while bringing the image up: is missing SEH the
         * only thing in the way, or the first of several? */
        if (g_swallow_raise) {
            c->rax = 0;
            return 1;
        }
    }

    /* ---- DirectInput8Create: the guest's HINSTANCE is not a real module ----
     *
     * DirectInput8Create(hinst, version, riid, out, outer) validates hinst
     * against the modules Windows has actually loaded. The guest's idea of its
     * own instance handle is the base of the image THIS RUNTIME mapped by hand,
     * 0x140000000, which the loader has never heard of - so the call fails, and
     * the game does not check the HRESULT. It dereferences the interface
     * pointer immediately:
     *
     *     call DirectInput8Create        ; leaves the out-parameter NULL
     *     mov  rcx, [rip+...]            ; reload it
     *     mov  rax, [rcx]                ; read from address 0
     *
     * Substituting the runtime's own module handle is honest here: it is a real
     * HINSTANCE of a real loaded module in this process, which is all the API
     * wants it for. The alternative - leaving the guest to fail - is not
     * emulating the machine, it is emulating a machine with no DirectInput.
     */
    if (target == g_addr_DirectInput8Create) {
        uint64_t guest_hinst = c->rcx;
        c->rcx = (uint64_t)(uintptr_t)GetModuleHandleW(NULL);
        if (g_trace_files)
            fprintf(stderr, "[dinput] DirectInput8Create hinst %#llx -> %#llx "
                            "(version %#x)\n",
                    (unsigned long long)guest_hinst,
                    (unsigned long long)c->rcx, (unsigned)c->rdx);
    }

    /* ---- CreateThread: substitute a native start routine ----
     *
     * Win64 argument order: rcx=attributes, rdx=stack size, r8=start address,
     * r9=parameter, [rsp+0x28]=flags, [rsp+0x30]=out thread id. Only r8 and r9
     * are replaced; everything else is forwarded untouched, so the guest's
     * stack size, CREATE_SUSPENDED and returned thread id all still work.
     */
    if (target == g_addr_CreateThread && c->r8) {
        thread_start_t *ts = (thread_start_t *)malloc(sizeof *ts);
        ts->guest_fn = c->r8;
        ts->param    = c->r9;
        ts->stack    = (size_t)c->rdx;
        c->r8 = (uint64_t)(uintptr_t)es3_thread_shim;
        c->r9 = (uint64_t)(uintptr_t)ts;
        if (g_trace_files)
            fprintf(stderr, "[thread] CreateThread guest_fn=%#llx param=%#llx "
                            "stack=%llu\n",
                    (unsigned long long)ts->guest_fn,
                    (unsigned long long)ts->param,
                    (unsigned long long)ts->stack);
        /* falls through and forwards, now with a start routine that exists */
    }

    /* ---- _initterm / _initterm_e: the static-initialiser tables ----
     *
     * `_initterm_e(first, last)` walks an array of function pointers and calls
     * each one. Every pointer in it is a GUEST address, so letting the real
     * MSVCR100 do the walking means the CRT calls guest code directly - which
     * is where this build faulted, eleven dispatches in, on pre_c_init.
     *
     * Doing the walk here instead is not an approximation of the CRT; this IS
     * what those two functions do, in full. The only difference is that each
     * entry goes through the dispatcher.
     *
     * The _e form stops at the first entry returning non-zero and yields that
     * value; the plain form ignores return values. Getting that backwards
     * would run initialisers after one had already failed.
     */
    if ((target == g_addr_initterm || target == g_addr_initterm_e) &&
        c->rcx && c->rdx) {
        int wants_result = (target == g_addr_initterm_e);
        uint64_t p = c->rcx, end = c->rdx;
        uint64_t saved_rcx = c->rcx, saved_rdx = c->rdx;
        uint32_t rc = 0;
        for (; p < end; p += 8) {
            uint64_t fnp = rd64(p);
            if (!fnp) continue;            /* the table is sparse */
            es3_call_guest(c, fnp);
            if (wants_result && (uint32_t)c->rax) { rc = (uint32_t)c->rax; break; }
        }
        c->rcx = saved_rcx; c->rdx = saved_rdx;
        c->rax = rc;
        return 1;
    }

    f.fn  = (void *)target;
    f.rcx = c->rcx;
    f.rdx = c->rdx;
    f.r8  = c->r8;
    f.r9  = c->r9;
    memcpy(&f.x0, &c->xmm[0], 16);
    memcpy(&f.x1, &c->xmm[1], 16);
    memcpy(&f.x2, &c->xmm[2], 16);
    memcpy(&f.x3, &c->xmm[3], 16);

    /* Stack arguments begin above the shadow space. How many there are is not
     * knowable from here - the IAT says nothing about arity - so a fixed window
     * is copied. It is only ever read by the callee up to its real argument
     * count, and the source is the guest's own stack, so copying too much is
     * harmless where copying too little would pass garbage. */
    f.stack  = c->rsp + 32;
    f.nstack = HLE_STACK_ARGS;

    /* WriteFile to a text file: echo it. This is how UE3's own log reaches the
     * console, and its last lines before appError are the actual diagnosis.
     * Done BEFORE the call, because the buffer is the guest's and the call may
     * be what fails. */
    if (g_trace_files && target == g_addr_WriteFile) {
        const wchar_t *p = NULL;
        if (ft_is_text(c->rcx, &p) && c->rdx && c->r8 && c->r8 < (1u << 20)) {
            fprintf(stderr, "[guest-log] %.*s",
                    (int)c->r8, (const char *)(uintptr_t)c->rdx);
        }
    }

    hle_invoke(&f);

    /* ReadFile on a package: log where it read and what came back.
     *
     * This is the question that separates a recompiler bug from a data or
     * configuration problem, and nothing else answers it. If the bytes the
     * kernel returns are the right ones and the guest still rejects them, the
     * corruption happened in lifted code; if the offset is wrong, it is the
     * seek. Either way it is one line of evidence instead of a theory. */
    if (g_trace_files && target == g_addr_ReadFile) {
        const wchar_t *p = NULL;
        /* Any read that comes back holding a UE3 package tag, whatever handle
         * it arrived on. If the summary is being read at all, this sees it -
         * including on a handle opened by a thread whose CreateFile we missed,
         * which is the case a handle-keyed filter cannot cover. */
        const unsigned char *b = (const unsigned char *)(uintptr_t)f.rdx;
        /* A read that FAILED, or returned short. UE3 reads a package summary
         * into a zeroed struct and then checks the tag, so a read that quietly
         * returns nothing presents exactly as "the file contains
         * unrecognizable data" - the symptom names the file, never the read.
         * FILE_FLAG_NO_BUFFERING is the usual cause: it requires
         * sector-aligned offsets, sizes and buffers, and fails the read
         * outright when they are not. */
        DWORD got = (f.r9 && !IsBadReadPtr((void *)(uintptr_t)f.r9, 4))
                    ? *(DWORD *)(uintptr_t)f.r9 : 0xFFFFFFFFu;
        if (!f.rax_out || (f.r8 && got == 0)) {
            long idx = ft_find(f.rcx);
            fprintf(stderr, "[read-fail] h=%#llx %ls want=%lu got=%lu ok=%llu err=%lu\n",
                    (unsigned long long)f.rcx,
                    idx >= 0 ? g_ft[idx].path : L"(untracked handle)",
                    (unsigned long)f.r8, (unsigned long)got,
                    (unsigned long long)f.rax_out, GetLastError());
        }
        /* Everything that is not config or shader noise, INCLUDING reads on a
         * handle we never saw opened. A path-keyed filter silently drops those,
         * and "no reads happened" is a conclusion worth being sure of before
         * building a theory on it. */
        {
            long ix = ft_find(f.rcx);
            const wchar_t *pp = ix >= 0 ? g_ft[ix].path : NULL;
            const wchar_t *ext = pp ? wcsrchr(pp, L'.') : NULL;
            int noisy = ext && (!_wcsicmp(ext, L".ini") || !_wcsicmp(ext, L".bin") ||
                                !_wcsicmp(ext, L".INT"));
            if (!noisy)
                fprintf(stderr, "[rd] h=%#llx %ls want=%lu first=%02X %02X %02X %02X\n",
                        (unsigned long long)f.rcx, pp ? pp : L"(untracked)",
                        (unsigned long)f.r8, b[0], b[1], b[2], b[3]);
        }
        if (b && f.r8 >= 4 &&
            b[0] == 0xC1 && b[1] == 0x83 && b[2] == 0x2A && b[3] == 0x9E) {
            long idx = ft_find(f.rcx);
            fprintf(stderr, "[pkg] summary read on h=%#llx %ls (%lu bytes)\n",
                    (unsigned long long)f.rcx,
                    idx >= 0 ? g_ft[idx].path : L"(untracked handle)",
                    (unsigned long)f.r8);
        }
        if (ft_is_pkg(f.rcx, &p)) {
            LARGE_INTEGER pos = {0}, zero = {0};
            SetFilePointerEx((HANDLE)(uintptr_t)f.rcx, zero, &pos, FILE_CURRENT);
            const unsigned char *b = (const unsigned char *)(uintptr_t)f.rdx;
            fprintf(stderr, "[read] %ls want=%lu -> pos now %lld, first bytes"
                            " %02X %02X %02X %02X\n",
                    p, (unsigned long)f.r8, (long long)pos.QuadPart,
                    b[0], b[1], b[2], b[3]);
        }
    }

    /* ---- --watch-alloc: catch the allocation of a known size ----
     *
     * The package buffer is allocated by a producer that then fails to fill
     * it, and nothing in the consumer says who that producer was. But the size
     * is known exactly - it is the file's - so the allocation itself is a
     * reliable place to stand. Watching for it names the producer and shows
     * what it does next, which is where the missing read should be. */
    if (g_watch_alloc && target == g_addr_scalable_malloc &&
        f.rcx == g_watch_alloc) {
        fprintf(stderr, "[alloc] %llu bytes -> %#llx, returns to %#llx\n",
                (unsigned long long)f.rcx, (unsigned long long)f.rax_out,
                (unsigned long long)rd64(gsp));
        if (g_trace_enabled) es3_dump_callstack("package buffer allocation");
    }

    /* GetFileSize on a package.
     *
     * UE3 builds its file reader from the size, precaches against it and then
     * serialises the summary out of that buffer. A size of zero means it never
     * issues a read at all, leaves the summary zeroed, and reports the TAG as
     * wrong - which is the BinaryFormat error, naming the file and saying
     * nothing about the size. So the size is worth seeing even when it looks
     * uninteresting. */
    if (g_trace_files &&
        (target == g_addr_GetFileSize || target == g_addr_GetFileSizeEx)) {
        const wchar_t *p = NULL;
        if (ft_is_pkg(f.rcx, &p)) {
            if (target == g_addr_GetFileSizeEx) {
                LARGE_INTEGER *out = (LARGE_INTEGER *)(uintptr_t)f.rdx;
                fprintf(stderr, "[size] %ls GetFileSizeEx ok=%llu -> %lld\n",
                        p, (unsigned long long)f.rax_out,
                        out ? (long long)out->QuadPart : -1);
            } else {
                fprintf(stderr, "[size] %ls GetFileSize -> %llu\n",
                        p, (unsigned long long)f.rax_out);
            }
            /* The trail at the PRODUCER. Sizing a package is the step just
             * before its buffer is allocated and its read enqueued, so this is
             * where a missing read has to be visible - by the time the consumer
             * wraps the buffer the decision has already been made. */
            if (g_trace_enabled) es3_trace_tail(20);
        }
    }

    /* Direct3DCreate9: whether this machine can render at all.
     *
     * Always reported, not only under --trace-files. A NULL here is not a bug
     * in the recompilation - it is the host saying there is no display device,
     * which a remote session legitimately is - and every null dereference that
     * follows is a consequence rather than a separate fault to chase. Worth one
     * unconditional line to stop that being rediscovered.
     */
    if (target == g_addr_Direct3DCreate9) {
        fprintf(stderr, "[d3d9] Direct3DCreate9(%#x) -> %#llx%s\n",
                (unsigned)f.rcx, (unsigned long long)f.rax_out,
                f.rax_out ? "" : "   NULL - no D3D9 on this session");
        es3_d3d9_watch((void *)(uintptr_t)f.rax_out);
    }

    /* OpenFileMappingW, with no CreateFileMapping anywhere in the run: the game
     * expects something ELSE to have made this. On a cabinet that something is
     * the I/O service, and the name it asks for is the name to answer to. */
    if (g_addr_OpenFileMappingW && target == g_addr_OpenFileMappingW) {
        const wchar_t *nm = (const wchar_t *)(uintptr_t)f.r8;
        fprintf(stderr, "[io] OpenFileMappingW \"%ls\" -> %#llx%s\n",
                nm ? nm : L"(null)", (unsigned long long)f.rax_out,
                f.rax_out ? "" : "   NOT PRESENT");
    }
    if (g_addr_LoadLibraryW && target == g_addr_LoadLibraryW)
        fprintf(stderr, "[io] LoadLibraryW \"%ls\" -> %#llx\n",
                (const wchar_t *)(uintptr_t)f.rcx,
                (unsigned long long)f.rax_out);
    if (g_addr_LoadLibraryA && target == g_addr_LoadLibraryA)
        fprintf(stderr, "[io] LoadLibraryA \"%s\" -> %#llx\n",
                (const char *)(uintptr_t)f.rcx,
                (unsigned long long)f.rax_out);

    /* ---- the I/O board hunt ----
     *
     * 03-01 I/O PCB ERROR is raised without the game ever opening a port, so
     * whatever it is looking for it does not find during enumeration. These
     * name it: the device class it asks Windows for, the interface GUID it
     * matches against, and the device instance id it tries to locate directly.
     * Reported rather than answered, because answering the wrong device is
     * worse than answering none - see the note in the 32-bit jvs.c about the
     * card reader. */
    if (g_addr_SetupDiGetClassDevsW && target == g_addr_SetupDiGetClassDevsW) {
        const unsigned char *g = (const unsigned char *)(uintptr_t)f.rcx;
        const wchar_t *en = (const wchar_t *)(uintptr_t)f.rdx;
        if (g)
            fprintf(stderr, "[io] SetupDiGetClassDevsW class "
                    "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}"
                    " enum=%ls flags=%#lx -> %#llx\n",
                    *(const unsigned long *)g, *(const unsigned short *)(g + 4),
                    *(const unsigned short *)(g + 6),
                    g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15],
                    en ? en : L"(any)", (unsigned long)f.r9,
                    (unsigned long long)f.rax_out);
        else
            fprintf(stderr, "[io] SetupDiGetClassDevsW class=(null) enum=%ls "
                    "flags=%#lx -> %#llx\n", en ? en : L"(any)",
                    (unsigned long)f.r9, (unsigned long long)f.rax_out);
    }
    if (g_addr_CM_Locate_DevNodeW && target == g_addr_CM_Locate_DevNodeW) {
        const wchar_t *id = (const wchar_t *)(uintptr_t)f.rdx;
        fprintf(stderr, "[io] CM_Locate_DevNodeW \"%ls\" -> %lu%s\n",
                id ? id : L"(root)", (unsigned long)f.rax_out,
                f.rax_out ? "  NOT FOUND" : "");
    }
    if (g_addr_SetupDiEnumDeviceInterfaces &&
        target == g_addr_SetupDiEnumDeviceInterfaces) {
        const unsigned char *g = (const unsigned char *)(uintptr_t)f.r8;
        if (g)
            fprintf(stderr, "[io] SetupDiEnumDeviceInterfaces #%lu iface "
                    "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X} -> %s\n",
                    (unsigned long)f.r9,
                    *(const unsigned long *)g, *(const unsigned short *)(g + 4),
                    *(const unsigned short *)(g + 6),
                    g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15],
                    f.rax_out ? "TRUE" : "FALSE");
    }

    /* CreateFile* returns the handle the later WriteFile will name. */
    if (g_trace_files &&
        (target == g_addr_CreateFileW || target == g_addr_CreateFileA)) {
        wchar_t wbuf[260];
        const wchar_t *path;
        if (target == g_addr_CreateFileA) {
            MultiByteToWideChar(CP_ACP, 0, (const char *)(uintptr_t)f.rcx, -1,
                                wbuf, 260);
            path = wbuf;
        } else {
            path = (const wchar_t *)(uintptr_t)f.rcx;
        }
        int ok = f.rax_out != (uint64_t)(intptr_t)INVALID_HANDLE_VALUE;
        fprintf(stderr, "[file] %s %ls\n", ok ? "open " : "FAIL ", path);
        if (ok) ft_record(f.rax_out, path);
    }

    /* Win64 returns integers in RAX and floats in XMM0. Which one the callee
     * used is not knowable here either, so both are taken; the guest reads the
     * one its own prototype says, and the other is a register it was entitled
     * to treat as volatile anyway. */
    c->rax = f.rax_out;
    memcpy(&c->xmm[0], &f.xmm0_out, 16);

    /* RCX, RDX, R8-R11 and XMM0-5 are volatile across a Win64 call, so their
     * contents afterwards are undefined and the guest cannot read them. Left
     * alone deliberately: scrambling them would be more faithful but would make
     * every trace harder to read for no behavioural difference. */
    return 1;
}

/* ---- calling INTO lifted code ----
 *
 * The other direction, and the one a recompiled build cannot do without. A
 * guest function pointer handed to a real DLL is a guest address, and the DLL
 * will call it: _initterm_e walks the C++ static-initialiser table, qsort calls
 * a comparator, CreateThread calls a thread procedure, user32 calls a window
 * procedure. The address it calls has no executable code at it - guest memory
 * is mapped non-executable precisely so that this is caught rather than
 * silently running the original machine code.
 *
 * So the runtime intercepts the import and re-enters through the dispatcher,
 * which is the only path to the lifted body.
 */
void es3_call_guest(CPU *c, uint64_t target)
{
    /* The callee's RET pops a return address, so there has to be one. The
     * value is never used - the lifted function returns to us by returning
     * from its C body - but the stack accounting has to match or every
     * subsequent frame is eight bytes out. */
    c->rsp -= 8;
    wr64(c->rsp, 0xE5E3CA11E5E3CA11ULL);
    dispatch(c, target);
}

/* ---- threads ----
 *
 * CreateThread is handed a GUEST address as its start routine, and the real
 * kernel32 will call it on a brand new thread. Everything about that is wrong
 * for a recompiled build: there is no executable code at the address, and even
 * if there were, the new thread has no CPU state.
 *
 * So the start routine is replaced with a native shim and the guest's own
 * routine travels alongside it. Each thread gets its OWN CPU - which is the
 * whole reason the lifter emits `void L_x(CPU *c)` and not a global register
 * file. A global one would have made this the point where the project stopped.
 */
/* ---- the general callback bridge ----
 *
 * Intercepting imports one at a time does not scale: _initterm_e, CreateThread,
 * then a TLS callback, a window procedure, a qsort comparator, a Wwise or D3D
 * callback. Each is the same problem - a native caller reaching a guest address
 * - and each would need its own shim, forever, with a crash for every one not
 * yet written.
 *
 * The DEP fault already carries everything needed to bridge it generically.
 * When native code CALLs a guest address the call itself completes: the return
 * address is pushed, and the fault happens fetching the first instruction. So
 * when the handler runs,
 *
 *     ctx->Rip  is the guest function
 *     ctx->Rsp  points at the return address the call pushed
 *     Rcx/Rdx/R8/R9 and Xmm0-3 hold the arguments, in the same ABI the guest
 *               itself uses
 *
 * which is exactly a guest call frame. Seed a CPU from the context, dispatch to
 * the lifted body, and put the results back: RIP to the return address, RSP to
 * where the callee's RET left it, RAX and XMM0 to the return value. The thread
 * continues as though the call had simply worked.
 *
 * This is what makes the non-executable mapping a design rather than a
 * diagnostic: every guest address a DLL can call becomes callable, and no
 * original machine code ever runs.
 */
int es3_bridge_callback(EXCEPTION_POINTERS *ep)
{
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_ACCESS_VIOLATION)
        return 0;
    if (ep->ExceptionRecord->ExceptionInformation[0] != 8)   /* not execute */
        return 0;

    uint64_t fn = (uint64_t)ep->ExceptionRecord->ExceptionInformation[1];
    if (!g_image.base || fn < g_image.text_lo || fn >= g_image.text_hi)
        return 0;
    if (!lookup(to_preferred(fn)))          /* not a function we can enter */
        return 0;

    CONTEXT *ctx = ep->ContextRecord;
    CPU c;
    memset(&c, 0, sizeof c);
    c.rax = ctx->Rax; c.rcx = ctx->Rcx; c.rdx = ctx->Rdx; c.rbx = ctx->Rbx;
    c.rbp = ctx->Rbp; c.rsi = ctx->Rsi; c.rdi = ctx->Rdi;
    c.r8  = ctx->R8;  c.r9  = ctx->R9;  c.r10 = ctx->R10; c.r11 = ctx->R11;
    c.r12 = ctx->R12; c.r13 = ctx->R13; c.r14 = ctx->R14; c.r15 = ctx->R15;
    memcpy(c.xmm, &ctx->Xmm0, sizeof c.xmm);

    uint64_t retaddr = rd64(ctx->Rsp);

    /* ---- the bridged call runs on its own stack ----
     *
     * NOT on ctx->Rsp, which is the obvious thing and is wrong. By the time a
     * vectored handler runs, the kernel has already pushed the EXCEPTION_RECORD
     * and the CONTEXT below the faulting RSP, and this function's own frames sit
     * below those. Running the lifted callee from ctx->Rsp makes it push
     * downwards over all of it - over the CONTEXT it is about to return
     * through, and over the locals of the handler doing the returning.
     *
     * It does not crash. It quietly corrupts, and the damage surfaces as the
     * callee reading plausible-looking rubbish: this presented as UE3 rejecting
     * Core.upk because its package tag read back as 23 00 69 00 - UTF-16 for
     * "#i", text from somewhere else entirely on that stack.
     *
     * So: a private stack per thread, with the top of the caller's frame copied
     * across so the callee still finds its return address, its shadow space and
     * any stack arguments at the offsets it expects.
     */
    static __declspec(thread) uint8_t *tls_stack;
    if (!tls_stack) {
        tls_stack = (uint8_t *)VirtualAlloc(NULL, BRIDGE_STACK,
                                            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (!tls_stack) return 0;           /* let it fault honestly instead */
    }
    uint8_t *top = tls_stack + BRIDGE_STACK - BRIDGE_ARGCOPY;
    /* Keep the 16-byte phase of the original RSP: the ABI requires RSP+8 to be
     * 16-aligned at entry, and the callee's own SSE spills depend on it. */
    top -= ((uintptr_t)top - (uintptr_t)ctx->Rsp) & 15u;
    memcpy(top, (const void *)(uintptr_t)ctx->Rsp, BRIDGE_ARGCOPY);
    c.rsp = (uint64_t)(uintptr_t)top;

    if (g_trace_enabled) es3_trace(fn, "callback");
    dispatch(&c, fn);                       /* the callee's RET does rsp += 8 */

    /* Only the 32 bytes of shadow space travel back.
     *
     * Copying the whole window back looked harmless - it was copied in from
     * the same place moments earlier, so unchanged bytes write themselves - but
     * it is not: the window reaches past the caller's stack arguments into the
     * caller's OWN frame, and restoring a stale copy of that undoes whatever
     * the caller had done to it. That regressed the run from 14.7M dispatches
     * to 1.5M. The shadow space is the only part of the caller's frame a callee
     * owns outright. */
    memcpy((void *)(uintptr_t)(ctx->Rsp + 8), top + 8, 32);

    ctx->Rip = retaddr;
    ctx->Rsp = ctx->Rsp + 8;                /* what the callee's RET left */
    ctx->Rax = c.rax;
    /* Callee-saved registers are the guest's to preserve, and the lifted body
     * did preserve them - in the CPU. Copy them back, or the native caller
     * finds its own non-volatiles holding whatever the guest left there. */
    ctx->Rbx = c.rbx; ctx->Rbp = c.rbp; ctx->Rsi = c.rsi; ctx->Rdi = c.rdi;
    ctx->R12 = c.r12; ctx->R13 = c.r13; ctx->R14 = c.r14; ctx->R15 = c.r15;
    memcpy(&ctx->Xmm0, c.xmm, sizeof c.xmm);
    return 1;
}

static DWORD WINAPI es3_thread_shim(void *arg)
{
    thread_start_t ts = *(thread_start_t *)arg;
    free(arg);

    CPU c;
    memset(&c, 0, sizeof c);
    c.rsp = es3_alloc_stack(ts.stack ? ts.stack : (1u << 20));
    if (!c.rsp) {
        fprintf(stderr, "[thread] no guest stack for %#llx\n",
                (unsigned long long)ts.guest_fn);
        return 1;
    }
    c.rcx = ts.param;                 /* the thread parameter, first argument */
    if (g_trace_files) {
        /* Which runnable this thread was given, by its vtable.
         *
         * FRunnableThread::GuardedRun takes the thread object in RCX and finds
         * the runnable at [this+0x10], then calls its vtable[0] - Init - before
         * entering the loop. So a runnable whose Init never runs was never
         * handed to a thread, and the vtable is the only thing that says WHICH
         * runnable each thread actually got. Printing it turns "some threads
         * exist" into a list of which subsystems are running. */
        uint64_t runnable = 0, vt = 0;
        __try {
            runnable = rd64(ts.param + 0x10);
            if (runnable) vt = rd64(runnable);
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
        fprintf(stderr, "[thread] %lu entering guest %#llx  thread=%#llx "
                        "runnable=%#llx vtable=%#llx\n",
                GetCurrentThreadId(), (unsigned long long)ts.guest_fn,
                (unsigned long long)ts.param, (unsigned long long)runnable,
                (unsigned long long)vt);
    }
    es3_call_guest(&c, ts.guest_fn);
    if (g_trace_files)
        fprintf(stderr, "[thread] %lu guest %#llx returned %#llx\n",
                GetCurrentThreadId(), (unsigned long long)ts.guest_fn,
                (unsigned long long)c.rax);
    return (DWORD)c.rax;
}

/* ---- the cabinet service ----
 *
 * 03-01 I/O PCB ERROR does not come from talking to hardware. This title never
 * opens a port and never enumerates a device - of the nine setupapi functions
 * it imports it calls none. What it does is:
 *
 *   OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, L"RSSharedData")
 *   MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, 0)      <- size 0: all of it
 *   CreateMutexW(... L"RSMutexCredits") and five more
 *
 * so the I/O board, the credits, the dongle info, the ranking and the webcam
 * all reach the game as one block of shared memory published by the cabinet's
 * own service process. On a desktop nothing publishes it, OpenFileMapping
 * fails, and the game reports the board missing.
 *
 * So publish it. The size is ours to choose because the game maps zero bytes,
 * meaning the whole object; the CONTENTS are not yet known - working out which
 * field the I/O status lives in is the next job - but a block that exists and
 * a set of mutexes that can be taken is the difference between "the service is
 * not there" and "the service is there and says X", and only the second can be
 * debugged.
 */
static HANDLE g_rs_map, g_rs_mutex[6];
static void  *g_rs_view;

static const wchar_t *k_rs_mutex[6] = {
    L"RSMutexCredits", L"RSMutexSystem",     L"RSMutexGameState",
    L"RSMutexDongleInfo", L"RSMutexRanking", L"RSMutexWebCam",
};

/* Big enough for the largest offset the game touches, which is the webcam
 * frame: it memcpys 0x12C000 bytes - 640*480*4 - to view+0x2228, so the block
 * has to be at least 0x12E228. The smaller offsets in use are view+0 (0x1B4
 * bytes, read AND written), view+0x1B4 (0x8C, read), view+0x240, view+0x268
 * (0x84, written) and view+0x2EC (0x1F3C, both ways). 2 MB covers all of it
 * with room for whatever has not been found yet; the game maps the whole
 * object, so the size is the runtime's to choose. */
size_t g_rs_size = 0x200000;

/* --rs-fill: what an unknown field should look like. The block is the cabinet
 * service's, its layout is not yet worked out, and "all zeroes" is a guess
 * like any other - being able to try another one costs a byte. */
int g_rs_fill = 0;
int g_rs_dump_on = 0;

void es3_rs_dump(void)
{
    const unsigned char *p = (const unsigned char *)g_rs_view;
    if (!p) return;
    fprintf(stderr, "[rs] block, first 0x300 bytes (what the game published):\n");
    for (unsigned o = 0; o < 0x300; o += 16) {
        unsigned z = 1;
        for (unsigned i = 0; i < 16; i++) if (p[o + i]) z = 0;
        if (z) continue;                       /* zero rows say nothing */
        fprintf(stderr, "   %04X ", o);
        for (unsigned i = 0; i < 16; i++) fprintf(stderr, "%02X ", p[o + i]);
        fprintf(stderr, " ");
        for (unsigned i = 0; i < 16; i++)
            fprintf(stderr, "%c", (p[o + i] >= 32 && p[o + i] < 127) ? p[o + i] : '.');
        fprintf(stderr, "\n");
    }
}

/* ---- the I/O library, answered at its own API ----
 *
 * The lesson from lindberghrecomp's hle_sega.c, which solves the same problem
 * one cabinet over: a game does not talk to its I/O hardware, it calls the
 * cabinet library, and the thing to answer is the LIBRARY. Lindbergh overrides
 * SEGA's amLib by symbol name; here the equivalent library is statically
 * linked into the executable, so the same job is done by intercepting three
 * of its functions at their guest addresses.
 *
 *   0x1400037B0  state    - a busy byte, then a state word mapped
 *                           0->-1, 1->0, 2->1, 3->2, 4->3. Negative is what
 *                           becomes 03-01 I/O PCB ERROR.
 *   0x1400037F0  count    - how many JVS nodes are on the bus
 *   0x140003800  node(i)  - &node[i] in a table of four 0x2EC-byte records
 *
 * The game checks the board's identity by memcmp of the first 42 bytes of
 * node 1 against a string in its own .rdata, exactly as the Lindbergh game
 * checks the reply to JVS command 0x10 - so that string is what node 1 has to
 * start with, and it is read out of the image rather than typed here.
 *
 * Reading the analog channels at node+0x28A onwards is next; a pod is not a
 * kart and nothing is wired to an input yet.
 */
#define IO_NODE_STRIDE 0x2ec
#define IO_NODE_COUNT  4
#define IO_IDENT_VA    0x1412AD958ull   /* "namco ltd.;NA-JV;Ver4.00;..." */
#define IO_IDENT_LEN   0x2a

/* OFF by default, and UNTESTED - not known-broken.
 *
 * Two notes here previously said this path faulted. Neither survives: the
 * priming below has never actually run in any recorded run (it prints on its
 * first call and that line has never appeared), so the crashes attributed to
 * it happened upstream of it, and the same crash occurs with --io-board off.
 * What this machine really has is a display device that comes and goes, and
 * every "A differs from B" conclusion drawn across that has been wrong.
 *
 * The record layout IS known, by tracking the register the node accessor
 * returns through the poll function at 0x1409E0700 and recording every offset
 * it is used at. Every field is a scalar - there is no pointer anywhere in the
 * 0x2EC bytes - so a zero-filled record carrying the right identity is
 * structurally sound. (An earlier note said the record held a pointer; that
 * came from a tracker that let taint cross a call, so a C++ "this" and its
 * vtable call were being read as node fields.)
 *
 *   +0x000  42  board identity, memcmp'd against .rdata
 *   +0x109   1  byte field
 *   +0x187   1  \
 *   +0x189   3   > byte fields, read together - switches and coins
 *   +0x18E   1  |
 *   +0x190   1  |
 *   +0x19E   2  /
 *   +0x28A   2  \
 *   +0x28C   2   > 16-bit analog channels; the caller converts these to float
 *   +0x28E   2  /  with a subtract-then-scale, which is the calibration
 *   +0x2A8   2  \
 *   +0x2AA   2   > 16-bit values compared against 32-bit ones at +0x2AC,
 *   +0x2B0   2  |  +0x2B4, +0x2CC - analog readings against their limits
 *   +0x2B2   2  |
 *   +0x2C8   2  |
 *   +0x2CA   2  /
 *   +0x2E8   1  byte, compared - a status or present flag
 *
 * And the init builds TWO tables, which is the gap in what is primed here.
 * sub_140002360 allocates 4 records of 0x2EC at 0x141F2E770, then a SECOND
 * array of 0x48-byte records at 0x141F2E780 with its count at 0x141F2E778,
 * and finally zeroes a 16-entry word array at 0x141F2E788. Publishing only the
 * first leaves the second null, so the thing to do is run the real init and
 * then correct only the globals that say "no board" - not to keep hand-
 * building its outputs one table at a time.
 *
 * Two things to know before doing that. It takes ONE argument in rcx: rcx is
 * read before it is written, and the wrapper at 0x140E94870 that calls it is a
 * bare `sub rsp,0x28; call` which forwards whatever it was given. And nothing
 * in the image CALLS that wrapper - it is reached through a function pointer -
 * so the argument cannot be read off a call site and has to come from
 * instrumenting the wrapper at run time. Which needs a display, because with
 * no adapter UE3 aborts long before any of this runs. */
 *
 * Until that is settled the default build keeps the behaviour that is known to
 * work: rendering at 43 fps with 03-01 on screen. */
int g_io_board = 0;

/* Prime the library's OWN state, then let its own code run.
 *
 * The first version of this returned values and a node pointer of its own from
 * the three accessors. That was wrong in a way worth recording: the accessors
 * are three of seventy-odd places that reach this data, and the other seventy
 * read the library's globals directly. Answering the accessors from a private
 * buffer gave the game two different node tables depending on which path it
 * took to the same record.
 *
 * So write the library's own globals instead and let every path agree:
 *
 *   0x141F2E310  state, mapped by 0x1400037B0 (1 -> it returns 0)
 *   0x141F2E334  busy byte; non-zero makes the accessor return -2
 *   0x141F2E338  nodes on the bus, which the library's init sets to 0
 *   0x141F2E770  base of the table the init malloc'd, 4 records of 0x2EC
 */
static void io_board_prime(void)
{
    static int said;
    uint64_t base;

    wr32(GVA(0x141F2E310ull), 1);      /* state 1 -> "connected" */
    wr8 (GVA(0x141F2E334ull), 0);      /* not busy */
    wr32(GVA(0x141F2E338ull), 1);      /* one node on the bus */

    /* The table is allocated by the library's own init, and that init only
     * runs once a board has been found - so with no board there is no table,
     * and there is no table because there is no board. Break the circle by
     * publishing one: the game's seventy-odd direct readers of this global
     * then see the same records the accessors hand out, which is the thing
     * the first version of this got wrong. */
    base = rd64(GVA(0x141F2E770ull));
    if (!base) {
        static unsigned char table[IO_NODE_COUNT][IO_NODE_STRIDE];
        base = (uint64_t)(uintptr_t)table;
        wr64(GVA(0x141F2E770ull), base);
        wr32(GVA(0x141F2E768ull), IO_NODE_COUNT);
    }
    for (int i = 0; i < IO_NODE_COUNT; i++)
        memcpy((void *)(uintptr_t)(base + (uint64_t)i * IO_NODE_STRIDE),
               (const void *)(uintptr_t)GVA(IO_IDENT_VA), IO_IDENT_LEN);
    if (!said) {
        said = 1;
        fprintf(stderr, "[io] primed the library: node table %#llx, ident "
                        "\"%.42s\"\n", (unsigned long long)base,
                (const char *)(uintptr_t)base);
    }
}

/* Returns 1 if this address was answered here. Always 0 now: the accessors run
 * their own code, they just find the data already true. */
static int io_board_call(CPU *c, uint64_t va)
{
    (void)c;
    if (!g_io_board) return 0;
    if (va == 0x1400037B0ull || va == 0x1400037F0ull || va == 0x140003800ull)
        io_board_prime();
    return 0;
}

/* --rs-poke: a PROBE, not a fix.
 *
 * The I/O library keeps a "board present" byte at 0x141F2E334. Its accessor at
 * 0x1400037B0 is two instructions - compare it with zero, and return -2 if it
 * is zero - and -2 is what becomes 03-01 I/O PCB ERROR. In the whole image
 * that byte is written exactly once, to ZERO, by the library's init at
 * 0x1400023B6; whatever sets it on a real cabinet does so through a pointer,
 * and has not been found yet.
 *
 * Holding it at 1 from outside answers one question and only one: whether that
 * byte really is the thing 03-01 is about. If the error clears, the semantics
 * are confirmed and the honest version is to find the path that sets it and
 * feed that. If it does not, the search moves on. It is off by default and it
 * does not belong in a working build.
 */
int g_rs_poke;

static DWORD WINAPI rs_poke_thread(void *unused)
{
    (void)unused;
    for (;;) {
        wr8(GVA(0x141F2E334ull), 1);
        Sleep(50);
    }
}

void es3_rs_service(void)
{
    if (g_rs_map) return;
    if (g_rs_poke) {
        HANDLE t = CreateThread(NULL, 0, rs_poke_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
        fprintf(stderr, "[rs] PROBE: holding the I/O present byte at "
                        "0x141F2E334 set - this is a diagnostic, not a fix\n");
    }
    g_rs_map = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                  0, (DWORD)g_rs_size, L"RSSharedData");
    if (!g_rs_map) {
        fprintf(stderr, "[rs] CreateFileMappingW(RSSharedData) failed (%lu)\n",
                GetLastError());
        return;
    }
    g_rs_view = MapViewOfFile(g_rs_map, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (g_rs_view) memset(g_rs_view, 0, g_rs_size);
    for (int i = 0; i < 6; i++) {
        g_rs_mutex[i] = CreateMutexW(NULL, FALSE, k_rs_mutex[i]);
        if (!g_rs_mutex[i])
            fprintf(stderr, "[rs] CreateMutexW(%ls) failed (%lu)\n",
                    k_rs_mutex[i], GetLastError());
    }
    fprintf(stderr, "[rs] published RSSharedData (%llu bytes at %p) and %d "
                    "mutexes\n",
            (unsigned long long)g_rs_size, g_rs_view, 6);
}

/* ---- the entry points the lifted code calls ---- */

static void unknown_target(CPU *c, uint64_t target, const char *how)
{
    char msg[256];
    const char *nm = es3_import_name(target);
    snprintf(msg, sizeof msg,
             "%s to %#llx (%s) - not a lifted function, not in the image",
             how, (unsigned long long)target, nm ? nm : "unknown");
    es3_trace_dump(msg);
    fprintf(stderr, "[dispatch] %s\n", msg);
    abort();
}

void dispatch(CPU *c, uint64_t target)
{
    check_limit();
    uint64_t pref = to_preferred(target);
    tc_bump(pref);
    /* The cabinet library, answered rather than run - see io_board_call. */
    if (io_board_call(c, pref)) return;
    void (*fn)(CPU *) = lookup(pref);
    if (fn) {
        CPU *prev_cpu = g_cur_cpu;
        g_cur_cpu = c;
        /* A logged call's RETURN value. LoadPackage returning NULL is the
         * difference between "the package loaded and the object is missing"
         * and "the package never loaded at all", and entry logging alone
         * cannot tell those apart. */
        if (g_n_log_calls) {
            for (int q = 0; q < g_n_log_calls; q++)
                if (g_log_calls[q] == pref) {
                    es3_log_call(c, pref);
                    fn(c);
                    fprintf(stderr, "       -> returned %#llx\n",
                            (unsigned long long)c->rax);
                    g_cur_cpu = prev_cpu;
                    return;
                }
        }
        if (g_trace_enabled) {
            es3_trace(pref, "call");
            if (cs_depth < CS_MAX) cs_stack[cs_depth] = pref;
            cs_depth++;
            es3_watch_reader(c, pref);
            es3_log_call(c, pref);
            es3_log_callee(pref);
            if (g_watch_serialize && pref == g_watch_serialize) {
                g_watch_armed = 1; fn(c); g_watch_armed = 0; cs_depth--;
                g_cur_cpu = prev_cpu; return;
            }
            fn(c);
            cs_depth--;
            g_cur_cpu = prev_cpu;
            return;
        }
        /* FArchive::Serialize(this, dest, len) - watch what it actually
         * produces. The package summary is read through this one helper, and
         * the engine reports only that the TAG was wrong, never what it was.
         * Zero means nothing was written; a plausible value read at the wrong
         * offset means something else. One number decides it. */
        /* Armed by the summary parser, fired by the very next serialize.
         *
         * The serialize helper is shared by every archive in the engine - it
         * runs constantly, on strings and on object data - so watching it
         * unconditionally buries the one call that matters among thousands
         * that do not. Arming on the caller makes the output exactly the read
         * whose result the tag check is about to reject. */
        if (g_watch_serialize && pref == g_watch_serialize) {
            g_watch_armed = 1;
            fn(c);
            g_watch_armed = 0;
            return;
        }
        es3_watch_reader(c, pref);
        es3_log_call(c, pref);
        fn(c);
        g_cur_cpu = prev_cpu;
        return;
    }
    /* Inside the image but not a catalogued function: the disassembler missed
     * it. That is a real gap and worth reporting as one rather than trying to
     * call into it. */
    if (target >= g_image.text_lo && target < g_image.text_hi) {
        unknown_target(c, target, "call into uncatalogued guest code");
        return;
    }
    if (g_trace_enabled) es3_trace(target, "native");
    es3_native_call(c, target);
}

void dispatch_jmp(CPU *c, uint64_t target)
{
    check_limit();
    /* A tail call. The difference from dispatch() is that no return address was
     * pushed - the jump reuses the caller's - so a native callee here already
     * has the right frame and must NOT have the stack adjusted for it. */
    uint64_t pref = to_preferred(target);
    void (*fn)(CPU *) = lookup(pref);
    if (fn) {
        if (g_trace_enabled) es3_trace(pref, "tail");
        /* The buffer reader is reached by a TAIL jump from the forwarding
         * thunk, so the probe has to live on this path too. */
        es3_watch_reader(c, pref);
        es3_log_call(c, pref);
        fn(c);
        return;
    }
    if (target >= g_image.text_lo && target < g_image.text_hi) {
        unknown_target(c, target, "tail call into uncatalogued guest code");
        return;
    }
    if (g_trace_enabled) es3_trace(target, "native-tail");

    /* No stack adjustment here, and that is not an omission.
     *
     * A `jmp [__imp_memcpy]` thunk does not push a return address - it reuses
     * the one its own caller pushed, and the native callee's RET is what
     * consumes it. That is the same net effect as the call case, where the
     * lifted caller pushed the address and the callee's RET consumes it. So
     * both paths hand es3_native_call a stack pointing at a return address
     * with the shadow space above it, and both want the same adjustment. */
    es3_native_call(c, target);
}
