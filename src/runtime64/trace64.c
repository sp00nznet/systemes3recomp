/*
 * trace64.c - where it got to.
 *
 * A recompiled game that stops has stopped somewhere, and there is no debugger
 * on the far side of a lifted call: the stack is C frames named L_0001400xxxxx
 * with no symbols, and a release build turns abort() into __fastfail, which no
 * handler sees and which leaves nothing behind at all. The only way to know
 * where it got to is to have written it down on the way.
 *
 * A ring buffer, because the interesting part is always the last few hundred
 * entries and the first few million are startup. Unsynchronised on purpose -
 * a lock here would change the timing of the thing being diagnosed, and a
 * torn entry in a crash log is still worth more than no log.
 */

#include "es3_rt64.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>

/* A megabyte of entries. The tail of a UE3 startup is dominated by allocator
 * churn - scalable_malloc/free around every string - so a few thousand entries
 * cover a fraction of a second of guest time and the interesting call is
 * already gone by the time anything dumps. 16 MB of ring is cheap next to
 * losing the one line that matters. */
#define TRACE_N (1 << 20)

typedef struct { uint64_t va; const char *what; } trace_ent_t;

static trace_ent_t g_ring[TRACE_N];
static volatile long g_head;
static uint64_t g_calls;

void es3_trace(uint64_t va, const char *what)
{
    long i = (g_head++) & (TRACE_N - 1);
    g_ring[i].va = va;
    g_ring[i].what = what;
    g_calls++;
}

void es3_trace_dump(const char *why)
{
    FILE *f = fopen("es3_trace64.txt", "w");
    if (!f) f = stderr;
    fprintf(f, "=== es3 trace: %s ===\n", why);
    fprintf(f, "image base %p (preferred %#llx, delta %+lld)\n",
            (void *)g_image.base, (unsigned long long)g_image.preferred,
            (long long)g_image_delta);
    fprintf(f, "%llu dispatches total, last %d:\n",
            (unsigned long long)g_calls, TRACE_N);

    long head = g_head;
    long n = head < TRACE_N ? head : TRACE_N;
    for (long k = n; k > 0; k--) {
        long i = (head - k) & (TRACE_N - 1);
        if (!g_ring[i].what) continue;
        uint64_t va = g_ring[i].va;
        const char *nm = es3_import_name(va);
        fprintf(f, "  %-12s %#018llx %s\n", g_ring[i].what,
                (unsigned long long)va, nm ? nm : "");
    }
    fflush(f);
    if (f != stderr) {
        fclose(f);
        fprintf(stderr, "[trace] wrote es3_trace64.txt (%ld entries)\n", n);
    }
}

/* ---- RECOMP_TODO: an instruction the lifter could not express ----
 *
 * cpu64.h defines this as plain abort() so that anything including only the
 * header still builds. That default is useless in practice: MSVC turns abort()
 * into __fastfail, which no exception handler sees and no filter can report, so
 * the process vanishes with 0xC0000409 and not one line of output. This build
 * spent a run being diagnosed as "it crashed somewhere" for exactly that
 * reason, after the guest had in fact got FURTHER than ever before.
 *
 * The runtime overrides it (see the /D on the generated files) to say which
 * guest address, which mnemonic, and how it got there.
 */
void es3_todo(uint64_t va, const char *text)
{
    fprintf(stderr, "\n[TODO] unexpressed instruction at %#llx: %s\n",
            (unsigned long long)va, text ? text : "?");
    es3_dump_callstack("at the unexpressed instruction");
    es3_trace_dump("RECOMP_TODO");
    fflush(stderr);
    _exit(4);
}

void es3_trace_tail(int n)
{
    /* Straight to stderr, not to the dump file.
     *
     * es3_trace_dump writes one fixed filename, so a dump taken at an
     * interesting moment is overwritten by whatever exception ends the process
     * afterwards - and reading that file then answers a question about the
     * wrong moment. This prints where it is asked, when it is asked. */
    long head = g_head;
    long have = head < TRACE_N ? head : TRACE_N;
    if (n > have) n = (int)have;
    fprintf(stderr, "[trail] last %d dispatches:\n", n);
    for (long k = n; k > 0; k--) {
        long i = (head - k) & (TRACE_N - 1);
        if (!g_ring[i].what) continue;
        const char *nm = es3_import_name(g_ring[i].va);
        fprintf(stderr, "  %-12s %#018llx %s\n", g_ring[i].what,
                (unsigned long long)g_ring[i].va, nm ? nm : "");
    }
}

/* ---- did it actually draw anything? ----
 *
 * On a machine with no display device - every session here is remote - a
 * window is black whether the game is rendering into it or not, so looking at
 * it proves nothing either way. The only honest answer comes from counting the
 * calls.
 *
 * IDirect3D9 and IDirect3DDevice9 are plain COM: a pointer to a vtable of
 * function pointers. Swapping two of those entries for functions that count
 * and then forward is enough, and it needs no d3d9.h and no knowledge of what
 * the guest does with the device. The indices are from the interface
 * declarations and are fixed by ABI.
 */
#define D3D9_CREATEDEVICE 16
#define D3D9_DEV_PRESENT  17

typedef long (__stdcall *pfn_createdevice)(void *, unsigned, int, void *,
                                           unsigned long, void *, void **);
typedef long (__stdcall *pfn_present)(void *, const void *, const void *,
                                      void *, const void *);

static pfn_createdevice orig_createdevice;
static pfn_present      orig_present;
unsigned long long      g_present_count;

static int patch_slot(void *iface, int index, void *repl, void **orig)
{
    void **vt = *(void ***)iface;
    DWORD old;
    if (*orig) return 1;                     /* the vtable is shared */
    if (!VirtualProtect(&vt[index], sizeof(void *), PAGE_READWRITE, &old))
        return 0;
    *orig = vt[index];
    vt[index] = repl;
    VirtualProtect(&vt[index], sizeof(void *), old, &old);
    return 1;
}

/* --capture N: write frame N out as a PNG.
 *
 * The one thing a frame counter cannot tell you is WHAT was drawn, and on a
 * session with no display there is no other way to look. d3dx9_43 is already
 * loaded - the guest imports it - so the save costs a GetProcAddress and the
 * back buffer, and nothing has to be reimplemented. */
#define D3D9_DEV_GETBACKBUFFER 18

typedef long (__stdcall *pfn_getbackbuffer)(void *, unsigned, unsigned, int,
                                            void **);
typedef long (__stdcall *pfn_savesurface)(const char *, int, void *,
                                          const void *, const void *);
typedef unsigned long (__stdcall *pfn_release)(void *);

unsigned long long g_capture_frame;

static void capture_backbuffer(void *dev, unsigned long long n)
{
    void **vt = *(void ***)dev;
    void *surf = NULL;
    char path[64];
    HMODULE d3dx;
    pfn_savesurface save;
    long hr;

    d3dx = GetModuleHandleA("d3dx9_43.dll");
    save = d3dx ? (pfn_savesurface)(void *)
                  GetProcAddress(d3dx, "D3DXSaveSurfaceToFileA") : NULL;
    if (!save) {
        fprintf(stderr, "[d3d9] capture: no D3DXSaveSurfaceToFileA\n");
        return;
    }
    hr = ((pfn_getbackbuffer)vt[D3D9_DEV_GETBACKBUFFER])(dev, 0, 0, 0, &surf);
    if (hr < 0 || !surf) {
        fprintf(stderr, "[d3d9] capture: GetBackBuffer -> %#lx\n",
                (unsigned long)hr);
        return;
    }
    snprintf(path, sizeof path, "es3_frame_%llu.png", n);
    hr = save(path, 3 /* D3DXIFF_PNG */, surf, NULL, NULL);
    ((pfn_release)(*(void ***)surf)[2])(surf);
    fprintf(stderr, "[d3d9] captured frame %llu to %s (%#lx)\n",
            n, path, (unsigned long)hr);
}

static long __stdcall hook_present(void *dev, const void *a, const void *b,
                                   void *c, const void *d)
{
    long hr;
    /* Before the flip: afterwards the back buffer is whatever the driver
     * handed back, which on some drivers is the frame before last and on
     * others is undefined. */
    if (g_capture_frame && g_present_count + 1 == g_capture_frame)
        capture_backbuffer(dev, g_capture_frame);
    hr = orig_present(dev, a, b, c, d);
    /* Logged on a curve, not every frame: the point is that the number keeps
     * going up, and one line per frame buries everything else. */
    g_present_count++;
    if (g_present_count <= 4 || g_present_count == 30 ||
        g_present_count % 300 == 0)
        fprintf(stderr, "[d3d9] Present #%llu -> %#lx\n",
                g_present_count, (unsigned long)hr);
    return hr;
}

static long __stdcall hook_createdevice(void *d3d, unsigned adapter, int type,
                                        void *focus, unsigned long flags,
                                        void *pp, void **out)
{
    long hr = orig_createdevice(d3d, adapter, type, focus, flags, pp, out);
    fprintf(stderr, "[d3d9] CreateDevice(adapter=%u type=%d hwnd=%p flags=%#lx)"
                    " -> %#lx  device=%p\n",
            adapter, type, focus, (unsigned long)flags, (unsigned long)hr,
            (out && hr >= 0) ? *out : NULL);
    if (hr >= 0 && out && *out)
        patch_slot(*out, D3D9_DEV_PRESENT, (void *)hook_present,
                   (void **)&orig_present);
    return hr;
}

/* IDirect3D9::GetAdapterCount, vtable slot 4. */
typedef unsigned (__stdcall *pfn_adaptercount)(void *);

void es3_d3d9_watch(void *d3d9)
{
    void **vt;
    unsigned n;

    if (!d3d9) return;
    vt = *(void ***)d3d9;
    n = ((pfn_adaptercount)vt[4])(d3d9);
    /* Reported every run, because it is the first thing to check when a
     * graphical target dies early and the window is black. A remote session
     * has no display device: Direct3DCreate9 still SUCCEEDS there and returns
     * an interface, and it is the adapter count that comes back zero - after
     * which UE3 raises a fatal error before it loads a single package, which
     * looks nothing like a display problem from the log. */
    fprintf(stderr, "[d3d9] %u adapter(s)%s\n", n,
            n ? "" : "  - NO DISPLAY DEVICE on this session; nothing will "
                     "render and the engine will abort early");
    if (patch_slot(d3d9, D3D9_CREATEDEVICE, (void *)hook_createdevice,
                   (void **)&orig_createdevice))
        fprintf(stderr, "[d3d9] watching CreateDevice/Present\n");
}

/* --find-string: is this text anywhere in guest memory?
 *
 * Settles "did the package actually decompress" without reverse-engineering
 * the decompressor. A UE3 package's name table lives inside an LZO chunk; if
 * the engine inflated Startup.upk correctly then every FName in it is sitting
 * in the heap as plain ASCII, and if it did not, it is not.
 *
 * ponytail: naive memchr over every committed region, ~seconds on a few GB.
 * Only ever runs once, at the throw.
 */
const char *g_find_string;

void es3_find_string(void)
{
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char *p = 0;
    size_t n;
    int hits = 0;

    if (!g_find_string) return;
    n = strlen(g_find_string);
    fprintf(stderr, "[find] scanning guest memory for \"%s\"\n", g_find_string);
    while (VirtualQuery(p, &mbi, sizeof mbi) == sizeof mbi) {
        unsigned char *base = (unsigned char *)mbi.BaseAddress;
        size_t sz = mbi.RegionSize;
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) &&
            mbi.Protect != PAGE_NOACCESS) {
            unsigned char *q = base, *end = base + sz - n;
            while (q <= end) {
                unsigned char *h = memchr(q, g_find_string[0], (size_t)(end - q) + 1);
                if (!h) break;
                if (!memcmp(h, g_find_string, n)) {
                    if (hits < 8)
                        fprintf(stderr, "[find] hit at %p (region %p size %llu prot %#lx)\n",
                                (void *)h, (void *)base,
                                (unsigned long long)sz, (unsigned long)mbi.Protect);
                    hits++;
                }
                q = h + 1;
            }
        }
        if (base + sz <= p) break;
        p = base + sz;
    }
    fprintf(stderr, "[find] \"%s\": %d hit(s)\n", g_find_string, hits);
}

static LONG WINAPI es3_seh(EXCEPTION_POINTERS *ep)
{
    char msg[256];
    snprintf(msg, sizeof msg, "exception %#lx at %p",
             ep->ExceptionRecord->ExceptionCode,
             ep->ExceptionRecord->ExceptionAddress);
    fprintf(stderr, "\n[crash] %s\n", msg);

    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        /* The address the guest tried to touch is the diagnosis nine times out
         * of ten: near zero is an uninitialised pointer, and a value that looks
         * like a guest address with a 4 GB-multiple offset is a 32-bit register
         * write that failed to zero-extend.
         *
         * Operation 8 is a DEP violation, and it is worth its own message
         * rather than being lumped in with "write" - guest memory is mapped
         * non-executable on purpose, so an execute fault inside the image is
         * not a corrupt pointer at all. It is a native caller reaching a guest
         * callback that needs a thunk, and it names the exact address. */
        ULONG_PTR op = ep->ExceptionRecord->ExceptionInformation[0];
        ULONG_PTR at = ep->ExceptionRecord->ExceptionInformation[1];
        const char *what = op == 8 ? "EXECUTE" : op ? "write to" : "read from";
        fprintf(stderr, "[crash] %s address %#llx\n", what, (unsigned long long)at);
        if (op == 8 && g_image.base &&
            at >= (ULONG_PTR)g_image.base &&
            at < (ULONG_PTR)g_image.base + g_image.size) {
            fprintf(stderr,
                "[crash] that is INSIDE the guest image, which is mapped\n"
                "[crash] non-executable because all of its code was recompiled.\n"
                "[crash] Something native called a guest address directly - a\n"
                "[crash] callback (thread proc, window proc, comparator) handed\n"
                "[crash] to a real DLL. It needs a thunk that enters the lifted\n"
                "[crash] function instead.\n");
        }
    }
    /* The lifted call stack, not just the trail. A fault in generated C has no
     * usable native stack - every frame is L_0001400xxxxx with no symbols - so
     * the shadow stack is the only thing that says which guest function was
     * running and who called it. */
    if (g_cur_cpu)
        fprintf(stderr, "[crash] guest PC (block) %#llx  rax=%#llx rcx=%#llx "
                        "rdx=%#llx rsp=%#llx\n",
                (unsigned long long)g_cur_cpu->rip,
                (unsigned long long)g_cur_cpu->rax,
                (unsigned long long)g_cur_cpu->rcx,
                (unsigned long long)g_cur_cpu->rdx,
                (unsigned long long)g_cur_cpu->rsp);
    es3_dump_callstack("at the fault");
    es3_trace_dump(msg);
    return EXCEPTION_EXECUTE_HANDLER;
}

static LONG CALLBACK es3_veh(EXCEPTION_POINTERS *ep)
{
    DWORD code = ep->ExceptionRecord->ExceptionCode;

    /* A native caller reaching a guest function is not a crash - it is a
     * callback, and it is bridged rather than reported. Checked first and
     * silently, because it is a normal event that happens thousands of times.
     */
    if (es3_bridge_callback(ep))
        return EXCEPTION_CONTINUE_EXECUTION;

    /* Every exception gets a line, always. Passing one over silently as
     * "benign" is how a run ends with an exit code and no explanation: nothing
     * downstream had a handler either, so the exception this filter waved
     * through became the thing that killed the process. */
    fprintf(stderr, "[veh] exception %#lx at %p (dispatch %llu)\n",
            code, ep->ExceptionRecord->ExceptionAddress,
            (unsigned long long)g_dispatch_count);

    /* 0x406D1388 is the "set thread name" notification. It is addressed to a
     * debugger and is meant to be swallowed; with no debugger attached and no
     * guest SEH to catch it, letting it continue the search makes it fatal.
     * Continuing EXECUTION is what a debugger does. */
    if (code == 0x406D1388u)
        return EXCEPTION_CONTINUE_EXECUTION;

    /* A C++ throw carries the thrown type's name, and in a build with no
     * symbols and no log that name is most of the diagnosis. The record holds
     * a ThrowInfo whose members are RVAs from the module base in
     * ExceptionInformation[3] - which is how a 64-bit throw stays
     * position-independent. */
    if (code == 0xE06D7363u) {
        const EXCEPTION_RECORD *r = ep->ExceptionRecord;
        /* UE3 throws its error MESSAGE: appError does `throw TEXT("...")`, so
         * the thrown type is wchar_t* and the object is a pointer to it. That
         * string is the engine's own diagnosis, in English, which is worth
         * more than any amount of dispatch trail - and in a shipping build
         * with the log compiled out it is the only place the reason appears.
         *
         * Guarded, because the object is guest memory and a wrong guess about
         * the layout would fault inside the handler for the original fault. */
        if (r->NumberParameters >= 2 && r->ExceptionInformation[1]) {
            __try {
                const wchar_t *msg = *(const wchar_t **)r->ExceptionInformation[1];
                if (msg && !IsBadReadPtr(msg, 2))
                    fprintf(stderr, "[throw] guest threw: %ls\n", msg);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                fprintf(stderr, "[throw] (thrown object not readable as a string)\n");
            }
        }
        if (r->NumberParameters >= 4 &&
            r->ExceptionInformation[0] == 0x19930520u) {
            char *mod = (char *)r->ExceptionInformation[3];
            const int *ti = (const int *)r->ExceptionInformation[2];
            if (mod && ti && ti[3]) {
                const int *cta = (const int *)(mod + ti[3]);
                if (cta[0] > 0) {
                    const int *ct = (const int *)(mod + cta[1]);
                    /* TypeDescriptor: vftable, spare, then the decorated name */
                    const char *nm = (const char *)(mod + ct[1]) + 16;
                    fprintf(stderr, "[throw] C++ exception of type '%s'\n", nm);
                }
            }
        }
        /* The lifted call stack at the THROW, not just at the eventual death.
         * UE3's appErrorf messages name a symptom ("Failed to find object
         * 'Class None.'") and never the caller, and the caller is the only
         * thing that says which config key or which package was expected to
         * provide it. */
        if (g_cur_cpu)
            fprintf(stderr, "[throw] guest PC (block) %#llx\n",
                    (unsigned long long)g_cur_cpu->rip);
        es3_dump_callstack("at the throw");
        es3_find_string();
        es3_dump_threads();
        es3_trace_dump("guest C++ throw");
        return EXCEPTION_CONTINUE_SEARCH;
    }
    /* ---- the guest's own log ----
     *
     * OutputDebugString does not write anywhere; it RAISES, with the text in
     * the exception record, and a debugger is what normally picks it up. There
     * is no debugger here, so UE3 has been narrating its startup - every
     * warning, every "couldn't find", every subsystem announcing itself - into
     * an exception filter that waved it through unread.
     *
     * 0x40010006 carries ANSI, 0x4001000A wide. Information[0] is the length
     * including the terminator, Information[1] the text.
     */
    if (code == 0x40010006u || code == 0x4001000Au) {
        const EXCEPTION_RECORD *r = ep->ExceptionRecord;
        if (g_guest_log && r->NumberParameters >= 2 && r->ExceptionInformation[1]) {
            __try {
                if (code == 0x4001000Au)
                    fprintf(stderr, "[log] %.*ls",
                            (int)r->ExceptionInformation[0],
                            (const wchar_t *)r->ExceptionInformation[1]);
                else
                    fprintf(stderr, "[log] %.*s",
                            (int)r->ExceptionInformation[0],
                            (const char *)r->ExceptionInformation[1]);
            } __except (EXCEPTION_EXECUTE_HANDLER) { }
        }
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    es3_seh(ep);
    return EXCEPTION_CONTINUE_SEARCH;
}

void es3_install_crash_handler(void)
{
    /* Both, deliberately. SetUnhandledExceptionFilter runs last and does not
     * run at all if the fault corrupted enough state to prevent unwinding -
     * which is exactly the case when a lifted function walks off a stack. A
     * vectored handler runs FIRST, before any unwinding, so the trail survives
     * the faults that matter most. */
    AddVectoredExceptionHandler(1, es3_veh);
    SetUnhandledExceptionFilter(es3_seh);
}
