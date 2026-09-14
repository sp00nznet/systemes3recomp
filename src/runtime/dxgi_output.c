/*
 * dxgi_output.c - give a DXUT title a display to find.
 *
 * A game built on DXUT enumerates DXGI adapters, asks each one for its
 * outputs, and builds its list of usable device settings from the display
 * modes those outputs report. An adapter with no outputs contributes nothing,
 * and when nothing is left DXUT puts up
 *
 *     Could not find any compatible Direct3D devices.
 *
 * and waits for an OK. On a cabinet there is nobody to click it, and from
 * outside the run is a hung process with a black window.
 *
 * That is what happens in a session with no display attached to the adapter -
 * a Remote Desktop session, most obviously. Measured on one: Direct3DCreate9
 * reports 0 adapters, Direct3DCreate9Ex returns D3DERR_NOTAVAILABLE, and DXGI
 * reports six adapters with zero outputs between them.
 *
 * And yet the graphics work. In the same session:
 *
 *     D3D10CreateDeviceAndSwapChain(HARDWARE, Windowed=TRUE) = S_OK
 *     Clear + Present                                        = DXGI_STATUS_OCCLUDED
 *
 * which is a success. A windowed swap chain presents into a window the
 * compositor owns and never needs a display mode; the mode list is only there
 * so DXUT can offer a fullscreen resolution nobody is going to pick. The
 * enumeration is the whole blocker, and it is asking the wrong question.
 *
 * So answer it. When IDXGIAdapter::EnumOutputs comes back empty, hand the game
 * one synthetic IDXGIOutput describing the desktop this process can actually
 * see - GetSystemMetrics knows its size even here - with a short list of
 * ordinary modes on it. Everything after that is real: the real adapter, the
 * real device, a real windowed swap chain on the game's own window.
 *
 * This is the same kind of shim as substituting a module handle for the
 * guest's own image base, and it has the same justification. The machine the
 * game was built for had a monitor bolted to it. This reconstructs that much
 * of it and nothing else - the runtime forces every swap chain windowed, so
 * the fullscreen modes advertised here can never actually be entered.
 *
 * ES3_NO_FAKE_OUTPUT turns it off, which is how you tell this apart from a
 * real enumeration failure.
 */

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "es3_rt.h"

#define E_NOINTERFACE_        ((long)0x80004002L)
#define E_NOTIMPL_            ((long)0x80004001L)
#define E_INVALIDARG_         ((long)0x80070057L)

/* The formats DXUT asks about, and the sizes worth offering. The game asks for
 * 1360x768; the rest are here so a title that wants something else still finds
 * a match, and because DXUT ranks modes and an empty rank list is the bug this
 * file exists to avoid. */
static const struct { unsigned w, h; } MODES[] = {
    {  640,  480 }, {  800,  600 }, { 1024,  768 }, { 1280,  720 },
    { 1280,  768 }, { 1280, 1024 }, { 1360,  768 }, { 1366,  768 },
    { 1600,  900 }, { 1680, 1050 }, { 1920, 1080 },
};
#define NMODES (sizeof MODES / sizeof MODES[0])

/* DXGI_MODE_DESC: Width, Height, RefreshRate{Num,Den}, Format,
 * ScanlineOrdering, Scaling - 28 bytes, and the layout is ABI, not a guess. */
typedef struct {
    unsigned width, height, num, den, format, scanline, scaling;
} MODE_DESC;

/* DXGI_OUTPUT_DESC: WCHAR DeviceName[32]; RECT DesktopCoordinates;
 * BOOL AttachedToDesktop; DXGI_MODE_ROTATION Rotation; HMONITOR Monitor. */
typedef struct {
    wchar_t name[32];
    RECT    desktop;
    int     attached;
    int     rotation;
    void   *monitor;
} OUTPUT_DESC;

typedef struct FakeOutput {
    const void **vtbl;
    volatile long refs;
} FakeOutput;

static int g_off = -1;
static unsigned g_made;

static int fake_off(void)
{
    if (g_off < 0) g_off = getenv("ES3_NO_FAKE_OUTPUT") != NULL;
    return g_off;
}

/* --- IUnknown ----------------------------------------------------------- */

/* IID_IDXGIOutput and IID_IUnknown. QueryInterface has to answer both,
 * because DXUT stores the result of one and DXGI itself may ask for the
 * other. Anything else is declined rather than guessed at. */
static const GUID IID_IDXGIOutput_ =
    { 0xae02eedb, 0xc735, 0x4690,
      { 0x8d, 0x52, 0x5a, 0x8d, 0xc2, 0x02, 0x13, 0xaa } };
static const GUID IID_IUnknown_ =
    { 0x00000000, 0x0000, 0x0000,
      { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

static long __stdcall out_qi(FakeOutput *o, const GUID *iid, void **pp)
{
    if (!pp) return E_INVALIDARG_;
    if (iid && (memcmp(iid, &IID_IDXGIOutput_, sizeof *iid) == 0 ||
                memcmp(iid, &IID_IUnknown_, sizeof *iid) == 0)) {
        InterlockedIncrement(&o->refs);
        *pp = o;
        return 0;
    }
    *pp = NULL;
    return E_NOINTERFACE_;
}

static unsigned long __stdcall out_addref(FakeOutput *o)
{
    return (unsigned long)InterlockedIncrement(&o->refs);
}

/* Never actually freed: it is one static object per process, and a game that
 * over-releases a display it did not allocate should not take the run with
 * it. The count is still tracked so the numbers it sees are sane. */
static unsigned long __stdcall out_release(FakeOutput *o)
{
    long n = InterlockedDecrement(&o->refs);
    return (unsigned long)(n < 0 ? 0 : n);
}

/* --- IDXGIObject -------------------------------------------------------- */

static long __stdcall out_set_priv(FakeOutput *o, const GUID *g, unsigned n,
                                   const void *p)
{ (void)o; (void)g; (void)n; (void)p; return 0; }

static long __stdcall out_set_priv_iface(FakeOutput *o, const GUID *g,
                                         const void *p)
{ (void)o; (void)g; (void)p; return 0; }

static long __stdcall out_get_priv(FakeOutput *o, const GUID *g, unsigned *n,
                                   void *p)
{ (void)o; (void)g; (void)p; if (n) *n = 0; return (long)0x887A0002L;   /* DXGI_ERROR_NOT_FOUND */ }

/* GetParent would have to hand back the adapter, and handing back a real
 * interface this object does not own is how a shim starts corrupting
 * lifetimes. Declined; DXUT does not need it to enumerate. */
static long __stdcall out_get_parent(FakeOutput *o, const GUID *g, void **pp)
{ (void)o; (void)g; if (pp) *pp = NULL; return E_NOINTERFACE_; }

/* --- IDXGIOutput -------------------------------------------------------- */

static long __stdcall out_get_desc(FakeOutput *o, OUTPUT_DESC *d)
{
    POINT origin;
    (void)o;
    if (!d) return E_INVALIDARG_;
    memset(d, 0, sizeof *d);
    /* The name USER32 would use for the primary display. DXUT prints it and
     * compares it; anything else looks like a device that is not there. */
    memcpy(d->name, L"\\\\.\\DISPLAY1", sizeof(L"\\\\.\\DISPLAY1"));
    d->desktop.left = 0;
    d->desktop.top = 0;
    d->desktop.right = GetSystemMetrics(SM_CXSCREEN);
    d->desktop.bottom = GetSystemMetrics(SM_CYSCREEN);
    if (d->desktop.right <= 0) d->desktop.right = 1920;
    if (d->desktop.bottom <= 0) d->desktop.bottom = 1080;
    d->attached = 1;
    d->rotation = 1;                       /* DXGI_MODE_ROTATION_IDENTITY */
    /* A real HMONITOR, because a game that calls MonitorFromWindow and
     * compares gets a match. USER32 has one even in a session DXGI does not. */
    origin.x = 0; origin.y = 0;
    d->monitor = MonitorFromPoint(origin, MONITOR_DEFAULTTOPRIMARY);
    return 0;
}

/* GetDisplayModeList(format, flags, *count, modes):
 * with a null list it is a query for how many, otherwise it fills that many.
 * The same list for every format DXUT asks about - it asked for one format and
 * gets modes in it, which is the contract. */
static long __stdcall out_get_modes(FakeOutput *o, unsigned format,
                                    unsigned flags, unsigned *count,
                                    MODE_DESC *modes)
{
    unsigned i, n;
    (void)o; (void)flags;
    if (!count) return E_INVALIDARG_;
    if (!modes) { *count = (unsigned)NMODES; return 0; }
    n = *count < NMODES ? *count : (unsigned)NMODES;
    for (i = 0; i < n; i++) {
        modes[i].width = MODES[i].w;
        modes[i].height = MODES[i].h;
        modes[i].num = 60;
        modes[i].den = 1;
        modes[i].format = format;
        modes[i].scanline = 0;             /* UNSPECIFIED */
        modes[i].scaling = 0;              /* UNSPECIFIED */
    }
    *count = n;
    return 0;
}

static long __stdcall out_find_mode(FakeOutput *o, const MODE_DESC *want,
                                    MODE_DESC *got, void *dev)
{
    unsigned i, best = 0;
    long bestd = 0x7FFFFFFF;
    (void)o; (void)dev;
    if (!want || !got) return E_INVALIDARG_;
    for (i = 0; i < NMODES; i++) {
        long dw = (long)MODES[i].w - (long)want->width;
        long dh = (long)MODES[i].h - (long)want->height;
        long d = (dw < 0 ? -dw : dw) + (dh < 0 ? -dh : dh);
        if (d < bestd) { bestd = d; best = i; }
    }
    got->width = MODES[best].w;
    got->height = MODES[best].h;
    got->num = want->num ? want->num : 60;
    got->den = want->den ? want->den : 1;
    got->format = want->format;
    got->scanline = 0;
    got->scaling = 0;
    return 0;
}

/* There is no vertical blank to wait for, and pretending to wait for one at
 * sixty hertz would throttle a game to a refresh rate this display does not
 * have. Return at once; the swap chain's own Present does the pacing. */
static long __stdcall out_wait_vblank(FakeOutput *o) { (void)o; return 0; }

static long __stdcall out_take(FakeOutput *o, void *dev, int excl)
{ (void)o; (void)dev; (void)excl; return 0; }
static void __stdcall out_release_own(FakeOutput *o) { (void)o; }
static long __stdcall out_gamma_caps(FakeOutput *o, void *p)
{ (void)o; (void)p; return E_NOTIMPL_; }
static long __stdcall out_set_gamma(FakeOutput *o, const void *p)
{ (void)o; (void)p; return 0; }
static long __stdcall out_get_gamma(FakeOutput *o, void *p)
{ (void)o; (void)p; return E_NOTIMPL_; }
static long __stdcall out_set_surface(FakeOutput *o, void *p)
{ (void)o; (void)p; return E_NOTIMPL_; }
static long __stdcall out_get_surface(FakeOutput *o, void *p)
{ (void)o; (void)p; return E_NOTIMPL_; }
static long __stdcall out_frame_stats(FakeOutput *o, void *p)
{ (void)o; (void)p; return E_NOTIMPL_; }

/* In interface order. A slot out of place is a call into the wrong function
 * with the wrong arguments, so the order is the ABI and not a preference. */
static const void *g_out_vtbl[] = {
    (const void *)out_qi,
    (const void *)out_addref,
    (const void *)out_release,
    (const void *)out_set_priv,
    (const void *)out_set_priv_iface,
    (const void *)out_get_priv,
    (const void *)out_get_parent,
    (const void *)out_get_desc,
    (const void *)out_get_modes,
    (const void *)out_find_mode,
    (const void *)out_wait_vblank,
    (const void *)out_take,
    (const void *)out_release_own,
    (const void *)out_gamma_caps,
    (const void *)out_set_gamma,
    (const void *)out_get_gamma,
    (const void *)out_set_surface,
    (const void *)out_get_surface,
    (const void *)out_frame_stats,
};

static FakeOutput g_fake = { g_out_vtbl, 1 };

uint32_t es3_fake_output(void)
{
    if (fake_off()) return 0;
    InterlockedIncrement(&g_fake.refs);
    if (!g_made++) {
        OUTPUT_DESC d;
        out_get_desc(&g_fake, &d);
        fprintf(stderr,
            "\n[dxgi] no adapter in this session reports a display, so the game "
            "cannot enumerate one.\n"
            "       Handing it one that describes this desktop (%ldx%ld, %u "
            "modes) - windowed\n"
            "       rendering works here, and only the enumeration did not. "
            "ES3_NO_FAKE_OUTPUT to stop.\n\n",
            d.desktop.right - d.desktop.left, d.desktop.bottom - d.desktop.top,
            (unsigned)NMODES);
        fflush(stderr);
    }
    return (uint32_t)(uintptr_t)&g_fake;
}

#else
uint32_t es3_fake_output(void) { return 0; }
#endif
