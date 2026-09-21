/*
 * es3_input.c - see es3_input.h.
 *
 * The keyboard and pad mapping follows the one jvs.c established for the
 * 32-bit titles, so that a person who has driven a kart does not have to learn
 * a second set of keys to fly a pod:
 *
 *   keyboard          pad                  meaning
 *   ----------------  -------------------  ------------------------------
 *   Enter             Start                START
 *   Left Ctrl, Space  A                    FIRE
 *   Z                 B                    FIRE2
 *   arrow keys        left stick / d-pad   stick, and the four directions
 *   Up / Down         right/left trigger   throttle and brake
 *   T                 -                    TEST    (the operator menu)
 *   S                 Back                 SERVICE
 *   5                 stick click          insert a coin
 *
 * Only while a window of this process has the foreground: GetAsyncKeyState is
 * global, and a game that reads your typing in another application is a worse
 * bug than no input at all.
 */

#include "es3_input.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>

/* XInput by name rather than by import library, so the runtime does not need
 * xinput at link time and runs on a machine with no pad and no DLL. */
typedef struct {
    WORD  wButtons;
    BYTE  bLeftTrigger, bRightTrigger;
    SHORT sThumbLX, sThumbLY, sThumbRX, sThumbRY;
} ES3_XINPUT_GAMEPAD;

typedef struct { DWORD dwPacketNumber; ES3_XINPUT_GAMEPAD Gamepad; } ES3_XINPUT_STATE;
typedef DWORD (WINAPI *ES3_XInputGetState)(DWORD, ES3_XINPUT_STATE *);

/* GetModuleHandle, never LoadLibrary.
 *
 * This is called from the board layer, which a recompiled game reaches from
 * inside its own dispatch - and the guest loads DLLs of its own (dxgi, d3d11,
 * nvapi, PhysX) while that is happening. Calling LoadLibrary from here takes
 * the loader lock from a second thread while the guest holds it, and the
 * process stops: 400 seconds of wall time for two seconds of CPU, blocked in
 * startup, with nothing to say a DLL was involved.
 *
 * Nothing is lost by refusing to load one. A cabinet title that supports a pad
 * imports XInput itself - this one imports XINPUT1_3.dll - so by the time
 * there is a game to play the module is already there. If it is not, there is
 * no pad, which is exactly what a keyboard-only machine should report. */
static ES3_XInputGetState xinput_fn(void)
{
    static ES3_XInputGetState fn;
    static int tried;
    if (!tried) {
        static const char *dlls[] = {
            "xinput1_4.dll", "xinput1_3.dll", "xinput9_1_0.dll"
        };
        tried = 1;
        for (int i = 0; i < 3 && !fn; i++) {
            HMODULE m = GetModuleHandleA(dlls[i]);
            if (m) fn = (ES3_XInputGetState)(void *)
                        GetProcAddress(m, "XInputGetState");
        }
    }
    return fn;
}

static int input_off(void)
{
    static int off = -1;
    if (off < 0) off = GetEnvironmentVariableA("ES3_NO_INPUT", NULL, 0) != 0;
    return off;
}

/* Does a window of THIS process have the foreground? */
static int ours_in_front(void)
{
    DWORD pid = 0;
    HWND h = GetForegroundWindow();
    if (!h) return 0;
    GetWindowThreadProcessId(h, &pid);
    return pid == GetCurrentProcessId();
}

void es3_input_poll(es3_input_t *out)
{
    static long coin_latch;
    static int had_coin, said;
    ES3_XInputGetState xi;
    int coin = 0;

    memset(out, 0, sizeof *out);
    if (input_off()) return;

    if (ours_in_front()) {
        #define DOWN_(k) ((GetAsyncKeyState(k) & 0x8000) != 0)
        if (DOWN_(VK_RETURN))                       out->start = 1;
        if (DOWN_(VK_LCONTROL) || DOWN_(VK_SPACE))  out->fire = 1;
        if (DOWN_('Z'))                             out->fire2 = 1;
        if (DOWN_(VK_UP))    { out->up = 1;    out->y =  32000; out->throttle = 255; }
        if (DOWN_(VK_DOWN))  { out->down = 1;  out->y = -32000; out->brake = 255; }
        if (DOWN_(VK_LEFT))  { out->left = 1;  out->x = -32000; }
        if (DOWN_(VK_RIGHT)) { out->right = 1; out->x =  32000; }
        if (DOWN_('S'))                             out->service = 1;
        if (DOWN_('T'))                             out->test = 1;
        if (DOWN_('5'))                             coin = 1;
        #undef DOWN_
    }

    xi = xinput_fn();
    if (xi) {
        ES3_XINPUT_STATE st;
        memset(&st, 0, sizeof st);
        if (xi(0, &st) == 0) {
            WORD b = st.Gamepad.wButtons;
            if (b & 0x0010) out->start = 1;      /* Start */
            if (b & 0x0020) out->service = 1;    /* Back  */
            if (b & 0x1000) out->fire = 1;       /* A     */
            if (b & 0x2000) out->fire2 = 1;      /* B     */
            if (b & 0x0001) out->up = 1;
            if (b & 0x0002) out->down = 1;
            if (b & 0x0004) out->left = 1;
            if (b & 0x0008) out->right = 1;
            if (b & 0x0040) coin = 1;            /* left stick click  */
            if (b & 0x0080) coin = 1;            /* right stick click */
            if (st.Gamepad.bRightTrigger > 30) out->throttle = st.Gamepad.bRightTrigger;
            if (st.Gamepad.bLeftTrigger  > 30) out->brake    = st.Gamepad.bLeftTrigger;
            /* A stick beats the arrow keys only when it is actually pushed: a
             * resting stick reads a few hundred either way. */
            if (st.Gamepad.sThumbLX > 8000 || st.Gamepad.sThumbLX < -8000)
                out->x = st.Gamepad.sThumbLX;
            if (st.Gamepad.sThumbLY > 8000 || st.Gamepad.sThumbLY < -8000)
                out->y = st.Gamepad.sThumbLY;
            if (!said) {
                said = 1;
                fprintf(stderr, "[input] an Xbox pad is connected and is "
                                "driving the stick and the buttons\n");
            }
        }
    }

    out->any = out->start | out->fire | out->fire2 |
               out->up | out->down | out->left | out->right;

    /* One edge per insertion, latched so a caller polling at frame rate sees
     * it exactly once however fast it polls. */
    if (coin && !had_coin) InterlockedIncrement(&coin_latch);
    had_coin = coin;
    if (InterlockedExchange(&coin_latch, 0)) out->coin = 1;
}
