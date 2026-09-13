/*
 * hle_board.c - the parts of the cabinet that are not a PC.
 *
 * hle_native.c forwards almost the whole import table to the host's own copy
 * of the DLL, because almost the whole import table is Windows. What is left
 * is the arcade machine, and it is the actual work of an ES3 port:
 *
 *   JVSEmuMK.dll / DeviceIoControl   The JVS I/O board. Coins, the start
 *                                    button, the steering wheel, the pedals,
 *                                    the item switch, the service menu. On a
 *                                    real cabinet these arrive over USB to a
 *                                    Namco I/O board; a JConfig tree replaces
 *                                    it with a DLL that reads DirectInput and
 *                                    XInput, which is a much better starting
 *                                    point than the original.
 *   bngrw.dll                        The Bandai Namco card reader/writer. The
 *                                    game writes a player's progress to a
 *                                    magnetic card and reads it back.
 *   Nbam_QR_Code.dll                 Encodes the QR code printed on the card
 *                                    at the end of a session.
 *   eOkao*.dll                       OMRON's OKAO Vision SDK: face detection,
 *                                    facial parts, age and gender estimation.
 *                                    This is the camera in the cabinet roof
 *                                    that photographs the player and puts
 *                                    their face on their kart. Imported purely
 *                                    by ordinal - and those DLLs exist nowhere
 *                                    but in the game tree, which is why
 *                                    pcrecomp's stdcall_argc.py learned to
 *                                    read an argument count out of a DLL's own
 *                                    code.
 *   AMCUS / Mucha / ALL.Net          Network authentication, over WINHTTP and
 *                                    WS2_32 to servers that are gone. The
 *                                    imports themselves are stock Windows, so
 *                                    hle_native.c forwards them and they fail
 *                                    the way an unplugged cabinet failed.
 *
 * **Nothing is bound here yet, and that is on purpose.** Every one of these
 * needs behaviour observed from a title, not invented: the JVS report layout,
 * what the card reader returns for an empty slot, what OKAO_DT_GetResult fills
 * in. A stub that returns 0 would let the game past the call and break it
 * somewhere else an hour later. So each one aborts naming itself the first
 * time the game asks, which is the whole to-do list in the order the game
 * wants it - and the only order worth doing it in.
 *
 * What this file does provide is the names: hle.c's abort message says which
 * DLL an import came from, and hle_board_note() says what that DLL *is*, so
 * the first run reads as "this is the camera" rather than "ordinal_302".
 */

#include <stdio.h>
#include <string.h>

#include "es3_rt.h"

/* Windows spells it _stricmp and POSIX strcasecmp; a DLL name comparison is
 * three lines of its own rather than an #ifdef in two places. */
static int eq_nocase(const char *a, const char *b)
{
    for (; *a && *b; a++, b++) {
        int ca = *a >= 'A' && *a <= 'Z' ? *a + 32 : *a;
        int cb = *b >= 'A' && *b <= 'Z' ? *b + 32 : *b;
        if (ca != cb) return 0;
    }
    return *a == *b;
}

static const struct { const char *dll; const char *what; } BOARD[] = {
    { "JVSEmuMK.dll",     "JVS I/O - coins, wheel, pedals, buttons" },
    { "JVSEmu.dll",       "JVS I/O - coins, wheel, pedals, buttons" },
    { "bngrw.dll",        "Bandai Namco card reader/writer" },
    { "Nbam_QR_Code.dll", "QR code encoder for the player's card" },
    { "eOkaoCo.dll",      "OMRON OKAO Vision - common" },
    { "eOkaoDt.dll",      "OMRON OKAO Vision - face detection" },
    { "eOkaoPt.dll",      "OMRON OKAO Vision - facial parts" },
    { "eOkaoAg.dll",      "OMRON OKAO Vision - age estimation" },
    { "eOkaoGn.dll",      "OMRON OKAO Vision - gender estimation" },
    { "eOkaoSm.dll",      "OMRON OKAO Vision - smile estimation" },
    { "eOkaoPc.dll",      "OMRON OKAO Vision - face contour" },
    { "ipccl.dll",        "IPC client (managed) - talks to the ShareK service" },
    { "iauthdll.dll",     "AMCUS authentication" },
};

const char *hle_board_note(const char *dll)
{
    unsigned i;
    for (i = 0; i < sizeof BOARD / sizeof BOARD[0]; i++)
        if (eq_nocase(BOARD[i].dll, dll)) return BOARD[i].what;
    return NULL;
}

void hle_register_board(void)
{
    /* Deliberately empty - see the top of this file. What it does instead is
     * report what is still missing, grouped by DLL, so the size and shape of
     * the remaining work is visible before the game is even started rather
     * than one abort at a time. */
    unsigned i;
    const char *seen[32];
    unsigned nseen = 0;

    for (i = 0; i < HLE_COUNT; i++) {
        const char *dll, *what;
        unsigned j;
        if (g_hle_handlers[i]) continue;
        dll = hle_dll((HleId)i);
        for (j = 0; j < nseen; j++)
            if (eq_nocase(seen[j], dll)) break;
        if (j < nseen) continue;
        if (nseen < sizeof seen / sizeof seen[0]) seen[nseen++] = dll;
        what = hle_board_note(dll);
        fprintf(stderr, "[board] %-20s unimplemented%s%s\n", dll,
                what ? "  <- " : "", what ? what : "");
    }
}
