/*
 * card.c - the IC card reader, as a side-car.
 *
 * Namco cabinets of this generation read their player cards with an NXP PN53x
 * NFC controller hanging off a serial port, and the card itself is an ordinary
 * MIFARE Classic 1K. Both halves of that are worth having in the shared
 * runtime rather than in one game: the same chip and the same card turn up
 * across the Namco arcade line, so anything that speaks this protocol once can
 * present a card to any of them.
 *
 * What the wire looks like was not guessed. The JConfig tree ships an I/O
 * emulator, JVSEmuMK.DLL, which answers this port badly, and ES3_TRACE_CARD
 * recorded the whole conversation it has with the game:
 *
 *   D4 4A 01 00                            InListPassiveTarget, 106k type A
 *   D5 4B 01 01 0004 08 04 3E86D02D        one target, SAK 08 = MIFARE 1K
 *   D4 40 01 60 03 6090D00632F5 3E86D02D   authenticate key A against block 3
 *   D5 41 00                               accepted
 *   D4 40 01 30 00                         read block 0
 *   D5 41 00                               status, and no data at all
 *
 * That last line is the bug this file exists to fix. A MIFARE read answers
 * with a status byte AND the sixteen bytes of the block; the emulator sends
 * the status alone, so the game reads a card full of nothing and puts up "this
 * card could not be recognized" every single boot.
 *
 * So: claim the port before the emulator sees it, speak PN53x properly, and
 * back the card with a file on disk. The file is the card - it persists, it
 * can be copied, and a player can have as many as they have files.
 *
 * ES3_CARD        1 to switch the side-car on (off until it has been proven)
 * ES3_CARD_PORT   which COM the reader is on (default 4; jvs.c has COM1)
 * ES3_CARD_FILE   the card image (default es3_card.bin beside the executable)
 * ES3_CARD_UID    four hex bytes, the card's UID (default 3E86D02D)
 * ES3_CARD_ALWAYS leave the card on the reader instead of tapping it
 * ES3_TRACE_CARD  every frame, decoded
 *
 * The card is tapped on with C, or Y on the pad - see card_in_field().
 */

#include "es3_rt.h"

#ifdef _WIN32

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ card - */

#define CARD_BYTES   1024            /* MIFARE Classic 1K */
#define BLOCK_BYTES  16
#define BLOCKS       (CARD_BYTES / BLOCK_BYTES)

/* Sector 0's key A, read straight off the wire above. A real reader proves it
 * knows the card by presenting this; this one accepts whatever it is given,
 * but a card image that carries the right key in its trailers is a card that
 * a real reader could also read, and that seems worth keeping true. */
static const unsigned char NAMCO_KEY_A[6] =
    { 0x60, 0x90, 0xD0, 0x06, 0x32, 0xF5 };

static unsigned char g_card[CARD_BYTES];
static unsigned char g_uid[4] = { 0x3E, 0x86, 0xD0, 0x2D };
static char g_card_path[MAX_PATH];
static int  g_card_dirty;
static int  g_n_reads, g_n_writes;   /* what the window counts */

/*
 * Whether a card is on the reader right now, which is a thing a player does
 * and not a thing a cabinet is configured with.
 *
 * Measured, not assumed: with a card permanently in the field the game reads
 * it once during the reader's power-on test and then never polls again, while
 * an empty reader is polled continuously - 7349 times in the same two and a
 * half minutes. The continuous poll is the machine waiting for a player, so
 * an empty reader is the resting state and a card is an event.
 *
 * So the card is tapped on: pressing the key puts it in the field for a
 * couple of seconds, which is how long a hand holds one against the panel,
 * and holding the key keeps it there.
 */
#define CARD_DWELL_MS 2000
static ULONGLONG g_present_until;
static int card_trace(void);

/*
 * ES3_CARD_ALWAYS is for tests, and it does not behave like a cabinet.
 *
 * A card that is already in the field when the reader runs its power-on test
 * is read there, and the game then judges it at boot - so an unrecognised
 * card is rejected before a player has touched anything, and because the game
 * stops polling once it has found a card, the tap at the prompt never
 * happens. That is an artefact of the flag, not of the reader. It stays
 * because a scripted run has no hands, but it says so once.
 */
static int card_always(void)
{
    static int on = -1;
    if (on < 0) {
        on = getenv("ES3_CARD_ALWAYS") != NULL;
        if (on)
            fprintf(stderr, "[card] ES3_CARD_ALWAYS: the card is glued to the "
                            "reader, so the game reads it during its power-on "
                            "test and never polls again. A cabinet does not "
                            "behave this way - tap the card instead.\n");
    }
    return on;
}

static int card_in_field(void)
{
    if (card_always()) return 1;
    return GetTickCount64() < g_present_until;
}

/* Called from the input poll when the tap button goes down, and from this
 * file for the keyboard. Extending rather than setting means holding the
 * button holds the card on the reader. */
void es3_card_tap(void)
{
    int was = card_in_field();
    g_present_until = GetTickCount64() + CARD_DWELL_MS;
    if (!was && card_trace())
        fprintf(stderr, "[card] card tapped on the reader\n");
}

/* What the side-car window shows. Copied out under no lock because every
 * field is written by one thread and read for display: a torn read here costs
 * one stale frame in a web page, and a lock around the card would be held
 * across the game's reads. */
void es3_card_state(unsigned char uid[4], int *present, int *reads, int *writes,
                    unsigned char *image1k)
{
    if (uid) memcpy(uid, g_uid, 4);
    if (present) *present = card_in_field();
    if (reads) *reads = g_n_reads;
    if (writes) *writes = g_n_writes;
    if (image1k) memcpy(image1k, g_card, CARD_BYTES);
}

const char *es3_card_file(void)
{
    return g_card_path;
}

static int card_off(void)
{
    static int off = -1;
    if (off < 0) off = getenv("ES3_CARD") == NULL;
    return off;
}

static int card_trace(void)
{
    static int on = -1;
    if (on < 0) on = getenv("ES3_TRACE_CARD") != NULL;
    return on;
}

static int hexnib(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* A blank card that is nonetheless a valid one: the manufacturer block agrees
 * with the UID the reader will announce, and every sector trailer carries the
 * key the game authenticates with. The rest is zero, which is what a card
 * fresh out of the box holds - if the game wants to register it, it has room
 * to, and the writes land in the file. */
static void card_format(void)
{
    int s;

    memset(g_card, 0, sizeof g_card);

    memcpy(g_card, g_uid, 4);
    g_card[4] = (unsigned char)(g_uid[0] ^ g_uid[1] ^ g_uid[2] ^ g_uid[3]);
    g_card[5] = 0x08;                /* SAK: MIFARE Classic 1K */
    g_card[6] = 0x04;                /* ATQA, as stored in block 0 */
    g_card[7] = 0x00;

    for (s = 0; s < 16; s++) {
        unsigned char *t = g_card + (s * 4 + 3) * BLOCK_BYTES;
        memcpy(t, NAMCO_KEY_A, 6);
        t[6] = 0xFF; t[7] = 0x07; t[8] = 0x80; t[9] = 0x69;
        memset(t + 10, 0xFF, 6);     /* key B */
    }
}

static void card_save(void);

static void card_load(void)
{
    const char *env = getenv("ES3_CARD_FILE");
    FILE *f;

    {
        const char *hex = getenv("ES3_CARD_UID");
        if (hex) {
            int i;
            for (i = 0; i < 4; i++) {
                int hi = hexnib(hex[i * 2]), lo = hexnib(hex[i * 2 + 1]);
                if (hi < 0 || lo < 0) break;
                g_uid[i] = (unsigned char)(hi * 16 + lo);
            }
        }
    }

    if (env && *env) {
        strncpy(g_card_path, env, sizeof g_card_path - 1);
    } else {
        strncpy(g_card_path, "es3_card.bin", sizeof g_card_path - 1);
    }
    g_card_path[sizeof g_card_path - 1] = 0;

    f = fopen(g_card_path, "rb");
    if (f) {
        size_t got = fread(g_card, 1, sizeof g_card, f);
        fclose(f);
        if (got == sizeof g_card) {
            /* The image owns the UID - a card is its number, and a card that
             * changed identity between boots is a different card. */
            memcpy(g_uid, g_card, 4);
            fprintf(stderr, "[card] %s: %02X%02X%02X%02X\n", g_card_path,
                    g_uid[0], g_uid[1], g_uid[2], g_uid[3]);
            return;
        }
        fprintf(stderr, "[card] %s is %u bytes, not %u - starting a new one\n",
                g_card_path, (unsigned)got, (unsigned)sizeof g_card);
    }

    card_format();
    g_card_dirty = 1;
    /* Written at once rather than waiting for the game to change something:
     * the file is the card, and a card that only exists once it has been
     * written to is one the player cannot find, copy or keep. */
    card_save();
    fprintf(stderr, "[card] new blank card %02X%02X%02X%02X in %s\n",
            g_uid[0], g_uid[1], g_uid[2], g_uid[3], g_card_path);
}

/* Written back as it changes rather than at exit: an arcade cabinet is turned
 * off at the wall, and this one is closed with a window button. */
static void card_save(void)
{
    FILE *f;
    if (!g_card_dirty) return;
    f = fopen(g_card_path, "wb");
    if (!f) return;
    fwrite(g_card, 1, sizeof g_card, f);
    fclose(f);
    g_card_dirty = 0;
}

/* ------------------------------------------------------------------- port - */

#define FIFO 4096

typedef struct {
    HANDLE handle;
    unsigned char out[FIFO];
    unsigned out_head, out_tail;
    unsigned char in[FIFO];
    unsigned in_len;
    int       read_pending;
    uint32_t  read_buf, read_len, read_ovl, read_routine;
    HANDLE    read_thread;
    ULONGLONG read_deadline;
    CRITICAL_SECTION lock;
} CardPort;

static CardPort g_p;
static int g_ready;

static void out_push(unsigned char b)
{
    unsigned n = (g_p.out_tail + 1) % FIFO;
    if (n == g_p.out_head) return;
    g_p.out[g_p.out_tail] = b;
    g_p.out_tail = n;
}

static unsigned out_avail(void)
{
    return (g_p.out_tail - g_p.out_head + FIFO) % FIFO;
}

static unsigned out_take(unsigned char *dst, unsigned n)
{
    unsigned got = 0;
    while (got < n && g_p.out_head != g_p.out_tail) {
        dst[got++] = g_p.out[g_p.out_head];
        g_p.out_head = (g_p.out_head + 1) % FIFO;
    }
    return got;
}

static void hexline(const char *tag, const unsigned char *p, unsigned n)
{
    unsigned i;
    fprintf(stderr, "[card] %s %u:", tag, n);
    for (i = 0; i < n && i < 48; i++) fprintf(stderr, " %02X", p[i]);
    if (n > 48) fprintf(stderr, " ...");
    fputc('\n', stderr);
    fflush(stderr);
}

/* A normal information frame: preamble, start, length and its checksum, the
 * payload beginning with the direction byte, the data checksum, postamble. */
static void send_frame(const unsigned char *body, unsigned n)
{
    unsigned i;
    unsigned char sum = 0;

    out_push(0x00); out_push(0x00); out_push(0xFF);
    out_push((unsigned char)n);
    out_push((unsigned char)(0x100 - n));
    for (i = 0; i < n; i++) { out_push(body[i]); sum = (unsigned char)(sum + body[i]); }
    out_push((unsigned char)(0x100 - sum));
    out_push(0x00);

    if (card_trace()) hexline("->", body, n);
}

/* ---------------------------------------------------------------- PN53x - */

/* Which sector the game last authenticated against. MIFARE only lets a reader
 * touch a sector it has authenticated, and a card that forgets this would
 * answer reads the real one would refuse - a difference the game could see. */
static int g_auth_sector = -1;

static void mifare(const unsigned char *p, unsigned n, unsigned char *r,
                   unsigned *rn)
{
    unsigned char cmd = n ? p[0] : 0;
    unsigned char blk = n > 1 ? p[1] : 0;

    r[0] = 0xD5; r[1] = 0x41;
    *rn = 3;
    r[2] = 0x00;                                   /* success */

    if (!card_in_field()) { r[2] = 0x01; return; }     /* timeout: nothing there */

    switch (cmd) {
    case 0x60:                                     /* authenticate, key A */
    case 0x61:                                     /* authenticate, key B */
        if (blk / 4 >= 16) { r[2] = 0x14; break; }
        g_auth_sector = blk / 4;
        if (card_trace())
            fprintf(stderr, "[card] auth key %c, sector %d\n",
                    cmd == 0x60 ? 'A' : 'B', g_auth_sector);
        break;

    case 0x30:                                     /* read one block */
        if (blk >= BLOCKS) { r[2] = 0x14; break; }
        if (g_auth_sector != blk / 4) { r[2] = 0x14; break; }
        memcpy(r + 3, g_card + blk * BLOCK_BYTES, BLOCK_BYTES);
        *rn = 3 + BLOCK_BYTES;
        g_n_reads++;
        if (card_trace())
            fprintf(stderr, "[card] read block %u\n", blk);
        break;

    case 0xA0:                                     /* write one block */
        if (blk >= BLOCKS || n < 2 + BLOCK_BYTES) { r[2] = 0x14; break; }
        if (g_auth_sector != blk / 4) { r[2] = 0x14; break; }
        if (blk == 0) break;                       /* block 0 is read-only */
        memcpy(g_card + blk * BLOCK_BYTES, p + 2, BLOCK_BYTES);
        g_card_dirty = 1;
        g_n_writes++;
        card_save();
        if (card_trace())
            fprintf(stderr, "[card] wrote block %u\n", blk);
        break;

    default:
        /* Increment, decrement, restore, transfer - value-block operations
         * this game has never been seen to use. Refusing is honest and the
         * trace will say so if one ever turns up. */
        r[2] = 0x14;
        if (card_trace())
            fprintf(stderr, "[card] refused MIFARE command %02X\n", cmd);
        break;
    }
}

/*
 * One command from the host.
 *
 * Where the answer only has to be well formed, it mirrors what JVSEmuMK sent -
 * those bytes are known to get the game as far as reading a card, and a reader
 * that differs from a working one in ways nobody has a reason for is a reader
 * that will be blamed for the next unrelated bug. Where its answer was wrong,
 * this follows the PN53x manual instead, and says so.
 */
static void command(const unsigned char *p, unsigned n)
{
    unsigned char r[64];
    unsigned rn = 0;
    unsigned char cmd = n > 1 ? p[1] : 0;

    switch (cmd) {
    case 0x02:                                     /* GetFirmwareVersion */
        r[0] = 0xD5; r[1] = 0x03;
        r[2] = 0x32; r[3] = 0x01; r[4] = 0x06; r[5] = 0x07;
        rn = 6;
        break;

    case 0x06: {                                   /* ReadRegister */
        /* One byte back per register asked for. The values are the ones the
         * emulator gave, which the game accepted; these are PN53x
         * configuration registers and nothing here depends on them. */
        static const unsigned char pat[4] = { 0x77, 0x1C, 0x11, 0xF1 };
        unsigned regs = (n - 2) / 2, i;
        r[0] = 0xD5; r[1] = 0x07;
        for (i = 0; i < regs && i < sizeof r - 2; i++) r[2 + i] = pat[i % 4];
        rn = 2 + i;
        break;
    }

    case 0x08:                                     /* WriteRegister */
        r[0] = 0xD5; r[1] = 0x09; r[2] = 0x00;
        rn = 3;
        break;

    case 0x0C:                                     /* ReadGPIO */
        r[0] = 0xD5; r[1] = 0x0D;
        r[2] = 0x3F; r[3] = 0x01; r[4] = 0x03;
        rn = 5;
        break;

    case 0x0E:                                     /* WriteGPIO */
        /* The emulator answers this one with an error frame, every time. The
         * GPIO lines on a reader board drive its lamps, so the game has been
         * failing to light the reader since before any of this was written. */
        r[0] = 0xD5; r[1] = 0x0F;
        rn = 2;
        break;

    case 0x12:                                     /* SetParameters */
        r[0] = 0xD5; r[1] = 0x13;
        rn = 2;
        break;

    case 0x14:                                     /* SAMConfiguration */
        r[0] = 0xD5; r[1] = 0x15;
        rn = 2;
        break;

    case 0x18:
        /* Not a command in the PN53x manual. The emulator answers it with a
         * bare D5 19 and the game carries on, so this answers the same.
         *
         * Worth spelling out because the first attempt got it wrong: the frame
         * on the wire is 00 00 FF 02 FE D5 19 12 00, and the 12 at the end is
         * the data checksum, not a status byte - the length field says two.
         * Sending it as payload makes a ten byte frame where the game expects
         * nine, and the game simply stops talking. */
        r[0] = 0xD5; r[1] = 0x19;
        rn = 2;
        break;

    case 0x32:                                     /* RFConfiguration */
        r[0] = 0xD5; r[1] = 0x33;
        rn = 2;
        break;

    case 0x4A:                                     /* InListPassiveTarget */
        r[0] = 0xD5; r[1] = 0x4B;
        if (!card_in_field()) {
            r[2] = 0x00;                           /* no targets in the field */
            rn = 3;
        } else {
            r[2] = 0x01;                           /* one target */
            r[3] = 0x01;                           /* its number */
            r[4] = 0x00; r[5] = 0x04;              /* SENS_RES */
            r[6] = 0x08;                           /* SEL_RES: MIFARE 1K */
            r[7] = 0x04;                           /* UID length */
            memcpy(r + 8, g_uid, 4);
            rn = 12;
            g_auth_sector = -1;                    /* a fresh select */
        }
        break;

    case 0x40:                                     /* InDataExchange */
        /* p[2] is the target number; the rest is for the card itself. */
        mifare(p + 3, n > 3 ? n - 3 : 0, r, &rn);
        break;

    case 0x44:                                     /* InCommunicateThru */
        mifare(p + 2, n > 2 ? n - 2 : 0, r, &rn);
        r[1] = 0x45;
        break;

    case 0x52:                                     /* InRelease */
        r[0] = 0xD5; r[1] = 0x53; r[2] = 0x01; r[3] = 0x00;
        rn = 4;
        g_auth_sector = -1;
        break;

    default:
        /* Syntax error frame, which is what a real chip sends for a command
         * it does not know. */
        r[0] = 0x7F; r[1] = (unsigned char)(cmd + 1);
        rn = 2;
        if (card_trace())
            fprintf(stderr, "[card] unknown command %02X\n", cmd);
        break;
    }

    if (rn) send_frame(r, rn);
}

/* Pull whole frames out of whatever has arrived. The host prefixes a wake-up
 * byte and sends bare ACKs to cancel, so anything that is not a frame start is
 * skipped rather than treated as an error. */
static void consume(void)
{
    unsigned i = 0;

    while (i + 5 <= g_p.in_len) {
        unsigned len, lcs, need;

        if (!(g_p.in[i] == 0x00 && g_p.in[i + 1] == 0x00 &&
              g_p.in[i + 2] == 0xFF)) { i++; continue; }

        len = g_p.in[i + 3];
        lcs = g_p.in[i + 4];

        if (len == 0x00 && lcs == 0xFF) {          /* ACK */
            i += 6 <= g_p.in_len - i ? 6 : 5;
            continue;
        }
        if (len == 0xFF && lcs == 0x00) {          /* NACK */
            i += 6 <= g_p.in_len - i ? 6 : 5;
            continue;
        }
        if (((len + lcs) & 0xFF) != 0) { i++; continue; }

        need = 5 + len + 2;                        /* + DCS + postamble */
        if (i + need > g_p.in_len) break;          /* wait for the rest */

        if (card_trace()) hexline("<-", g_p.in + i + 5, len);
        command(g_p.in + i + 5, len);
        i += need;
    }

    if (i) {
        memmove(g_p.in, g_p.in + i, g_p.in_len - i);
        g_p.in_len -= i;
    }
}

/* --------------------------------------------------------- overlapped io - */

typedef struct { uint32_t routine, err, bytes, ovl; } Completion;

static void CALLBACK deliver(ULONG_PTR up)
{
    Completion *c = (Completion *)up;
    void(__stdcall * fn)(DWORD, DWORD, void *);
    if (!c) return;
    /* Already a thunk standing for the guest's routine, so it is callable. */
    fn = (void(__stdcall *)(DWORD, DWORD, void *))(uintptr_t)c->routine;
    fn((DWORD)c->err, (DWORD)c->bytes, (void *)(uintptr_t)c->ovl);
    free(c);
}

static void finish_read(void)
{
    uint32_t want;
    unsigned got;

    if (!g_p.read_pending) return;
    want = g_p.read_len;
    if (out_avail() < want) {
        if (!g_p.read_deadline || GetTickCount64() < g_p.read_deadline) return;
        want = out_avail();                        /* short read on timeout */
    }

    got = out_take((unsigned char *)(uintptr_t)g_p.read_buf, want);
    g_p.read_pending = 0;

    if (g_p.read_ovl) {
        wr32(g_p.read_ovl, 0);
        wr32(g_p.read_ovl + 4, got);
    }
    if (g_p.read_routine && g_p.read_thread) {
        Completion *c = (Completion *)malloc(sizeof *c);
        if (c) {
            c->routine = g_p.read_routine;
            c->err = 0;
            c->bytes = got;
            c->ovl = g_p.read_ovl;
            if (!QueueUserAPC(deliver, g_p.read_thread, (ULONG_PTR)c)) free(c);
        }
    }
}

static DWORD WINAPI ticker(void *unused)
{
    (void)unused;
    for (;;) {
        Sleep(2);
        EnterCriticalSection(&g_p.lock);
        finish_read();
        LeaveCriticalSection(&g_p.lock);
    }
}

/* --------------------------------------------------------------- the api - */

int es3_card_is_port(uint32_t h)
{
    return g_ready && h && (HANDLE)(uintptr_t)h == g_p.handle;
}

uint32_t es3_card_open(const char *name)
{
    const char *p = name;
    int n;

    if (card_off() || !name) return 0;
    if (p[0] == '\\' && p[1] == '\\' && p[2] == '.' && p[3] == '\\') p += 4;
    if (!((p[0] == 'C' || p[0] == 'c') && (p[1] == 'O' || p[1] == 'o') &&
          (p[2] == 'M' || p[2] == 'm') && p[3] >= '0' && p[3] <= '9'))
        return 0;

    n = p[3] - '0';
    if (p[4] >= '0' && p[4] <= '9') n = n * 10 + (p[4] - '0');
    {
        const char *want = getenv("ES3_CARD_PORT");
        if (n != (want ? atoi(want) : 4)) return 0;
    }

    if (!g_ready) {
        InitializeCriticalSection(&g_p.lock);
        g_p.handle = CreateEventW(NULL, TRUE, FALSE, NULL);
        card_load();
        {
            HANDLE t = CreateThread(NULL, 0, ticker, NULL, 0, NULL);
            if (t) CloseHandle(t);
        }
        g_ready = 1;
        /* Started here rather than at startup so the window appears with the
         * reader it belongs to, and never on a run that has no card in it. */
        es3_passport_start();
        fprintf(stderr,
            "\n[card] the game opened %s, where the IC card reader would be.\n"
            "       This runtime is one: an NXP PN53x, with a MIFARE Classic 1K\n"
            "       card in %s. The reader is empty until the card is\n"
            "       tapped on it - C on the keyboard, Y on the pad.\n"
            "       ES3_CARD_ALWAYS to leave it there, ES3_TRACE_CARD to "
            "watch the frames.\n\n",
            name, g_card_path);
        fflush(stderr);
    }
    return (uint32_t)(uintptr_t)g_p.handle;
}

int es3_card_write(uint32_t buf, uint32_t n)
{
    const unsigned char *p = (const unsigned char *)(uintptr_t)buf;
    if (card_trace()) fprintf(stderr, "[card] write %u\n", n);
    EnterCriticalSection(&g_p.lock);
    if (n > FIFO - g_p.in_len) n = FIFO - g_p.in_len;
    memcpy(g_p.in + g_p.in_len, p, n);
    g_p.in_len += n;
    consume();
    finish_read();
    LeaveCriticalSection(&g_p.lock);
    return 1;
}

uint32_t es3_card_read(uint32_t buf, uint32_t n)
{
    uint32_t got;
    EnterCriticalSection(&g_p.lock);
    got = out_take((unsigned char *)(uintptr_t)buf, n);
    LeaveCriticalSection(&g_p.lock);
    if (card_trace())
        fprintf(stderr, "[card] blocking read of %u gave %u\n", n, got);
    return got;
}

void es3_card_post_read(uint32_t buf, uint32_t n, uint32_t ovl,
                        uint32_t routine)
{
    EnterCriticalSection(&g_p.lock);
    if (g_p.read_thread) CloseHandle(g_p.read_thread);
    g_p.read_thread = NULL;
    DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                    GetCurrentProcess(), &g_p.read_thread,
                    0, FALSE, DUPLICATE_SAME_ACCESS);
    g_p.read_pending = 1;
    g_p.read_buf = buf;
    g_p.read_len = n;
    g_p.read_ovl = ovl;
    g_p.read_routine = routine;
    g_p.read_deadline = GetTickCount64() + 100;
    if (card_trace())
        fprintf(stderr, "[card] read posted: %u into %08X, routine %08X "
                        "(%u waiting)\n", n, buf, routine, out_avail());
    finish_read();
    LeaveCriticalSection(&g_p.lock);
}

void es3_card_complete_write(uint32_t ovl, uint32_t bytes, uint32_t routine)
{
    Completion *c;
    HANDLE self = NULL;

    if (!routine) return;
    c = (Completion *)malloc(sizeof *c);
    if (!c) return;
    c->routine = routine;
    c->err = 0;
    c->bytes = bytes;
    c->ovl = ovl;
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                         GetCurrentProcess(), &self, 0, FALSE,
                         DUPLICATE_SAME_ACCESS)) { free(c); return; }
    if (!QueueUserAPC(deliver, self, (ULONG_PTR)c)) free(c);
    CloseHandle(self);
}

void es3_card_cancel(void)
{
    EnterCriticalSection(&g_p.lock);
    g_p.read_pending = 0;
    LeaveCriticalSection(&g_p.lock);
}

#else
void es3_card_tap(void) {}
void es3_card_state(unsigned char u[4], int *p, int *r, int *w, unsigned char *i)
{ (void)u; (void)p; (void)r; (void)w; (void)i; }
const char *es3_card_file(void) { return ""; }
int es3_card_is_port(uint32_t h) { (void)h; return 0; }
uint32_t es3_card_open(const char *n) { (void)n; return 0; }
int es3_card_write(uint32_t b, uint32_t n) { (void)b; (void)n; return 0; }
uint32_t es3_card_read(uint32_t b, uint32_t n) { (void)b; (void)n; return 0; }
void es3_card_post_read(uint32_t b, uint32_t n, uint32_t o, uint32_t r)
{ (void)b; (void)n; (void)o; (void)r; }
void es3_card_complete_write(uint32_t o, uint32_t b, uint32_t r)
{ (void)o; (void)b; (void)r; }
void es3_card_cancel(void) {}
#endif
