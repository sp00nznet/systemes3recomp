/*
 * jvs.c - the I/O board, which is the half of a cabinet a desktop does not have.
 *
 * A System ES3 game talks to its I/O over a serial link: coins, the wheel, the
 * pedals, the item button, and the service and test switches all arrive as JVS
 * packets on COM1 at 19200 8N1. Mario Kart Arcade GP DX opens that port during
 * boot, posts an overlapped three-byte read - a JVS packet header - and waits.
 *
 * On a desktop nothing answers, and the game does not care that nothing
 * answers: it keeps running its frame loop, presenting about twenty empty
 * frames a second, with a scene it never builds because the boot state machine
 * is still waiting for the board. Refusing the port outright does not help
 * either - a failed open is not what it is waiting for. It wants a board.
 *
 * So this is one. Not a stub that returns zero and lets the game past the call
 * to break somewhere else an hour later: a JVS I/O node that answers the
 * protocol - resets, takes an address, identifies itself, declares its
 * features, and reports switches, coins and analog channels every frame with
 * nothing pressed and the wheel centred.
 *
 * THE PROTOCOL, because the packets are the interface and nothing else is:
 *
 *   E0 <dest> <size> <data...> <sum>       master -> node
 *   E0 00     <size> <status> <report...> <sum>   node -> master
 *
 *   size counts everything after itself INCLUDING the checksum; sum is the
 *   bytes from dest up to but not including sum, modulo 256. D0 escapes: the
 *   byte after it is one less than the byte meant, so E0 travels as D0 DF and
 *   D0 as D0 CF. Only SYNC is ever unescaped.
 *
 *   status 1 is a packet understood; each command's reply starts with report 1
 *   for a command that worked.
 *
 * The asynchronous side matters as much as the protocol. The game uses
 * ReadFileEx and WriteFileEx with completion routines and waits alertably, so
 * a reply is not "put bytes in a buffer" - it is "deliver an APC to the thread
 * that asked, which calls a routine inside the guest". The routine is a guest
 * address, so it goes through a thunk like any other callback.
 *
 * ES3_NO_JVS turns the whole thing off and leaves the real port alone, which
 * is how you tell a board that answers wrongly from no board at all.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "es3_rt.h"

#define JVS_SYNC   0xE0
#define JVS_ESCAPE 0xD0
#define JVS_BROADCAST 0xFF

/* What this node says it is.
 *
 * Namco's own boards answer with a maker, a board name, a version and a note,
 * separated by semicolons and terminated by a nul. The game logs it and, as
 * far as anything here can tell, does not parse it - but a plausible one costs
 * nothing and an implausible one would be the first thing to suspect. */
static const char JVS_IDENT[] =
    "namco ltd.;I/O PCB-4072;ver1.00;JPN,Multipurpose + Rotary Encoder";

/* Two players, thirteen switch bits each, three coin slots, eight analog
 * channels of sixteen bits - a kart cabinet: wheel, accelerator, brake. The
 * feature list is what the game sizes its own polling by, so these numbers
 * decide the shape of every SWINP and ADREAD reply after them. */
#define JVS_PLAYERS   2
#define JVS_SW_BYTES  2          /* 13 bits rounds up to two bytes */
#define JVS_COIN_SLOTS 3
#define JVS_ANALOG    8

#define FIFO_SIZE 4096

/* What the cabinet's switches are holding right now - see ES3_JVS_SEQ. */
static uint32_t g_sw_sys, g_sw_p1, g_sw_p2;

/* And what a keyboard or an Xbox pad is holding - see input_poll(), which is
 * where the mapping is written down. Kept apart from the sequencer's bits so
 * the two can be OR-ed rather than one erasing the other. */
static uint32_t g_in_sys, g_in_p1;
static uint32_t g_analog[8] = { 0x8000u, 0, 0, 0x8000u, 0x8000u, 0x8000u,
                                0x8000u, 0x8000u };

typedef struct {
    HANDLE handle;               /* the value the game holds as its COM port */
    unsigned char out[FIFO_SIZE];/* node -> game, waiting to be read */
    unsigned out_head, out_tail;
    unsigned char in[FIFO_SIZE]; /* game -> node, waiting for a full packet */
    unsigned in_len;
    unsigned char address;       /* 0 until the master assigns one */
    unsigned coin[JVS_COIN_SLOTS];
    /* One read may be posted at a time, which is all this game does. */
    int       read_pending;
    uint32_t  read_buf, read_len, read_ovl, read_routine;
    HANDLE    read_thread;
    ULONGLONG read_deadline;     /* 0 = wait for the bytes, however long */
    /* COMMTIMEOUTS as the game set it: interval, read multiplier, read
     * constant, write multiplier, write constant. */
    uint32_t  to_interval, to_rd_mult, to_rd_const;
    CRITICAL_SECTION lock;
} JvsPort;

static JvsPort g_port;
static int g_off = -1;
static int g_trace = -1;
static int g_ready;

static int jvs_off(void)
{
    if (g_off < 0) g_off = getenv("ES3_NO_JVS") != NULL;
    return g_off;
}

static int jvs_trace(void)
{
    if (g_trace < 0) g_trace = getenv("ES3_TRACE_JVS") != NULL;
    return g_trace;
}

static void hexline(const char *tag, const unsigned char *p, unsigned n)
{
    unsigned i;
    fprintf(stderr, "[jvs] %s", tag);
    for (i = 0; i < n && i < 48; i++) fprintf(stderr, " %02X", p[i]);
    if (n > 48) fprintf(stderr, " ...(%u)", n);
    fprintf(stderr, "\n");
}

/* ---- the byte pipe back to the game ---- */

static void out_push(unsigned char b)
{
    unsigned next = (g_port.out_tail + 1) % FIFO_SIZE;
    if (next == g_port.out_head) return;         /* full: drop, never block */
    g_port.out[g_port.out_tail] = b;
    g_port.out_tail = next;
}

static unsigned out_avail(void)
{
    return (g_port.out_tail + FIFO_SIZE - g_port.out_head) % FIFO_SIZE;
}

static unsigned out_take(unsigned char *dst, unsigned n)
{
    unsigned i;
    for (i = 0; i < n && g_port.out_head != g_port.out_tail; i++) {
        dst[i] = g_port.out[g_port.out_head];
        g_port.out_head = (g_port.out_head + 1) % FIFO_SIZE;
    }
    return i;
}

/* Escaped, because every byte of a reply except the leading SYNC has to be. */
static void out_byte(unsigned char b)
{
    if (b == JVS_SYNC || b == JVS_ESCAPE) {
        out_push(JVS_ESCAPE);
        out_push((unsigned char)(b - 1));
    } else {
        out_push(b);
    }
}

/* A whole reply: SYNC, "to the master", the length, the body, the sum. */
static void reply(const unsigned char *body, unsigned n)
{
    unsigned i, sum;
    if (n + 1 > 255) return;
    out_push(JVS_SYNC);
    sum = 0x00 + (n + 1);
    out_byte(0x00);                              /* destination: the master */
    out_byte((unsigned char)(n + 1));            /* body plus the checksum */
    for (i = 0; i < n; i++) { out_byte(body[i]); sum += body[i]; }
    out_byte((unsigned char)(sum & 0xFF));
    if (jvs_trace()) hexline("node ->", body, n);
}

/* ---- answering one packet ---- */

static void handle_packet(unsigned char dest, const unsigned char *data,
                          unsigned n)
{
    unsigned char body[256];
    unsigned len = 0, i = 0;

    if (jvs_trace()) {
        char tag[32];
        sprintf(tag, "game -> %02X:", dest);
        hexline(tag, data, n);
    }

    /* Only ours, or a broadcast. An unaddressed node answers nothing, which is
     * what keeps RESET from being replied to by everybody at once. */
    if (dest != JVS_BROADCAST && dest != g_port.address) return;

    body[len++] = 0x01;                          /* status: understood */

    while (i < n) {
        unsigned char cmd = data[i++];
        switch (cmd) {
        case 0xF0:                               /* RESET */
            i++;                                 /* the 0xD9 that confirms it */
            g_port.address = 0;
            if (jvs_trace()) fprintf(stderr, "[jvs] reset; address cleared\n");
            return;                              /* a reset is never answered */

        case 0xF1:                               /* SET ADDRESS */
            g_port.address = data[i++];
            body[len++] = 0x01;
            if (jvs_trace())
                fprintf(stderr, "[jvs] address %u\n", g_port.address);
            break;

        case 0x10:                               /* IOIDENT */
            body[len++] = 0x01;
            memcpy(body + len, JVS_IDENT, sizeof JVS_IDENT);
            len += (unsigned)sizeof JVS_IDENT;   /* includes the nul */
            break;

        case 0x11: body[len++] = 0x01; body[len++] = 0x13; break;  /* CMDREV */
        case 0x12: body[len++] = 0x01; body[len++] = 0x30; break;  /* JVSREV */
        case 0x13: body[len++] = 0x01; body[len++] = 0x10; break;  /* COMMVER */

        case 0x14:                               /* FEATCHK */
            body[len++] = 0x01;
            body[len++] = 0x01; body[len++] = JVS_PLAYERS;
            body[len++] = 13;   body[len++] = 0x00;   /* switches */
            body[len++] = 0x02; body[len++] = JVS_COIN_SLOTS;
            body[len++] = 0x00; body[len++] = 0x00;   /* coins */
            body[len++] = 0x03; body[len++] = JVS_ANALOG;
            body[len++] = 16;   body[len++] = 0x00;   /* analog */
            body[len++] = 0x12; body[len++] = 8;
            body[len++] = 0x00; body[len++] = 0x00;   /* general output */
            body[len++] = 0x00;                       /* end of the list */
            break;

        case 0x20: {                             /* SWINP: players, bytes */
            unsigned players = data[i++], bytes = data[i++], p, b;
            body[len++] = 0x01;
            /* The timetable's bits and the live ones, OR-ed: ES3_JVS_SEQ and a
             * pad in somebody's hands both work, and neither erases the other. */
            body[len++] = (unsigned char)(g_sw_sys | g_in_sys); /* TEST is here */
            for (p = 0; p < players; p++) {
                uint32_t w = p == 0 ? (g_sw_p1 | g_in_p1)
                           : p == 1 ? g_sw_p2 : 0;
                for (b = 0; b < bytes; b++)
                    body[len++] = (unsigned char)(w >> (8 * (bytes - 1 - b)));
            }
            break;
        }

        case 0x21: {                             /* COINP: slots */
            unsigned slots = data[i++], s;
            body[len++] = 0x01;
            for (s = 0; s < slots; s++) {
                unsigned c = s < JVS_COIN_SLOTS ? g_port.coin[s] : 0;
                body[len++] = (unsigned char)((c >> 8) & 0x3F);  /* cond 0 = ok */
                body[len++] = (unsigned char)(c & 0xFF);
            }
            break;
        }

        case 0x22: {                             /* ADREAD: channels */
            unsigned ch = data[i++], k;
            body[len++] = 0x01;
            for (k = 0; k < ch; k++) {
                /* Whatever the wheel and pedals are doing, and mid-scale for a
                 * channel nothing drives. A pedal that read full-on at boot is
                 * how a cabinet decides it is broken, so the default matters. */
                uint32_t v = k < 8 ? g_analog[k] : 0x8000u;
                body[len++] = (unsigned char)(v >> 8);
                body[len++] = (unsigned char)v;
            }
            break;
        }

        case 0x25:                               /* rotary encoder read */
        case 0x26: {
            unsigned ch = data[i++], k;
            body[len++] = 0x01;
            for (k = 0; k < ch; k++) { body[len++] = 0x00; body[len++] = 0x00; }
            break;
        }

        case 0x30: {                             /* coin decrease */
            unsigned slot = data[i++];
            unsigned amount = (unsigned)(data[i] << 8) | data[i + 1];
            i += 2;
            if (slot >= 1 && slot <= JVS_COIN_SLOTS) {
                unsigned *c = &g_port.coin[slot - 1];
                *c = *c > amount ? *c - amount : 0;
            }
            body[len++] = 0x01;
            break;
        }

        case 0x32: {                             /* general purpose output */
            unsigned nb = data[i++];
            i += nb;
            body[len++] = 0x01;
            break;
        }

        case 0x31: i += 3; body[len++] = 0x01; break;   /* coin increase */
        case 0x33: i += 2; body[len++] = 0x01; break;   /* analog output */
        case 0x34: i += 1; body[len++] = 0x01; break;   /* character output */
        case 0xF2: i += 1; body[len++] = 0x01; break;   /* comms method */
        case 0xF3: i += 2; body[len++] = 0x01; break;

        default:
            /* Say so rather than guess. status 2 is "I did not understand
             * that", which is a real JVS answer and better than silence: the
             * game reports it, and the log names the byte. */
            if (jvs_trace())
                fprintf(stderr, "[jvs] unknown command %02X\n", cmd);
            body[0] = 0x02;
            len = 1;
            i = n;
            break;
        }
        if (len > sizeof body - 80) break;
    }

    reply(body, len);
}

/* Pull whole packets out of whatever the game has written so far. */
static void consume_input(void)
{
    for (;;) {
        unsigned i, k, size;
        unsigned char body[256];
        unsigned blen = 0;

        /* Find SYNC. Anything before it is line noise by definition. */
        for (i = 0; i < g_port.in_len && g_port.in[i] != JVS_SYNC; i++) {}
        if (i) {
            memmove(g_port.in, g_port.in + i, g_port.in_len - i);
            g_port.in_len -= i;
        }
        if (g_port.in_len < 3) return;

        /* Un-escape from just after SYNC, which is where escaping starts. */
        size = 0;
        for (k = 1; k < g_port.in_len && blen < sizeof body; k++) {
            unsigned char b = g_port.in[k];
            if (b == JVS_ESCAPE) {
                if (k + 1 >= g_port.in_len) return;       /* wait for more */
                b = (unsigned char)(g_port.in[++k] + 1);
            }
            body[blen++] = b;
            if (blen == 2) size = body[1];                /* dest, size */
            if (blen >= 2 && size && blen == (unsigned)size + 2) break;
        }
        if (!size || blen < (unsigned)size + 2) return;   /* incomplete */

        {
            unsigned sum = 0;
            for (k = 0; k < (unsigned)size + 1; k++) sum += body[k];
            if ((sum & 0xFF) != body[size + 1]) {
                unsigned char bad[1] = { 0x03 };          /* sum error */
                if (jvs_trace())
                    fprintf(stderr, "[jvs] checksum %02X, expected %02X\n",
                            body[size + 1], sum & 0xFF);
                reply(bad, 1);
            } else {
                handle_packet(body[0], body + 2, size - 1);
            }
        }
        /* Drop the bytes this packet used, escapes included. */
        memmove(g_port.in, g_port.in + k + 1, g_port.in_len - (k + 1));
        g_port.in_len -= (k + 1);
    }
}

/* ---- completing an overlapped read on the thread that asked ---- */

typedef struct {
    uint32_t routine;            /* the thunk standing for the guest's routine */
    uint32_t err, bytes, ovl;
} Completion;

static void CALLBACK deliver(ULONG_PTR p)
{
    Completion *c = (Completion *)p;
    void(__stdcall * fn)(DWORD, DWORD, void *) =
        (void(__stdcall *)(DWORD, DWORD, void *))(uintptr_t)c->routine;
    fn((DWORD)c->err, (DWORD)c->bytes, (void *)(uintptr_t)c->ovl);
    free(c);
}

/* Hand the pending read whatever is waiting, if there is enough of it. */
/* When a serial read gives up.
 *
 * This is the whole reason the board looked dead. A real COM port completes a
 * read when its timeout expires, with however many bytes arrived - usually
 * none - and this game's driver is built on that: it posts a receive, waits,
 * is told "nothing came", and only THEN transmits. A port that never completes
 * anything leaves it waiting for a reply to a request it has not sent yet, and
 * it waits for ever, presenting empty frames.
 *
 * MAXDWORD as the interval with both totals zero means "return at once with
 * whatever is there", which is the one case worth naming; otherwise the total
 * is multiplier x bytes + constant, and zero means no timeout at all. */
static ULONGLONG read_deadline_for(uint32_t len)
{
    uint32_t total;
    if (g_port.to_interval == 0xFFFFFFFFu &&
        g_port.to_rd_mult == 0 && g_port.to_rd_const == 0)
        return 1;                                /* already expired */
    total = g_port.to_rd_mult * len + g_port.to_rd_const;
    if (!total) {
        /* No timeout configured. Waiting for ever is what a real port would
         * do and it is also how this deadlocks, so fall back to something a
         * driver would treat as a dead line rather than hanging the game. */
        total = 250;
    }
    return GetTickCount64() + total;
}

static void finish_read(void)
{
    Completion *c;
    unsigned got;
    int expired;

    if (!g_port.read_pending) return;
    expired = g_port.read_deadline && GetTickCount64() >= g_port.read_deadline;
    if (out_avail() < g_port.read_len && !expired) return;
    got = out_take((unsigned char *)(uintptr_t)g_port.read_buf,
                   g_port.read_len);
    g_port.read_pending = 0;

    /* The OVERLAPPED the game gave us describes the transfer, and code that
     * checks it before trusting the byte count is entitled to a sane one. */
    if (g_port.read_ovl) {
        wr32(g_port.read_ovl + 0, 0);            /* Internal: STATUS_SUCCESS */
        wr32(g_port.read_ovl + 4, got);          /* InternalHigh: bytes */
    }
    if (!g_port.read_routine) return;

    c = (Completion *)malloc(sizeof *c);
    if (!c) return;
    c->routine = g_port.read_routine;
    c->err = 0;
    c->bytes = got;
    c->ovl = g_port.read_ovl;
    /* Queued, not called: a completion routine runs on the thread that posted
     * the read, at its next alertable wait, and this game waits alertably on
     * purpose. Calling it here would run it on whichever thread happened to
     * write, which is not where its state lives. */
    if (!QueueUserAPC(deliver, g_port.read_thread, (ULONG_PTR)c)) free(c);
}

/* ---- what hle_callback.c calls ---- */

/* One thread, so a read that nothing satisfies still ends.
 *
 * finish_read() is otherwise only reached when the game writes, and the game
 * does not write until a read has come back - which is the deadlock this
 * exists to break. Ten milliseconds is far finer than any timeout a serial
 * driver sets and costs nothing measurable. */
/*
 * ES3_JVS_SEQ - press the cabinet's switches on a timetable.
 *
 * A desktop has no test and service buttons, and the first screen this game
 * reaches that anybody can act on is the operator menu, which is driven
 * entirely by them. So: a comma-separated list of `<ms>:<field>=<hex>`, where
 * field is `sys`, `p1` or `p2` and ms is milliseconds since the board opened.
 *
 *   ES3_JVS_SEQ="600000:p1=0200,600100:p1=0"
 *
 * A press is two entries, down and up - deliberately, because how long a
 * button is held is something a menu can care about and guessing it here
 * would be the kind of help that hides a bug.
 */
#define JVS_SEQ_MAX 32
static struct { unsigned when; unsigned char field; uint32_t bits; } g_seq[JVS_SEQ_MAX];
static unsigned g_nseq, g_seq_done;
static ULONGLONG g_seq_t0;

static void seq_init(void)
{
    const char *s = getenv("ES3_JVS_SEQ");
    g_seq_t0 = GetTickCount64();
    while (s && *s && g_nseq < JVS_SEQ_MAX) {
        char *end;
        unsigned when = (unsigned)strtoul(s, &end, 10);
        unsigned char field;
        if (end == s || *end != ':') break;
        s = end + 1;
        if (!_strnicmp(s, "sys", 3))     { field = 0; s += 3; }
        else if (!_strnicmp(s, "p1", 2)) { field = 1; s += 2; }
        else if (!_strnicmp(s, "p2", 2)) { field = 2; s += 2; }
        /* `shot` is not a switch. It is here because the only clock that can
         * say "capture what that press did" is this one: the frame counter
         * and this timetable drift apart from run to run, so naming a frame
         * number for it lands somewhere different every time. */
        else if (!_strnicmp(s, "shot", 4)) { field = 3; s += 4; }
        else break;
        if (*s != '=') break;
        g_seq[g_nseq].when = when;
        g_seq[g_nseq].field = field;
        g_seq[g_nseq].bits = (uint32_t)strtoul(s + 1, &end, 16);
        g_nseq++;
        s = *end == ',' ? end + 1 : end;
    }
    if (g_nseq)
        fprintf(stderr, "[jvs] %u scheduled switch change(s)\n", g_nseq);
}

static void seq_tick(void)
{
    unsigned elapsed;
    if (g_seq_done >= g_nseq) return;
    elapsed = (unsigned)(GetTickCount64() - g_seq_t0);
    while (g_seq_done < g_nseq && g_seq[g_seq_done].when <= elapsed) {
        unsigned k = g_seq_done++;
        switch (g_seq[k].field) {
        case 0: g_sw_sys = g_seq[k].bits; break;
        case 1: g_sw_p1  = g_seq[k].bits; break;
        case 3: es3_shot_now(); break;
        default: g_sw_p2 = g_seq[k].bits; break;
        }
        fprintf(stderr, "[jvs] %ums: %s = %04X\n", g_seq[k].when,
                g_seq[k].field == 0 ? "sys" :
                g_seq[k].field == 1 ? "p1"  :
                g_seq[k].field == 3 ? "shot" : "p2",
                g_seq[k].bits);
    }
}

/*
 * A keyboard and an Xbox pad, wired to the cabinet's switches.
 *
 * ES3_JVS_SEQ presses switches on a timetable, which is what a test needs and
 * nothing like what a person needs. A cabinet has a wheel, two pedals, a start
 * button, an item button and a coin slot, and every one of them is a JVS bit
 * or an analog channel this file already reports - so the only thing missing
 * was somewhere to read a human from.
 *
 *   keyboard          pad                  cabinet
 *   ----------------  -------------------  --------------------------
 *   Enter             Start                START
 *   Left Ctrl, Space  A                    ITEM  (dismisses the card prompt)
 *   Z                 B                    PUSH2
 *   arrow keys        d-pad                UP / DOWN / LEFT / RIGHT
 *   Left / Right      left stick X         steering, analog channel 0
 *   Up / Down         right / left trigger accelerator and brake, channels 1-2
 *   T                 -                    TEST   (the operator menu)
 *   S                 Back                 SERVICE
 *   5                 -                    insert a coin
 *
 * Only while a window of this process has the foreground, because
 * GetAsyncKeyState is global and a game that reads your typing in another
 * application is a worse bug than no input at all.
 *
 * The sequencer's bits and these are OR-ed rather than one overwriting the
 * other, so ES3_JVS_SEQ still works with a pad plugged in. ES3_NO_INPUT turns
 * the whole thing off.
 */
#define JVS_START 0x8000u
#define JVS_SERV  0x4000u
#define JVS_UP    0x2000u
#define JVS_DOWN  0x1000u
#define JVS_LEFT  0x0800u
#define JVS_RIGHT 0x0400u
#define JVS_ITEM  0x0200u
#define JVS_PUSH2 0x0100u

typedef struct {
    DWORD dwPacketNumber;
    struct {
        WORD  wButtons;
        BYTE  bLeftTrigger, bRightTrigger;
        SHORT sThumbLX, sThumbLY, sThumbRX, sThumbRY;
    } Gamepad;
} ES3_XINPUT_STATE;
typedef DWORD (WINAPI *ES3_XInputGetState)(DWORD, ES3_XINPUT_STATE *);

static int input_off(void)
{
    static int off = -1;
    if (off < 0) off = getenv("ES3_NO_INPUT") != NULL;
    return off;
}

static int ours_in_front(void)
{
    DWORD pid = 0;
    HWND h = GetForegroundWindow();
    if (!h) return 0;
    GetWindowThreadProcessId(h, &pid);
    return pid == GetCurrentProcessId();
}

static ES3_XInputGetState xinput_fn(void)
{
    static ES3_XInputGetState fn;
    static int tried;
    static const char *dlls[] = { "xinput1_4.dll", "xinput1_3.dll",
                                  "xinput9_1_0.dll" };
    unsigned i;
    if (tried) return fn;
    tried = 1;
    for (i = 0; i < 3 && !fn; i++) {
        HMODULE m = LoadLibraryA(dlls[i]);
        if (m) fn = (ES3_XInputGetState)GetProcAddress(m, "XInputGetState");
    }
    return fn;
}

/*
 * A coin, for a title whose credit counter this runtime pokes directly.
 *
 * g_port.coin[] is the JVS answer, and a game that reads its I/O over the
 * wire takes its coins from there. A game whose serial board this port does
 * not speak - Mario Kart talks a drive-board protocol on COM1, not JVS -
 * never reads it, so the same edge is offered here as a count a game project
 * can take and turn into whatever that title calls a credit.
 *
 * Edges, not a level: one press is one coin, and taking it consumes it, so
 * two callers cannot both spend the same coin.
 */
/* Interlocked rather than the port lock: this is called from lifted code on
 * the game's own thread, from the first frame, and g_port.lock does not
 * exist until the game opens the port - which for a title that never opens
 * one is never. Entering an uninitialised critical section is a crash, and
 * it is a crash at a plausible-looking place, which is worse. */
static volatile LONG g_coins_pending;

unsigned es3_coin_take(void)
{
    return (unsigned)InterlockedExchange(&g_coins_pending, 0);
}

static void input_poll(void)
{
    static int said, had_coin;
    uint32_t p1 = 0, sys = 0;
    int steer = 0, gas = 0, brake = 0, coin = 0;
    ES3_XInputGetState xi;

    if (input_off()) return;

    if (ours_in_front()) {
        #define DOWN_(k) ((GetAsyncKeyState(k) & 0x8000) != 0)
        if (DOWN_(VK_RETURN))                       p1 |= JVS_START;
        if (DOWN_(VK_LCONTROL) || DOWN_(VK_SPACE))  p1 |= JVS_ITEM;
        if (DOWN_('Z'))                             p1 |= JVS_PUSH2;
        if (DOWN_(VK_UP))    { p1 |= JVS_UP;    gas = 255; }
        if (DOWN_(VK_DOWN))  { p1 |= JVS_DOWN;  brake = 255; }
        if (DOWN_(VK_LEFT))  { p1 |= JVS_LEFT;  steer = -32000; }
        if (DOWN_(VK_RIGHT)) { p1 |= JVS_RIGHT; steer = 32000; }
        if (DOWN_('S'))                             p1 |= JVS_SERV;
        if (DOWN_('T'))                             sys |= 0x80u;
        if (DOWN_('5'))                             coin = 1;
        /* Not a switch on the cabinet - a card held against the reader. */
        if (DOWN_('C'))                             es3_card_tap();
        #undef DOWN_
    }

    xi = xinput_fn();
    if (xi) {
        ES3_XINPUT_STATE st;
        memset(&st, 0, sizeof st);
        if (xi(0, &st) == 0) {
            WORD b = st.Gamepad.wButtons;
            if (b & 0x0010) p1 |= JVS_START;    /* Start */
            if (b & 0x0020) p1 |= JVS_SERV;     /* Back  */
            if (b & 0x1000) p1 |= JVS_ITEM;     /* A     */
            if (b & 0x2000) p1 |= JVS_PUSH2;    /* B     */
            if (b & 0x0040) coin = 1;           /* left stick click  */
            if (b & 0x0080) coin = 1;           /* right stick click */
            if (b & 0x8000) es3_card_tap();     /* Y: tap the card on */
            if (b & 0x0001) p1 |= JVS_UP;
            if (b & 0x0002) p1 |= JVS_DOWN;
            if (b & 0x0004) p1 |= JVS_LEFT;
            if (b & 0x0008) p1 |= JVS_RIGHT;
            if (st.Gamepad.bRightTrigger > 30) gas = st.Gamepad.bRightTrigger;
            if (st.Gamepad.bLeftTrigger  > 30) brake = st.Gamepad.bLeftTrigger;
            /* A stick beats the arrow keys only when it is actually pushed:
             * a resting stick reads a few hundred either way. */
            if (st.Gamepad.sThumbLX > 8000 || st.Gamepad.sThumbLX < -8000)
                steer = st.Gamepad.sThumbLX;
            if (!said) {
                said = 1;
                fprintf(stderr, "[jvs] an Xbox pad is connected; it is driving "
                                "the wheel, the pedals and the buttons.\n");
            }
        }
    }

    g_in_p1  = p1;
    g_in_sys = sys;
    /* 0x8000 is centre, and the channels the game reads as 16-bit. */
    g_analog[0] = (uint32_t)(0x8000 + steer / 2);
    g_analog[1] = (uint32_t)(gas   * 257 / 2 + (gas   ? 0x8000 : 0));
    g_analog[2] = (uint32_t)(brake * 257 / 2 + (brake ? 0x8000 : 0));
    if (g_analog[1] > 0xFFFFu) g_analog[1] = 0xFFFFu;
    if (g_analog[2] > 0xFFFFu) g_analog[2] = 0xFFFFu;

    if (coin && !had_coin) {
        EnterCriticalSection(&g_port.lock);
        g_port.coin[0]++;
        InterlockedIncrement(&g_coins_pending);
        LeaveCriticalSection(&g_port.lock);
        fprintf(stderr, "[jvs] coin inserted (slot 1 is now at %u)\n",
                g_port.coin[0]);
    }
    had_coin = coin;
}

static DWORD WINAPI jvs_ticker(void *unused)
{
    (void)unused;
    seq_init();
    for (;;) {
        Sleep(10);
        seq_tick();
        input_poll();
        EnterCriticalSection(&g_port.lock);
        finish_read();
        LeaveCriticalSection(&g_port.lock);
    }
}

void es3_jvs_set_timeouts(uint32_t p)
{
    if (!p) return;
    EnterCriticalSection(&g_port.lock);
    g_port.to_interval  = rd32(p + 0);
    g_port.to_rd_mult   = rd32(p + 4);
    g_port.to_rd_const  = rd32(p + 8);
    LeaveCriticalSection(&g_port.lock);
    if (jvs_trace())
        fprintf(stderr, "[jvs] timeouts: interval %u, read %u x n + %u\n",
                g_port.to_interval, g_port.to_rd_mult, g_port.to_rd_const);
}

int es3_jvs_is_port(uint32_t h)
{
    return g_ready && h && (HANDLE)(uintptr_t)h == g_port.handle;
}

uint32_t es3_jvs_open(const char *name)
{
    const char *p = name;

    if (jvs_off() || !name) return 0;
    if (p[0] == '\\' && p[1] == '\\' && p[2] == '.' && p[3] == '\\') p += 4;
    if (!((p[0] == 'C' || p[0] == 'c') && (p[1] == 'O' || p[1] == 'o') &&
          (p[2] == 'M' || p[2] == 'm') && p[3] >= '0' && p[3] <= '9'))
        return 0;

    /*
     * One port, not every port.
     *
     * A cabinet has several serial devices and this file only knows one
     * protocol. Mario Kart opens COM1 for the JVS I/O and COM2 or COM4 for the
     * IC card reader (0x005BD830 picks between them by name), and answering
     * the card reader in JVS is worse than not answering it at all: it opens,
     * it talks, and it gets replies that mean nothing, which the game reports
     * as -301 and turns into E07-11 - an error whose entry in the mode table
     * suppresses the frame loop's task tick, so the game then draws nothing at
     * all.
     *
     * So claim the JVS port and leave the rest to Windows, where a port that
     * is not there fails to open and the game is told so honestly.
     * ES3_JVS_PORT moves it, for a cabinet wired differently.
     */
    {
        const char *want = getenv("ES3_JVS_PORT");
        int n = p[3] - '0';
        if (p[4] >= '0' && p[4] <= '9') n = n * 10 + (p[4] - '0');
        if (n != (want ? atoi(want) : 1)) {
            static int said;
            if (!said) {
                said = 1;
                fprintf(stderr, "[jvs] the game opened %s as well; leaving that "
                                "one to Windows - it is not the JVS board "
                                "(ES3_JVS_PORT to say which is).\n", name);
            }
            return 0;
        }
    }

    if (!g_ready) {
        InitializeCriticalSection(&g_port.lock);
        /* A real kernel object, so CloseHandle and every wait the game might
         * try on it behave like a handle rather than like a number. */
        g_port.handle = CreateEventW(NULL, TRUE, FALSE, NULL);
        {
            HANDLE t = CreateThread(NULL, 0, jvs_ticker, NULL, 0, NULL);
            if (t) CloseHandle(t);
        }
        g_ready = 1;
        fprintf(stderr,
            "\n[jvs] the game opened %s, where the JVS I/O board would be.\n"
            "      There is no board on a desktop, so this runtime is one: it "
            "answers resets,\n"
            "      takes an address, identifies itself and reports switches, "
            "coins and analog\n"
            "      channels with nothing pressed and the wheel centred. "
            "ES3_NO_JVS to stop,\n"
            "      ES3_TRACE_JVS to watch the packets.\n\n", name);
        fflush(stderr);
    }
    return (uint32_t)(uintptr_t)g_port.handle;
}

int es3_jvs_write(uint32_t buf, uint32_t n)
{
    const unsigned char *p = (const unsigned char *)(uintptr_t)buf;
    if (jvs_trace()) hexline("wire <-", p, n);
    EnterCriticalSection(&g_port.lock);
    if (n > FIFO_SIZE - g_port.in_len) n = FIFO_SIZE - g_port.in_len;
    memcpy(g_port.in + g_port.in_len, p, n);
    g_port.in_len += n;
    consume_input();
    finish_read();
    LeaveCriticalSection(&g_port.lock);
    return 1;
}

uint32_t es3_jvs_read(uint32_t buf, uint32_t n)
{
    uint32_t got;
    if (jvs_trace())
        fprintf(stderr, "[jvs] blocking read of %u (%u waiting)\n",
                n, out_avail());
    EnterCriticalSection(&g_port.lock);
    got = out_take((unsigned char *)(uintptr_t)buf, n);
    LeaveCriticalSection(&g_port.lock);
    return got;
}

/* Every call the game makes on the port, so the ORDER is visible. A board that
 * is never asked anything is a different problem from one that answers wrongly,
 * and only the sequence tells them apart. */
void es3_jvs_note(const char *what, uint32_t a, uint32_t b)
{
    if (jvs_trace()) fprintf(stderr, "[jvs] %s(%08X, %08X)\n", what, a, b);
}

void es3_jvs_post_read(uint32_t buf, uint32_t n, uint32_t ovl, uint32_t routine)
{
    if (jvs_trace())
        fprintf(stderr, "[jvs] read posted: %u byte(s) into %08X, ovl %08X, "
                        "routine %08X (%u waiting)\n",
                n, buf, ovl, routine, out_avail());
    EnterCriticalSection(&g_port.lock);
    if (g_port.read_thread) CloseHandle(g_port.read_thread);
    g_port.read_thread = NULL;
    DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                    GetCurrentProcess(), &g_port.read_thread,
                    0, FALSE, DUPLICATE_SAME_ACCESS);
    g_port.read_pending = 1;
    g_port.read_deadline = read_deadline_for(n);
    g_port.read_buf = buf;
    g_port.read_len = n;
    g_port.read_ovl = ovl;
    g_port.read_routine = routine;
    finish_read();                       /* it may already be satisfiable */
    LeaveCriticalSection(&g_port.lock);
}

/* A write finished the instant it was made, but WriteFileEx still promises a
 * completion routine, and code that counts them notices when one never comes. */
void es3_jvs_complete_write(uint32_t ovl, uint32_t bytes, uint32_t routine)
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

void es3_jvs_cancel(void)
{
    if (jvs_trace()) fprintf(stderr, "[jvs] read cancelled\n");
    EnterCriticalSection(&g_port.lock);
    g_port.read_pending = 0;
    LeaveCriticalSection(&g_port.lock);
}

#else
int es3_jvs_is_port(uint32_t h) { (void)h; return 0; }
uint32_t es3_jvs_open(const char *n) { (void)n; return 0; }
int es3_jvs_write(uint32_t b, uint32_t n) { (void)b; (void)n; return 0; }
uint32_t es3_jvs_read(uint32_t b, uint32_t n) { (void)b; (void)n; return 0; }
void es3_jvs_post_read(uint32_t b, uint32_t n, uint32_t o, uint32_t r)
{ (void)b; (void)n; (void)o; (void)r; }
void es3_jvs_cancel(void) {}
#endif
