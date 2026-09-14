/*
 * allnet.c - answer the authentication server that no longer exists.
 *
 * Mario Kart DX will not leave its boot sequence until ALL.Net says hello.
 * The client is Sega's `alAbEx Ver 2.00.07`, statically linked, and it does
 * the obvious thing: resolve the host in the URL, open a socket to port 80,
 * write an HTTP request it assembles by hand, and parse `key=value&...` out of
 * the reply. The host is `amk3-stg.nbgi-amnet.jp`, which stopped resolving
 * years ago, so the boot dies at `ERROR DNS TIMEOUT / ERROR TIP HOST NOTFOUND`
 * after the resolver's own timeout - about a minute of staring at black.
 *
 * Two pieces, both small, because the client's socket path is fine and only
 * its peer is missing:
 *
 *   1. gethostbyname() answers 127.0.0.1 for anything.
 *   2. A listener on 127.0.0.1:80 replies to /sys/servlet/PowerOn.
 *
 * Deliberately NOT a proxy and not a hosts-file edit: nothing here touches the
 * machine's network configuration or sends a packet off the loopback adapter,
 * which matters because this game already tried to renew the host's DHCP lease
 * once (see hle_ip_renew).
 *
 * The request body is zlib-deflated and base64'd when the client sends
 * `Pragma: DFI`. Nothing here decodes it - the reply does not depend on the
 * request, so the only cost is that ES3_TRACE_NET prints the body as the
 * gibberish it is.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")

#include "es3_rt.h"

static int g_trace;
static int g_started;

static unsigned short allnet_port(void)
{
    const char *s = getenv("ES3_ALLNET_PORT");
    return (unsigned short)(s ? atoi(s) : 80);
}

/* stat=1 is "you may play". The rest is what alAbEx looks for by substring:
 * the keys are scanned for one at a time, so order does not matter and a key
 * the client does not know is ignored. `uri` and `host` are where it goes
 * next - back here, so the follow-up request gets an answer too. */
static int reply_body(char *out, size_t n, const char *path)
{
    time_t t = time(NULL);
    struct tm tm;
    localtime_s(&tm, &t);

    if (strstr(path, "DownloadOrder"))
        return sprintf_s(out, n, "stat=1&uri=&host=");

    return sprintf_s(out, n,
        "stat=1&uri=http://127.0.0.1/&host=127.0.0.1"
        "&place_id=0123&name=RECOMP&nickname=RECOMP"
        "&region0=1&region_name0=W&region_name1=X"
        "&region_name2=Y&region_name3=Z"
        "&country=JPN&timezone=+09:00"
        "&year=%04d&month=%d&day=%d&hour=%d&minute=%d&second=%d",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
        tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static void serve(SOCKET s)
{
    char req[8192], body[1024], out[2048];
    int got = 0, blen, hlen;
    char *end = NULL, *sp;
    char path[256] = "/";

    /* Headers first. One recv() is almost always the whole request - this
     * loops because "almost always" is the bug you find at 3am. */
    while (got < (int)sizeof req - 1) {
        int r = recv(s, req + got, (int)sizeof req - 1 - got, 0);
        if (r <= 0) break;
        got += r;
        req[got] = 0;
        if ((end = strstr(req, "\r\n\r\n")) != NULL) break;
    }
    if (!end) { closesocket(s); return; }

    sp = strchr(req, ' ');
    if (sp) {
        char *sp2 = strchr(sp + 1, ' ');
        size_t len = sp2 ? (size_t)(sp2 - sp - 1) : 0;
        if (len && len < sizeof path) {
            memcpy(path, sp + 1, len);
            path[len] = 0;
        }
    }

    /* Drain the body before replying. Closing a socket with unread data in
     * its receive buffer sends an RST, and an RST throws away the reply that
     * was already written - so skipping this is a reply the client never
     * sees. The bytes themselves are not wanted: with `Pragma: DFI` the body
     * is zlib-deflated and base64'd, and the answer does not depend on it. */
    {
        const char *cl = strstr(req, "Content-Length:");
        int want = cl ? atoi(cl + 15) : 0;
        int have = got - (int)(end + 4 - req);
        while (have < want) {
            char sink[2048];
            int r = recv(s, sink, sizeof sink, 0);
            if (r <= 0) break;
            have += r;
        }
    }

    if (g_trace) {
        *end = 0;
        fprintf(stderr, "[allnet] request:\n%s\n", req);
    }

    blen = reply_body(body, sizeof body, path);
    hlen = sprintf_s(out, sizeof out,
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: text/plain\r\n"
                     "Content-Length: %d\r\n"
                     "Connection: close\r\n\r\n%s",
                     blen, body);
    send(s, out, hlen, 0);
    shutdown(s, SD_SEND);
    if (g_trace) fprintf(stderr, "[allnet] %s -> %s\n", path, body);
    closesocket(s);
}

static DWORD WINAPI allnet_thread(void *arg)
{
    SOCKET ls = (SOCKET)(uintptr_t)arg;
    for (;;) {
        SOCKET s = accept(ls, NULL, NULL);
        if (s == INVALID_SOCKET) break;
        serve(s);
    }
    return 0;
}

/* Started on the first name the game resolves, so a run that never asks never
 * opens a socket. */
static void allnet_start(void)
{
    WSADATA wsa;
    SOCKET ls;
    struct sockaddr_in a;
    unsigned short port = allnet_port();
    HANDLE th;

    g_started = 1;
    g_trace = getenv("ES3_TRACE_NET") != NULL;

    WSAStartup(MAKEWORD(2, 2), &wsa);
    ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls == INVALID_SOCKET) return;

    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);   /* loopback only, on purpose */
    if (bind(ls, (struct sockaddr *)&a, sizeof a) || listen(ls, 8)) {
        fprintf(stderr, "[allnet] cannot listen on 127.0.0.1:%u (%d) - the "
                        "game's authentication will fail. ES3_ALLNET_PORT to "
                        "move it.\n", port, WSAGetLastError());
        closesocket(ls);
        return;
    }
    fprintf(stderr, "[allnet] answering ALL.Net on 127.0.0.1:%u\n", port);
    th = CreateThread(NULL, 0, allnet_thread, (void *)(uintptr_t)ls, 0, NULL);
    if (th) CloseHandle(th);
}

/* A guest `char *`. Not es3_arg_string(), which wants four characters before
 * it believes a pointer is a string and decodes anything shorter as UTF-16 -
 * and the first name this game resolves is its own hostname, which on this
 * machine is three letters and came back as mojibake. */
static const char *guest_str(uint32_t va, char *buf, size_t n)
{
    const char *p = (const char *)(uintptr_t)va;
    size_t i;
    if (va < 0x10000u) return NULL;
    for (i = 0; i + 1 < n; i++) {
        char ch = p[i];
        if (ch == 0) break;
        if ((unsigned char)ch < 0x20 || (unsigned char)ch > 0x7E) return NULL;
        buf[i] = ch;
    }
    buf[i] = 0;
    return i ? buf : NULL;
}

/* gethostbyname(): every name is here - except this machine's own.
 *
 * The first thing the ALL.Net client resolves is the result of gethostname(),
 * to learn the cabinet's own IP address. Answering 127.0.0.1 to THAT is how
 * `ERROR DNS TIMEOUT` became `LOCAL NETWORK ERROR`: the game decided the
 * cabinet was on the loopback adapter. So that one name goes to the real
 * resolver and everything else comes here.
 *
 * The returned hostent is static and the guest reads it through a flat 1:1
 * address space, so host pointers are guest pointers. Winsock's own
 * gethostbyname returns a per-thread static too, so the lifetime the caller
 * expects is the one it gets. */
void es3_hle_gethostbyname(CPU *c, HleId id)
{
    static struct hostent he;
    static char name[256];
    static unsigned long addr;
    static char *addrs[2];
    static char *aliases[1];
    static int said;
    static char self[256];

    char asked[256];
    const char *want = guest_str(A32(0), asked, sizeof asked);

    if (!g_started) allnet_start();
    if (!self[0] && gethostname(self, sizeof self) != 0) self[0] = 0;

    if (want && (_stricmp(want, self) == 0 || _stricmp(want, "localhost") == 0)) {
        if (g_trace)
            fprintf(stderr, "[allnet] '%s' is this machine - asking the real "
                            "resolver\n", want);
        hle_call_native(c, id);
        return;
    }

    if (!said) {
        said = 1;
        fprintf(stderr, "[allnet] '%s' -> 127.0.0.1 (ES3_NO_ALLNET to let the "
                        "real resolver have it)\n", want ? want : "?");
    } else if (g_trace) {
        fprintf(stderr, "[allnet] resolve '%s' -> 127.0.0.1\n", want ? want : "?");
    }

    strncpy_s(name, sizeof name, want ? want : "localhost", _TRUNCATE);
    addr = htonl(INADDR_LOOPBACK);
    addrs[0] = (char *)&addr;
    addrs[1] = NULL;
    aliases[0] = NULL;
    he.h_name = name;
    he.h_aliases = aliases;
    he.h_addrtype = AF_INET;
    he.h_length = 4;
    he.h_addr_list = addrs;

    c->eax = (uint32_t)(uintptr_t)&he;
    c->esp += 4 + 4 * 1;              /* __stdcall, one argument */
}

/* connect() and send(), traced.
 *
 * gethostbyname() answering is only half an answer: the client is free to
 * ignore it, to have an address from its own configuration, or to talk to a
 * port nothing here is listening on. These say which, and then get out of the
 * way - the real winsock does the work either way. */
void es3_hle_connect(CPU *c, HleId id)
{
    uint32_t sa = A32(1);
    if (g_trace && sa) {
        const unsigned char *b = (const unsigned char *)(uintptr_t)sa;
        fprintf(stderr, "[allnet] connect -> %u.%u.%u.%u:%u\n",
                b[4], b[5], b[6], b[7], (unsigned)(b[2] << 8 | b[3]));
    }
    hle_call_native(c, id);
}

void es3_hle_send(CPU *c, HleId id)
{
    uint32_t buf = A32(1), n = A32(2);
    if (g_trace && buf && n) {
        unsigned show = n > 400 ? 400 : n;
        fprintf(stderr, "[allnet] send %u bytes:\n%.*s\n",
                n, (int)show, (const char *)(uintptr_t)buf);
    }
    hle_call_native(c, id);
}

/*
 * WinHTTP, pointed back here.
 *
 * The ALL.Net client rolls its own HTTP over WS2_32, so gethostbyname() is
 * enough to move it. Namco's own service - `amk3-stg.nbgi-amnet.jp`, which is
 * what `ERROR AUTH NG` is about - uses WinHTTP instead, and WinHTTP resolves
 * names and opens sockets INSIDE winhttp.dll. None of that goes through the
 * guest's imports, so the resolver hook above never sees it and the request
 * dies on a name that has not existed for years.
 *
 * So redirect it where it is named: WinHttpConnect takes the host and the port
 * as arguments, and replacing them is two stores. The rest of the client - the
 * verb, the headers, the response parse - stays real.
 */
static const wchar_t k_local[] = L"127.0.0.1";

void es3_hle_winhttp_connect(CPU *c, HleId id)
{
    if (g_trace) {
        const char *s = es3_arg_string(A32(1));
        fprintf(stderr, "[allnet] WinHttpConnect %s:%u -> 127.0.0.1:%u\n",
                s ? s : "?", A32(2), allnet_port());
    }
    if (!g_started) allnet_start();
    wr32(c->esp + 4 + 4 * 1, (uint32_t)(uintptr_t)k_local);
    wr32(c->esp + 4 + 4 * 2, allnet_port());
    hle_call_native(c, id);
}

/* WINHTTP_FLAG_SECURE. Nothing here speaks TLS and the loopback server does
 * not need to: drop the flag and the same request arrives in the clear. If a
 * title ever REQUIRES https, this is where it would have to grow one. */
#define WINHTTP_SECURE 0x00800000u

void es3_hle_winhttp_open_request(CPU *c, HleId id)
{
    uint32_t flags = A32(6);
    if (g_trace) {
        const char *v = es3_arg_string(A32(1));
        const char *o = es3_arg_string(A32(2));
        fprintf(stderr, "[allnet] WinHttpOpenRequest %s %s flags %08X\n",
                v ? v : "GET", o ? o : "/", flags);
    }
    if (flags & WINHTTP_SECURE)
        wr32(c->esp + 4 + 4 * 6, flags & ~WINHTTP_SECURE);
    hle_call_native(c, id);
}
