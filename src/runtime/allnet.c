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

/* Guest-visible, so it has to outlive the call. */
static char g_loopback[] = "127.0.0.1";

static unsigned short allnet_port(void)
{
    const char *s = getenv("ES3_ALLNET_PORT");
    return (unsigned short)(s ? atoi(s) : 80);
}

/*
 * The address the resolvers hand out - and why it is not 127.0.0.1.
 *
 * alAbEx validates every address it is given before it will use one.
 * 0x007B5EA0 does it in six instructions: ntohl the address, reject anything
 * at or below 0.255.255.255, reject 127.0.0.0/8, reject 240.0.0.0 and above.
 * So answering the ALL.Net host with loopback is answering with the one
 * address the library is certain is wrong: alAbExInit returns an error, the
 * client's status word at [this+0x94] is set to 4, 0x00679470 reports the
 * network as a problem and the cabinet files E05-55. All of that from a reply
 * the game never got to disagree with.
 *
 * 192.0.2.1 is TEST-NET-1 (RFC 5737), reserved for documentation and
 * guaranteed never to be a real host - so it cannot collide with anything on
 * this machine's network, and es3_hle_connect() sends it to 127.0.0.1 where
 * the listener actually is. The listener stays on loopback: nothing here opens
 * a port the LAN can reach.
 */
static uint32_t allnet_addr(void)
{
    static uint32_t cached;
    const char *s;
    if (cached) return cached;
    s = getenv("ES3_ALLNET_ADDR");
    cached = inet_addr(s && *s ? s : "192.0.2.1");
    if (cached == INADDR_NONE) cached = inet_addr("192.0.2.1");
    return cached;
}

/* The same address in the form a resolver argument wants. Guest-visible, so it
 * has to outlive the call: a file static, like the rest of this. */
static const char *allnet_addr_str(void)
{
    static char s[16];
    struct in_addr a;
    if (!s[0]) {
        a.s_addr = allnet_addr();
        strncpy_s(s, sizeof s, inet_ntoa(a), _TRUNCATE);
    }
    return s;
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

    /*
     * Namco's own service speaks JSON, not All.Net's key=value.
     *
     * The game asks `amk3-stg.nbgi-amnet.jp` for `/board/getControlData` and
     * then a family of `/amid/...` calls - the banapassport side. Answering
     * those with an All.Net reply gets the parse rejected in the game's own
     * words: `このJsonの解析はフォーマットが違う`, this Json's format is wrong,
     * with our body quoted back.
     *
     * The field names are not guessed. They are a block in .rdata at
     * 0x00487BF0: store_id, allnet_game_id, allnet_game_ver, line_type,
     * store_name, store_nickname, area_cd_0, area_name_0..3, country_code,
     * time_zone, status, started_at, yuai_option_limit_at - which is a
     * getControlData response written out.
     */
    if (strstr(path, "/board/getControlData")) {
        return sprintf_s(out, n,
            "{\"net_id\":\"AZZZ0123\","
            "\"place_id\":\"0123\","
            "\"game_id\":\"SBZB\","
            "\"serial_no\":\"271000020001\","
            "\"status\":0,"
            "\"store_id\":\"0123\","
            "\"store_name\":\"RECOMP\","
            "\"store_nickname\":\"RECOMP\","
            "\"allnet_game_id\":\"SBZB\","
            "\"allnet_game_ver\":\"0.01\","
            "\"line_type\":1,"
            "\"area_cd_0\":\"1\","
            "\"area_name_0\":\"W\",\"area_name_1\":\"X\","
            "\"area_name_2\":\"Y\",\"area_name_3\":\"Z\","
            "\"country_code\":\"JPN\","
            "\"time_zone\":\"+09:00\","
            "\"started_at\":\"%04d-%02d-%02dT%02d:%02d:%02dZ\","
            "\"yuai_option_limit_at\":\"2099-12-31T23:59:59Z\"}",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
            tm.tm_hour, tm.tm_min, tm.tm_sec);
    }

    /* The rest of that API - the banapassport calls - with nothing to say. */
    if (strstr(path, "/amid/") || strstr(path, "/board/") ||
        strstr(path, "/incoming/"))
        return sprintf_s(out, n, "{\"status\":0}");

    if (strstr(path, "DownloadOrder"))
        return sprintf_s(out, n, "stat=1&uri=&host=");

    /* uri and host are where the client goes next, so they carry the same
     * address the resolvers hand out - not 127.0.0.1, which alAbEx rejects
     * before it will use it (see allnet_addr). connect() puts it back on
     * loopback, which is where this listener is. */
    return sprintf_s(out, n,
        "stat=1&uri=http://%s/&host=%s"
        "&place_id=0123&name=RECOMP&nickname=RECOMP"
        "&region0=1&region_name0=W&region_name1=X"
        "&region_name2=Y&region_name3=Z"
        "&country=JPN&timezone=+09:00"
        "&year=%04d&month=%d&day=%d&hour=%d&minute=%d&second=%d",
        allnet_addr_str(), allnet_addr_str(),
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

    /* Every distinct path once, without ES3_TRACE_NET.
     *
     * Which calls the game makes is the whole question when its client rejects
     * an answer, and the trace that used to be the only way to see them binds
     * four more imports - with which this boot stalls early and reproducibly
     * around the I/O board. This costs one strcmp on a listener thread that is
     * ours, and it works on the run that actually boots. */
    {
        static char seen[16][128];
        static int nseen;
        int i;
        for (i = 0; i < nseen && strcmp(seen[i], path); i++) {}
        if (i == nseen && nseen < 16) {
            strncpy_s(seen[nseen++], sizeof seen[0], path, _TRUNCATE);
            fprintf(stderr, "[allnet] asked for %s\n", path);
        }
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
    static char self[256];
    static int said;

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
        fprintf(stderr, "[allnet] '%s' -> %s (ES3_NO_ALLNET to let the "
                        "real resolver have it)\n", want ? want : "?",
                allnet_addr_str());
    } else if (g_trace) {
        fprintf(stderr, "[allnet] resolve '%s' -> %s\n", want ? want : "?",
                allnet_addr_str());
    }

    /* Rewrite the name and let Winsock build the hostent, rather than
     * returning one of ours. A static of our own is only a valid guest pointer
     * while the address space stays flat and 1:1, and the caller has every
     * right to expect the per-thread buffer the real gethostbyname documents -
     * including its lifetime, and including a second call on the same thread
     * invalidating the first. The real resolver gives all of that for free,
     * and "127.0.0.1" needs no resolving. */
    wr32(c->esp + 4u, (uint32_t)(uintptr_t)allnet_addr_str());
    hle_call_native(c, id);
    /* The answer, not just the question. 0x004641F0 branches on it: a null
     * hostent sets the client's state to 2 and returns without resolving
     * anything else, which from outside looks exactly like a hang. */
    if (g_trace)
        fprintf(stderr, "[allnet]   hostent %08X\n", c->eax);
}

/*
 * getaddrinfo(), which is the one this game actually uses.
 *
 * `gethostbyname` does not appear in Mario Kart's import table at all - the
 * name is not in the executable - and the panel said `ERROR DNS TIMEOUT` and
 * `ERROR TIP HOST NOTFOUND` for as long as that was the only resolver
 * answered. Both errors come from the ALL.Net client, and it resolves through
 * getaddrinfo.
 *
 * Rewriting the node argument rather than building an addrinfo chain, because
 * the caller frees the result with the real freeaddrinfo: a chain of our own
 * would be handed to a heap that never allocated it. The guest's address space
 * is flat and 1:1, so a static host string is a valid guest pointer, and the
 * real resolver does the rest.
 */
void es3_hle_getaddrinfo(CPU *c, HleId id)
{
    static char self[256];
    static int said;

    char asked[256];
    const char *want = guest_str(A32(0), asked, sizeof asked);

    if (!g_started) allnet_start();
    if (!self[0] && gethostname(self, sizeof self) != 0) self[0] = 0;

    /* The cabinet's own name goes to the real resolver, for the same reason it
     * does in gethostbyname: a cabinet that believes it is on 127.0.0.1 fails
     * its local network check instead of its DNS one. */
    if (!want || _stricmp(want, self) == 0 || _stricmp(want, "localhost") == 0) {
        if (g_trace && want)
            fprintf(stderr, "[allnet] getaddrinfo '%s' is this machine - "
                            "asking the real resolver\n", want);
        hle_call_native(c, id);
        return;
    }

    if (!said) {
        said = 1;
        fprintf(stderr, "[allnet] getaddrinfo '%s' -> 127.0.0.1 (ES3_NO_ALLNET "
                        "to let the real resolver have it)\n", want);
    } else if (g_trace) {
        fprintf(stderr, "[allnet] getaddrinfo '%s' -> 127.0.0.1\n", want);
    }

    wr32(c->esp + 4u, (uint32_t)(uintptr_t)g_loopback);
    hle_call_native(c, id);
}

/* connect() and send(), traced.
 *
 * gethostbyname() answering is only half an answer: the client is free to
 * ignore it, to have an address from its own configuration, or to talk to a
 * port nothing here is listening on. These say which, and then get out of the
 * way - the real winsock does the work either way. */
/* The invented address, put back on loopback. Both connect() and sendto()
 * need it: alAbEx will not accept 127.0.0.1 as a server, but the traceroute
 * the same client runs before it is a raw ICMP echo to whatever the resolver
 * said - and only loopback answers one on a machine with no store router. */
static void to_loopback(uint32_t sa)
{
    unsigned char *b = (unsigned char *)(uintptr_t)sa;
    uint32_t a, lo;
    if (!b || b[0] != AF_INET) return;
    memcpy(&a, b + 4, 4);
    if (a != allnet_addr()) return;
    lo = inet_addr("127.0.0.1");
    memcpy(b + 4, &lo, 4);
}

void es3_hle_connect(CPU *c, HleId id)
{
    uint32_t sa = A32(1);
    to_loopback(sa);
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

/*
 * The cabinet link, traced.
 *
 * `LOCAL NETWORK ERROR` is not All.Net at all - it is the LAN between the
 * cabinets of one bank. A worker thread at 0x006770B0 opens a broadcast UDP
 * socket, binds a second one, sends an eight-byte discovery packet and waits;
 * `[[0x95A87C]+4]+0x1C` stays negative and the frame tick reports the error.
 *
 * These say where that packet goes and whether anything answers, which is the
 * question a single cabinet on a host with eleven virtual adapters raises.
 */
static void say_sockaddr(const char *what, uint32_t sa, int n)
{
    const unsigned char *b = (const unsigned char *)(uintptr_t)sa;
    if (!sa) { fprintf(stderr, "[link] %s <null>\n", what); return; }
    fprintf(stderr, "[link] %s %u.%u.%u.%u:%u (%d bytes)\n", what,
            b[4], b[5], b[6], b[7], (unsigned)(b[2] << 8 | b[3]), n);
}

void es3_hle_bind(CPU *c, HleId id)
{
    if (g_trace) say_sockaddr("bind", A32(1), (int)A32(2));
    hle_call_native(c, id);
}

void es3_hle_sendto(CPU *c, HleId id)
{
    uint32_t len = A32(2), to = A32(4);
    to_loopback(to);
    if (g_trace) {
        const unsigned char *p = (const unsigned char *)(uintptr_t)A32(1);
        unsigned i, show = len > 16 ? 16 : len;
        say_sockaddr("sendto", to, (int)len);
        fprintf(stderr, "[link]  ");
        for (i = 0; i < show; i++) fprintf(stderr, " %02X", p[i]);
        fprintf(stderr, "\n");
    }
    hle_call_native(c, id);
}

void es3_hle_recvfrom(CPU *c, HleId id)
{
    uint32_t buf = A32(1), from = A32(4);
    hle_call_native(c, id);
    if (g_trace && (int32_t)c->eax > 0) {
        const unsigned char *p = (const unsigned char *)(uintptr_t)buf;
        unsigned i, show = c->eax > 16 ? 16 : c->eax;
        say_sockaddr("recvfrom", from, (int)c->eax);
        fprintf(stderr, "[link]  ");
        for (i = 0; i < show; i++) fprintf(stderr, " %02X", p[i]);
        fprintf(stderr, "\n");
    }
}

/*
 * One interface, the one Windows actually routes through.
 *
 * `0x00678330` asks for SIO_GET_INTERFACE_LIST and walks every entry that is
 * up and not loopback, overwriting `[0x00952924]` each time - so the LAST such
 * interface becomes "the cabinet's IP". On a developer's machine that is
 * whichever virtual adapter sorts last: this one has eleven, and the game
 * adopted 172.19.0.1 while its own broadcast to 255.255.255.255:20199 came
 * back from 192.168.100.129. A cabinet that cannot recognise its own discovery
 * packet reports LOCAL NETWORK ERROR, and no amount of answering All.Net helps.
 *
 * So the list is filtered to the interface the routing table picks. connect()
 * on a UDP socket sends nothing - it is a route lookup and a getsockname - so
 * this asks Windows the same question the game's own sendto() will ask.
 *
 * ES3_NO_LINK_FIX leaves the list alone.
 */
#define SIO_GET_INTERFACE_LIST_ 0x4004747Fu
#define IFINFO 76u                        /* sizeof(INTERFACE_INFO) */

static uint32_t preferred_addr(void)
{
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in to, me;
    int n = sizeof me;
    uint32_t got = 0;
    BOOL yes = TRUE;
    if (s == INVALID_SOCKET) return 0;
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, (const char *)&yes, sizeof yes);
    memset(&to, 0, sizeof to);
    to.sin_family = AF_INET;
    to.sin_port = htons(20199);
    to.sin_addr.s_addr = INADDR_BROADCAST;
    if (connect(s, (struct sockaddr *)&to, sizeof to) == 0 &&
        getsockname(s, (struct sockaddr *)&me, &n) == 0)
        got = me.sin_addr.s_addr;
    closesocket(s);
    return got;
}

void es3_hle_wsaioctl(CPU *c, HleId id)
{
    uint32_t code = A32(1), out = A32(4), pret = A32(6);
    uint32_t want, bytes, k, n;
    unsigned char *p;
    static int said;

    hle_call_native(c, id);

    if (code != SIO_GET_INTERFACE_LIST_ || c->eax != 0 || !out || !pret) return;
    if (getenv("ES3_NO_LINK_FIX")) return;

    bytes = rd32(pret);
    n = bytes / IFINFO;
    if (n < 2) return;                    /* one interface is already the answer */

    want = preferred_addr();
    if (!want) return;

    p = (unsigned char *)(uintptr_t)out;
    for (k = 0; k < n; k++) {
        uint32_t a;
        memcpy(&a, p + k * IFINFO + 8, 4);      /* iiAddress.sin_addr */
        if (a != want) continue;
        if (k) memcpy(p, p + k * IFINFO, IFINFO);
        /* 24, not 76. The game's own count is `bytes / 24` (a compiler
         * reciprocal-multiply, plain as day at 0x0067839E) while it strides
         * the array by sizeof(INTERFACE_INFO) = 76 - so it always walks three
         * times as many entries as the buffer holds, off the end of a 1520
         * byte stack array, and the address it ends up calling the cabinet's
         * own is whatever garbage sorted last. Reporting 76 here handed it
         * three entries and it adopted two of stack. Report what makes its
         * arithmetic say one. */
        wr32(pret, 24u);
        if (!said) {
            const unsigned char *b = (const unsigned char *)&want;
            said = 1;
            fprintf(stderr, "[link] %u interfaces; giving the game only "
                            "%u.%u.%u.%u, the one this machine routes through "
                            "(ES3_NO_LINK_FIX to hand over all of them)\n",
                    n, b[0], b[1], b[2], b[3]);
        }
        return;
    }
}
