/*
 * passport.c - the card, in a window next to the game.
 *
 * card.c presents a MIFARE Classic 1K to the cabinet's reader, but a card is
 * an opaque thing: you cannot see what is on it, you cannot tell whether the
 * game just read it, and tapping it means finding the right key while the
 * game has the keyboard. This puts a page beside the game that shows the card
 * and can tap it.
 *
 * It is served rather than drawn. A window of our own would mean a second
 * top-level window belonging to a process that is already fighting the game
 * for focus and the display; a page in the browser is a window the player
 * already knows how to move, keep on top and put on a second monitor, and it
 * costs one socket instead of a UI toolkit.
 *
 * What it can show honestly, today, is the card: its number, whether it is on
 * the reader, how many blocks the game has read and written, and every byte of
 * it as it changes. What it cannot show yet is the profile - the name, the
 * coins, the unlocks - because those are not on the card at all.
 *
 * That last point is worth writing down, because it was the surprise. A
 * banapassport carries an identity and nothing else; the save lives on the
 * game's server, which the game reaches over HTTP - allnet.c is already
 * answering those calls, and the `/amid/` family is the profile side of that
 * API. So the panel for the profile is here and empty, and it says why, and
 * filling it in is a job for allnet.c rather than for the card.
 *
 * ES3_PASSPORT       1 to serve it (default: on whenever ES3_CARD is)
 * ES3_PASSPORT_PORT  where (default 49210)
 * ES3_PASSPORT_SHUT  do not open a browser, just print the address
 */

#include "es3_rt.h"

#ifdef _WIN32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "shell32.lib")

#define CARD_BYTES 1024

/*
 * 8642, and deliberately not up in the 49000s.
 *
 * The obvious choice was next door to the 49200 that Namco's own tooling
 * uses, and on this machine binding it fails with WSAEACCES rather than
 * "in use": Windows hands whole blocks of the ephemeral range to Hyper-V,
 * and `netsh interface ipv4 show excludedportrange protocol=tcp` lists
 * 49152-49251 among them. So the default lives below that range, where
 * nothing is reserved.
 */
static unsigned short passport_port(void)
{
    const char *p = getenv("ES3_PASSPORT_PORT");
    int n = p ? atoi(p) : 8642;
    if (n <= 0 || n > 65535) n = 8642;
    return (unsigned short)n;
}

/*
 * The page. Single-quoted attributes throughout so none of it needs escaping
 * to live in a C string, and no external anything - it is served by a socket
 * that answers three paths, and a page that fetched a font would hang on a
 * machine with no route out.
 */
static const char PAGE[] =
"<!doctype html><html><head><meta charset='utf-8'>"
"<title>BanaPassport</title><style>"
"*{box-sizing:border-box}"
"body{margin:0;padding:18px;background:#14161c;color:#e8e8ea;"
"font:13px/1.5 'Segoe UI',system-ui,sans-serif}"
".wrap{max-width:860px;margin:0 auto}"
"h1{font-size:15px;letter-spacing:.14em;text-transform:uppercase;"
"color:#8a8f9c;font-weight:600;margin:0 0 14px}"
".card{position:relative;border-radius:14px;padding:20px 22px;margin-bottom:18px;"
"background:linear-gradient(135deg,#d8232a,#f0a30a);color:#fff;"
"box-shadow:0 8px 28px rgba(0,0,0,.45);overflow:hidden}"
".card:after{content:'';position:absolute;right:-40px;top:-40px;width:180px;"
"height:180px;border-radius:50%;background:rgba(255,255,255,.10)}"
".brand{font-size:11px;letter-spacing:.22em;text-transform:uppercase;"
"opacity:.85;margin-bottom:10px}"
".uid{font:600 34px/1.1 ui-monospace,Consolas,monospace;letter-spacing:.06em}"
".sub{margin-top:6px;font-size:12px;opacity:.9}"
".lamp{display:inline-flex;align-items:center;gap:7px;margin-top:14px;"
"padding:6px 12px;border-radius:999px;background:rgba(0,0,0,.28);font-size:12px}"
".dot{width:9px;height:9px;border-radius:50%;background:#7d8590}"
".on .dot{background:#39d353;box-shadow:0 0 9px #39d353}"
"button{font:inherit;font-weight:600;border:0;border-radius:8px;padding:9px 16px;"
"background:#2f6fed;color:#fff;cursor:pointer}"
"button:hover{background:#4680f5}"
".row{display:flex;gap:18px;flex-wrap:wrap;margin-bottom:18px}"
".stat{flex:1;min-width:120px;background:#1c1f27;border:1px solid #272b36;"
"border-radius:10px;padding:12px 14px}"
".stat b{display:block;font:600 22px/1.2 ui-monospace,Consolas,monospace}"
".stat span{font-size:11px;color:#8a8f9c;text-transform:uppercase;"
"letter-spacing:.1em}"
".panel{background:#1c1f27;border:1px solid #272b36;border-radius:10px;"
"padding:14px 16px;margin-bottom:18px}"
".panel h2{font-size:12px;letter-spacing:.12em;text-transform:uppercase;"
"color:#8a8f9c;margin:0 0 10px}"
".note{color:#9aa1b0;font-size:12px}"
".note code{background:#0f1116;padding:1px 5px;border-radius:4px}"
"table{border-collapse:collapse;width:100%;font:12px/1.5 ui-monospace,Consolas,monospace}"
"td,th{padding:3px 6px;text-align:left;white-space:nowrap}"
"th{color:#8a8f9c;font-weight:500;font-size:11px}"
"tr.z td{color:#565c6b}"
".hexwrap{overflow-x:auto}"
"td.bn{color:#8a8f9c}"
"tr.nz td.hex{color:#f0a30a}"
"</style></head><body><div class='wrap'>"
"<h1>BanaPassport &middot; System ES3</h1>"
"<div class='card'>"
"<div class='brand'>BanaPassport</div>"
"<div class='uid' id='uid'>--------</div>"
"<div class='sub' id='file'></div>"
"<div class='lamp' id='lamp'><span class='dot'></span><span id='lampt'>"
"not on the reader</span></div>"
"</div>"
"<div class='row'>"
"<div class='stat'><b id='rd'>0</b><span>blocks read</span></div>"
"<div class='stat'><b id='wr'>0</b><span>blocks written</span></div>"
"<div class='stat' style='display:flex;align-items:center'>"
"<button onclick='tap()'>Tap card on reader</button></div>"
"</div>"
"<div class='panel'><h2>Profile</h2><div class='note' id='prof'>"
"A banapassport carries an identity, not a save. The name, coins and unlocks "
"live on the game server, which the game reaches over HTTP - the "
"<code>/amid/</code> calls that <code>allnet.c</code> answers. Nothing has "
"asked for a profile yet, because the game only does so once a card is "
"presented at the card prompt.</div></div>"
"<div class='panel'><h2>Card contents</h2>"
"<div class='hexwrap'><table id='blocks'></table></div></div>"
"</div><script>\n"
"function hx(b){return b.toString(16).toUpperCase().padStart(2,'0')}\n"
"function tap(){fetch('/tap',{method:'POST'}).then(poll)}\n"
"function poll(){fetch('/state.json').then(r=>r.json()).then(s=>{\n"
"  document.getElementById('uid').textContent=s.uid;\n"
"  document.getElementById('file').textContent=s.file;\n"
"  document.getElementById('rd').textContent=s.reads;\n"
"  document.getElementById('wr').textContent=s.writes;\n"
"  var l=document.getElementById('lamp');\n"
"  l.className='lamp'+(s.present?' on':'');\n"
"  document.getElementById('lampt').textContent=\n"
"    s.present?'on the reader':'not on the reader';\n"
"  var b=[];for(var i=0;i<s.blocks.length;i+=2)\n"
"    b.push(parseInt(s.blocks.substr(i,2),16));\n"
"  var h='<tr><th>blk</th><th>bytes</th><th>text</th></tr>';\n"
"  for(var k=0;k<64;k++){\n"
"    var r=b.slice(k*16,k*16+16),nz=r.some(x=>x!==0);\n"
"    var hexs=r.map(hx).join(' ');\n"
"    var txt=r.map(x=>x>=32&&x<127?String.fromCharCode(x):'.').join('');\n"
"    h+=\"<tr class='\"+(nz?'nz':'z')+\"'><td class='bn'>\"+k+\"</td>\"+\n"
"       \"<td class='hex'>\"+hexs+'</td><td>'+txt+'</td></tr>';\n"
"  }\n"
"  document.getElementById('blocks').innerHTML=h;\n"
"}).catch(()=>{})}\n"
"poll();setInterval(poll,700);\n"
"</script></body></html>";

static void send_all(SOCKET s, const char *p, int n)
{
    int sent = 0;
    while (sent < n) {
        int r = send(s, p + sent, n - sent, 0);
        if (r <= 0) return;
        sent += r;
    }
}

static void send_response(SOCKET s, const char *type, const char *body, int len)
{
    char head[256];
    int hl = sprintf_s(head, sizeof head,
                       "HTTP/1.1 200 OK\r\n"
                       "Content-Type: %s\r\n"
                       "Content-Length: %d\r\n"
                       "Cache-Control: no-store\r\n"
                       "Connection: close\r\n\r\n", type, len);
    send_all(s, head, hl);
    send_all(s, body, len);
}

static void state_json(char *out, size_t n)
{
    unsigned char uid[4], img[CARD_BYTES];
    int present = 0, reads = 0, writes = 0, i, used;

    es3_card_state(uid, &present, &reads, &writes, img);

    used = sprintf_s(out, n,
                     "{\"uid\":\"%02X%02X%02X%02X\",\"present\":%s,"
                     "\"reads\":%d,\"writes\":%d,\"file\":\"%s\","
                     "\"blocks\":\"",
                     uid[0], uid[1], uid[2], uid[3],
                     present ? "true" : "false", reads, writes,
                     es3_card_file());
    for (i = 0; i < CARD_BYTES; i++)
        used += sprintf_s(out + used, n - used, "%02X", img[i]);
    sprintf_s(out + used, n - used, "\"}");
}

static void serve_one(SOCKET s)
{
    char req[1024];
    int got = recv(s, req, sizeof req - 1, 0);

    if (got <= 0) return;
    req[got] = 0;

    if (strstr(req, "POST /tap")) {
        es3_card_tap();
        send_response(s, "application/json", "{\"ok\":true}", 11);
        return;
    }
    if (strstr(req, "GET /state.json")) {
        static char body[CARD_BYTES * 2 + 512];
        state_json(body, sizeof body);
        send_response(s, "application/json", body, (int)strlen(body));
        return;
    }
    send_response(s, "text/html; charset=utf-8", PAGE, (int)(sizeof PAGE - 1));
}

static DWORD WINAPI passport_thread(void *unused)
{
    SOCKET srv;
    struct sockaddr_in a;
    unsigned short port = passport_port();
    char url[64];

    (void)unused;

    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == INVALID_SOCKET) return 0;
    {
        /* Not SO_REUSEADDR: on Windows that lets two listeners share the port
         * and the requests split between them. If it is taken, say so. */
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_port = htons(port);
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(srv, (struct sockaddr *)&a, sizeof a) != 0 ||
            listen(srv, 8) != 0) {
            /* Which error, not a guess at it: 10048 is the port already in
             * use - usually an earlier run of the game that outlived its
             * window - and anything else means something quite different. */
            fprintf(stderr, "[passport] cannot listen on %u (winsock error "
                            "%d); the window is not being served "
                            "(ES3_PASSPORT_PORT to move it)\n",
                    port, WSAGetLastError());
            closesocket(srv);
            return 0;
        }
    }

    sprintf_s(url, sizeof url, "http://127.0.0.1:%u/", port);
    fprintf(stderr, "\n[passport] the card is on show at %s\n", url);
    fflush(stderr);

    if (!getenv("ES3_PASSPORT_SHUT"))
        ShellExecuteA(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);

    for (;;) {
        SOCKET c = accept(srv, NULL, NULL);
        if (c == INVALID_SOCKET) break;
        serve_one(c);
        shutdown(c, SD_BOTH);
        closesocket(c);
    }
    closesocket(srv);
    return 0;
}

void es3_passport_start(void)
{
    static int started;
    const char *want = getenv("ES3_PASSPORT");

    /* On with the card by default: the window is the card's window, and a
     * card nobody can see was the thing worth fixing. */
    if (!want && !getenv("ES3_CARD")) return;
    if (want && (want[0] == '0' || want[0] == 'n' || want[0] == 'N')) return;
    if (started) return;
    started = 1;

    {
        HANDLE t = CreateThread(NULL, 0, passport_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
}

#else
void es3_passport_start(void) {}
#endif
