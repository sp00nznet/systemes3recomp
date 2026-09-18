/*
 * main64.c - start the recompiled guest.
 *
 * Maps the original image, points a guest stack at real memory, and calls the
 * lifted entry point. The entry point is the MSVC CRT's `start`, so everything
 * a C++ program needs before main - the security cookie, the TLS callbacks,
 * the static initialisers, the CRT heap - runs as lifted code from here.
 */

#include "es3_rt64.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

#define GUEST_STACK (8u * 1024u * 1024u)   /* what the PE header asks for */

static void usage(const char *argv0)
{
    fprintf(stderr,
        "usage: %s <SWArcGame-Win64-Shipping.exe> [--trace] [--limit N]\n"
        "\n"
        "  --trace    record every dispatch to a ring buffer and dump it on a\n"
        "             fault or on exit (es3_trace64.txt)\n"
        "  --limit N  stop after N dispatches - a runaway guest otherwise runs\n"
        "             until it faults, and the trail is more useful than the\n"
        "             fault when bringing a new image up\n",
        argv0);
}

int main(int argc, char **argv)
{
    const char *exe = NULL;
    const char *game_args = "";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--trace")) g_trace_enabled = 1;
        else if (!strcmp(argv[i], "--swallow-raise")) g_swallow_raise = 1;
        else if (!strcmp(argv[i], "--trace-files")) g_trace_files = 1;
        else if (!strcmp(argv[i], "--watch-serialize") && i + 1 < argc)
            g_watch_serialize = strtoull(argv[++i], NULL, 0);
        else if (!strcmp(argv[i], "--game-args") && i + 1 < argc)
            game_args = argv[++i];
        else if (!strcmp(argv[i], "--limit") && i + 1 < argc)
            g_dispatch_limit = strtoull(argv[++i], NULL, 0);
        else if (argv[i][0] != '-') exe = argv[i];
    }
    if (!exe) { usage(argv[0]); return 2; }

    /* Unbuffered, because every interesting run of this program ends by dying.
     * stderr is unbuffered only while it is a console; redirected to a file it
     * is fully buffered, and the diagnosis of a crash then sits in a buffer
     * that the crash discards. Two runs were debugged blind before this. */
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    es3_install_crash_handler();

    es3_set_guest_cmdline(exe, game_args);

    if (!es3_load_image(exe)) return 1;

    uint64_t sp = es3_alloc_stack(GUEST_STACK);
    if (!sp) { fprintf(stderr, "[main] no guest stack\n"); return 1; }

    CPU c;
    memset(&c, 0, sizeof c);
    c.rsp = sp;

    /* The return address the entry point will eventually try to return
     * through. `start` normally returns into kernel32's thread stub, which
     * called it; nothing here did, so a sentinel goes in and reaching it means
     * the guest ran to completion rather than crashed. */
    c.rsp -= 8;
    *(uint64_t *)c.rsp = 0xE5E3DEADE5E3DEADULL;

    fprintf(stderr, "[main] guest stack %#llx, entering %#llx\n",
            (unsigned long long)sp, (unsigned long long)g_image.entry);
    fprintf(stderr, "[main] ---- guest starts ----\n");
    fflush(stderr);

    dispatch(&c, g_image.entry);

    fprintf(stderr, "[main] ---- guest returned ----\n");
    fprintf(stderr, "[main] rax=%#llx rsp=%#llx\n",
            (unsigned long long)c.rax, (unsigned long long)c.rsp);
    if (g_trace_enabled) es3_trace_dump("guest returned");
    return 0;
}
