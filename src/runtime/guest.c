/*
 * guest.c - put an ES3 process where the recompiled code expects one.
 *
 * Lifted code holds real addresses in its registers, so the game's sections
 * have to live at the virtual addresses they were linked for. An ES3 title is
 * a PE32 with ImageBase 0x00400000 and no IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
 * - it was built for a machine with ASLR off, which is what the cabinet ran -
 * so this reserves that range outright and nothing needs relocating.
 *
 * Only the section table is honoured. The real loader would then walk the
 * import directory and bind every IAT slot to a function in a DLL it mapped;
 * here every slot gets a sentinel instead, and dispatch() answers it. See
 * es3_rt.h for why the boundary is drawn there.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#include "es3_rt.h"
#include "recomp_iat.h"

#define PAGE       0x1000u
#define STACK_SZ   (8u << 20)

/* A return address the guest can never reach. The PE entry point is
 * mainCRTStartup, which exits through ExitProcess and does not return - if it
 * ever does, dispatch() stops on this rather than on whatever the stack
 * happened to contain. */
#define GUEST_RETURN_SENTINEL 0xDEADBE00u

static uint32_t g_entry;
static uint32_t g_base;
static uint32_t g_stack_pointer;

uint32_t g_image_delta = 0;       /* cpu.h's GVA(): we map where it asked */

static uint32_t rd32le(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint32_t rd16le(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}

static void *reserve(uint32_t addr, uint32_t size)
{
#ifdef _WIN32
    return VirtualAlloc((LPVOID)(uintptr_t)addr, size,
                        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#else
    void *p = mmap((void *)(uintptr_t)addr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    return p == MAP_FAILED ? NULL : p;
#endif
}

int guest_load(const char *exe_path)
{
    FILE *f = fopen(exe_path, "rb");
    if (!f) { perror(exe_path); return -1; }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *img = (unsigned char *)malloc((size_t)(len > 0 ? len : 1));
    if (!img || len <= 0 || fread(img, 1, (size_t)len, f) != (size_t)len) {
        fprintf(stderr, "%s: short read\n", exe_path);
        free(img); fclose(f); return -1;
    }
    fclose(f);

    if (len < 0x40 || img[0] != 'M' || img[1] != 'Z') {
        fprintf(stderr, "%s: not a PE\n", exe_path); free(img); return -1;
    }
    uint32_t pe = rd32le(img + 0x3C);
    if (pe + 0x78 > (uint32_t)len || memcmp(img + pe, "PE\0\0", 4) != 0) {
        fprintf(stderr, "%s: no PE signature\n", exe_path); free(img); return -1;
    }
    if (rd16le(img + pe + 4) != 0x014C) {
        fprintf(stderr, "%s: not i386 - ES3 titles are 32-bit x86\n", exe_path);
        free(img); return -1;
    }

    unsigned nsections  = rd16le(img + pe + 6);
    unsigned opt_size   = rd16le(img + pe + 20);
    const unsigned char *opt = img + pe + 24;
    g_base      = rd32le(opt + 28);
    g_entry     = g_base + rd32le(opt + 16);
    uint32_t image_size = rd32le(opt + 56);
    uint32_t hdr_size   = rd32le(opt + 60);

    /* One reservation for the whole image, then the sections copied into it.
     * Section by section would leave the gaps between them unmapped, and the
     * game reads across those: .rdata tables run right up to the end of their
     * page and MSVC's CRT walks structures that straddle a boundary. */
    if (!reserve(g_base, image_size)) {
        fprintf(stderr,
            "cannot map %#x..%#x.\n"
            "  This is the usual symptom of a 64-bit host: the image wants low\n"
            "  memory that only exists as an address in a 32-bit process.\n"
            "  Configure with: cmake -B build -A Win32\n",
            g_base, g_base + image_size);
        free(img); return -1;
    }
    memset((void *)(uintptr_t)g_base, 0, image_size);
    memcpy((void *)(uintptr_t)g_base, img, hdr_size < (uint32_t)len ? hdr_size : (uint32_t)len);

    const unsigned char *sec = img + pe + 24 + opt_size;
    for (unsigned i = 0; i < nsections; i++, sec += 40) {
        uint32_t vaddr  = rd32le(sec + 12);
        uint32_t rsize  = rd32le(sec + 16);
        uint32_t roff   = rd32le(sec + 20);
        if (!rsize || roff + rsize > (uint32_t)len) continue;   /* .bss: already zero */
        memcpy((void *)(uintptr_t)(g_base + vaddr), img + roff, rsize);
    }
    free(img);

    /* Point every IAT slot at its sentinel. This is what turns the game's
     * `call dword ptr [__imp_CreateFileW]` into a call the runtime answers. */
    {
        unsigned n = 0;
#define PATCH(slot_va, id) do { wr32((uint32_t)(slot_va), HLE_ADDR(id)); n++; } while (0);
        IAT_SLOTS(PATCH)
#undef PATCH
        if (!n) fprintf(stderr, "[guest] warning: no IAT slots patched - "
                                "every import call will land in the image\n");
    }

    /* A dedicated guest stack. It is not the host thread's, so the TEB's
     * StackBase/StackLimit do not describe it - which matters only to
     * stack-overflow recovery, and a working game never gets there.
     * ponytail: committed 8 MB up front, which is what the cabinet gave the
     * game; grow it on a guard-page fault if a title ever needs more. */
    uint32_t stack_lo;
#ifdef _WIN32
    {
        void *p = VirtualAlloc(NULL, STACK_SZ, MEM_RESERVE | MEM_COMMIT,
                               PAGE_READWRITE);
        if (!p) { fprintf(stderr, "cannot allocate the guest stack\n"); return -1; }
        stack_lo = (uint32_t)(uintptr_t)p;
    }
#else
    {
        void *p = mmap(NULL, STACK_SZ, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) { fprintf(stderr, "cannot allocate the guest stack\n"); return -1; }
        stack_lo = (uint32_t)(uintptr_t)p;
    }
#endif
    memset((void *)(uintptr_t)stack_lo, 0, STACK_SZ);

    /* Leave a page of slack at the top: the CRT reads a little above its own
     * frame while setting up, and a stack pointer at the very last mapped byte
     * turns that into an access violation before main. */
    g_stack_pointer = stack_lo + STACK_SZ - PAGE;
    g_stack_pointer &= ~0xFu;
    return 0;
}

uint32_t guest_entry(void)      { return g_entry; }
uint32_t guest_image_base(void) { return g_base; }

void guest_init_cpu(CPU *c)
{
    memset(c, 0, sizeof *c);
    c->esp = g_stack_pointer;
    c->eip = g_entry;
    push32(c, GUEST_RETURN_SENTINEL);
}
