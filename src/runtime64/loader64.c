/*
 * loader64.c - map the guest image and wire its imports to the real DLLs.
 *
 * This maps the ORIGINAL executable even though its code has been recompiled,
 * because the code is the only part that was. Everything else the program
 * reads from its own image is still needed exactly where it expects it:
 * .rdata holds every string, vtable, jump table and float constant; .data
 * holds the initialised globals; .rsrc holds the resources; and .text itself
 * holds constant pools that the lifted code reads as data through GVA(). A
 * recompiled build that maps only the sections it thinks are data crashes on
 * the first vtable.
 */

#include "es3_rt64.h"

#include <stdio.h>
#include <string.h>
#include <windows.h>

es3_image_t g_image;
int64_t g_image_delta = 0;

/* Imports, for diagnostics and for the handful that need interception. */
typedef struct {
    uint64_t addr;          /* the real function address */
    char     dll[32];
    char     name[96];
} import_rec_t;

static import_rec_t *g_imports;
static int g_nimports;

const char *es3_import_name(uint64_t addr)
{
    static char buf[160];
    for (int i = 0; i < g_nimports; i++) {
        if (g_imports[i].addr == addr) {
            snprintf(buf, sizeof buf, "%s!%s", g_imports[i].dll, g_imports[i].name);
            return buf;
        }
    }
    return NULL;
}

static void *rva(uint32_t r) { return g_image.base + r; }

int es3_load_image(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "[loader] cannot open %s\n", path); return 0; }
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *raw = (unsigned char *)malloc(fsz);
    if (!raw || fread(raw, 1, fsz, f) != (size_t)fsz) {
        fprintf(stderr, "[loader] short read\n"); fclose(f); return 0;
    }
    fclose(f);

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)raw;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(raw + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        fprintf(stderr, "[loader] not a PE32+ image\n"); free(raw); return 0;
    }

    uint64_t want = nt->OptionalHeader.ImageBase;
    uint64_t size = nt->OptionalHeader.SizeOfImage;

    /* Ask for the preferred base first. Getting it means g_image_delta stays
     * zero and every GVA() in four million lines of generated C is the identity
     * - which is worth trying for, though the .reloc path below is real and
     * exercised when something else already owns 0x140000000. */
    void *base = VirtualAlloc((void *)want, size, MEM_RESERVE | MEM_COMMIT,
                              PAGE_EXECUTE_READWRITE);
    if (!base) {
        base = VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT,
                            PAGE_EXECUTE_READWRITE);
        if (!base) {
            fprintf(stderr, "[loader] VirtualAlloc %llu bytes failed (%lu)\n",
                    (unsigned long long)size, GetLastError());
            free(raw); return 0;
        }
        fprintf(stderr, "[loader] note: preferred base %#llx unavailable, "
                        "loaded at %p, relocating\n",
                (unsigned long long)want, base);
    }

    g_image.base = (uint8_t *)base;
    g_image.preferred = want;
    g_image.size = size;
    g_image_delta = (int64_t)((uint64_t)base - want);

    /* headers, then every section at its virtual address */
    memcpy(base, raw, nt->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        uint32_t vsz = sec[i].Misc.VirtualSize;
        uint32_t rsz = sec[i].SizeOfRawData;
        uint8_t *dst = (uint8_t *)base + sec[i].VirtualAddress;
        if (rsz) memcpy(dst, raw + sec[i].PointerToRawData, rsz < vsz ? rsz : vsz);
        if (vsz > rsz) memset(dst + rsz, 0, vsz - rsz);   /* .bss tail */
        if (!memcmp(sec[i].Name, ".text", 5)) {
            g_image.text_lo = (uint64_t)base + sec[i].VirtualAddress;
            g_image.text_hi = g_image.text_lo + vsz;
        }
    }

    /* ---- relocations, only if we did not get the base we asked for ---- */
    if (g_image_delta) {
        IMAGE_DATA_DIRECTORY d =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        uint8_t *p = (uint8_t *)rva(d.VirtualAddress);
        uint8_t *end = p + d.Size;
        long n = 0;
        while (p < end) {
            IMAGE_BASE_RELOCATION *br = (IMAGE_BASE_RELOCATION *)p;
            if (!br->SizeOfBlock) break;
            uint16_t *ent = (uint16_t *)(br + 1);
            unsigned cnt = (br->SizeOfBlock - sizeof *br) / 2;
            for (unsigned i = 0; i < cnt; i++) {
                /* Only DIR64 matters in a 64-bit image; ABSOLUTE is padding. */
                if ((ent[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                    uint64_t *slot = (uint64_t *)rva(br->VirtualAddress + (ent[i] & 0xFFF));
                    *slot += g_image_delta;
                    n++;
                }
            }
            p += br->SizeOfBlock;
        }
        fprintf(stderr, "[loader] applied %ld relocations (delta %+lld)\n",
                n, (long long)g_image_delta);
    }

    /* ---- imports: resolve to the real DLLs ----
     *
     * The real address goes into the IAT, not a sentinel. The 32-bit runtime
     * uses sentinels because a Win32 import has to be reimplemented and needs
     * to be identified when it is called; here the function on the other side
     * of the slot is the one the game wants, with the ABI it expects, so the
     * honest thing is to put it there. dispatch() then recognises an import by
     * the only property that actually distinguishes one - the target is not a
     * lifted function and not inside the guest image - which also catches a
     * pointer copied out of the IAT and called later, and the vtables that D3D
     * and Wwise hand back. A sentinel scheme only catches the slot itself.
     */
    IMAGE_DATA_DIRECTORY imp =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    int cap = 1024;
    g_imports = (import_rec_t *)calloc(cap, sizeof *g_imports);
    g_nimports = 0;
    int nmissing = 0;

    if (imp.VirtualAddress) {
        IMAGE_IMPORT_DESCRIPTOR *id = (IMAGE_IMPORT_DESCRIPTOR *)rva(imp.VirtualAddress);
        for (; id->Name; id++) {
            const char *dll = (const char *)rva(id->Name);
            HMODULE h = LoadLibraryA(dll);
            if (!h) {
                fprintf(stderr, "[loader] MISSING DLL %s (%lu)\n", dll, GetLastError());
                nmissing++;
                continue;
            }
            uint64_t *thunk = (uint64_t *)rva(id->FirstThunk);
            uint64_t *names = (uint64_t *)rva(id->OriginalFirstThunk
                                              ? id->OriginalFirstThunk
                                              : id->FirstThunk);
            for (int k = 0; names[k]; k++) {
                FARPROC fp;
                char nm[96];
                if (names[k] & 0x8000000000000000ULL) {
                    WORD ord = (WORD)(names[k] & 0xFFFF);
                    fp = GetProcAddress(h, (LPCSTR)(uintptr_t)ord);
                    snprintf(nm, sizeof nm, "#%u", ord);
                } else {
                    IMAGE_IMPORT_BY_NAME *ibn =
                        (IMAGE_IMPORT_BY_NAME *)rva((uint32_t)(names[k] & 0x7FFFFFFF));
                    fp = GetProcAddress(h, ibn->Name);
                    snprintf(nm, sizeof nm, "%s", ibn->Name);
                }
                if (!fp) {
                    fprintf(stderr, "[loader] MISSING %s!%s\n", dll, nm);
                    nmissing++;
                    continue;
                }
                thunk[k] = (uint64_t)fp;
                if (g_nimports == cap) {
                    cap *= 2;
                    g_imports = (import_rec_t *)realloc(g_imports, cap * sizeof *g_imports);
                }
                g_imports[g_nimports].addr = (uint64_t)fp;
                snprintf(g_imports[g_nimports].dll, sizeof g_imports[0].dll, "%s", dll);
                snprintf(g_imports[g_nimports].name, sizeof g_imports[0].name, "%s", nm);
                g_nimports++;
            }
        }
    }

    g_image.entry = (uint64_t)base + nt->OptionalHeader.AddressOfEntryPoint;

    fprintf(stderr, "[loader] %s\n", path);
    fprintf(stderr, "[loader] base %p (wanted %#llx), size %llu KB\n",
            base, (unsigned long long)want, (unsigned long long)(size / 1024));
    fprintf(stderr, "[loader] .text %#llx..%#llx\n",
            (unsigned long long)g_image.text_lo, (unsigned long long)g_image.text_hi);
    fprintf(stderr, "[loader] entry %#llx, %d imports resolved, %d missing\n",
            (unsigned long long)g_image.entry, g_nimports, nmissing);

    free(raw);
    return 1;
}

/* Mapped headroom left ABOVE the initial guest RSP.
 *
 * Not padding. A Win64 function reads memory above its entry RSP as a matter of
 * course - the 32 bytes of shadow space its caller is required to provide, then
 * the fifth argument onwards - and the entry point is a function like any
 * other, called here by nothing. 64 bytes of margin was not enough: the guest
 * faulted reading exactly 0x40 above the stack top, three dispatches in, inside
 * __security_init_cookie. A page and a half covers the widest frame the CRT
 * startup expects to have been handed. */
#define STACK_HEADROOM 0x10000

uint64_t es3_alloc_stack(size_t bytes)
{
    /* A guard page below, so a runaway guest stack faults instead of quietly
     * writing over whatever VirtualAlloc put there first. */
    uint8_t *p = (uint8_t *)VirtualAlloc(NULL, bytes + 0x1000 + STACK_HEADROOM,
                                         MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!p) return 0;
    DWORD old;
    VirtualProtect(p, 0x1000, PAGE_NOACCESS, &old);
    uint64_t top = (uint64_t)(p + 0x1000 + bytes);
    return top & ~(uint64_t)15;
}

void es3_free_image(void)
{
    if (g_image.base) VirtualFree(g_image.base, 0, MEM_RELEASE);
    g_image.base = NULL;
    free(g_imports);
    g_imports = NULL;
    g_nimports = 0;
}
