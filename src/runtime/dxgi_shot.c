/*
 * dxgi_shot.c - what the game is actually drawing, read out of the back buffer.
 *
 * "Is it rendering?" is the hardest question to answer about a recompiled game
 * and the easiest to answer wrongly. A screenshot of the window is not an
 * answer: PrintWindow asks a window to paint itself and a game does not paint,
 * it presents, so a title that is drawing perfectly photographs as a black
 * rectangle. Reading the desktop instead needs a desktop the capturing process
 * can reach, which over a remote session it may not have.
 *
 * The back buffer has no such problem. It is in this process, it is the frame
 * the game is about to show, and copying it needs nothing but the swap chain
 * the game already made.
 *
 * ES3_SHOT=<n> writes the nth presented frame to es3_frame_<n>.bmp and says
 * how much of it is not black - which is the number the question was really
 * asking. ES3_SHOT=1,60,600 takes several.
 *
 * Before Present, not after: a swap chain created with DXGI_SWAP_EFFECT_DISCARD
 * - which is what a 2010-era title asks for - may have nothing in the back
 * buffer once Present has returned.
 *
 * BMP because it is twelve lines and no library. The point is evidence, not a
 * good image format.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define COBJMACROS
#include <windows.h>
#include <dxgi.h>
#include <d3d10.h>

#include "es3_rt.h"

/* Our own copies, so this needs no import library for two constants. */
static const GUID IID_Tex2D_ =
    { 0x9B7E4C04, 0x342C, 0x4106,
      { 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89, 0xF0 } };
static const GUID IID_Dev_ =
    { 0x9B7E4C0F, 0x342C, 0x4106,
      { 0xA1, 0x9F, 0x4F, 0x27, 0x04, 0xF6, 0x89, 0xF0 } };

#define MAX_WANTED 32     /* enough to shoot one frame per press of a switch sweep */
static unsigned g_want[MAX_WANTED];
static unsigned g_nwant;
static int g_read;
static unsigned g_frame;

static void shot_init(void)
{
    const char *e = getenv("ES3_SHOT");
    g_read = 1;
    while (e && *e && g_nwant < MAX_WANTED) {
        char *end;
        unsigned long v = strtoul(e, &end, 10);
        if (end == e) break;
        g_want[g_nwant++] = (unsigned)v;
        e = *end == ',' ? end + 1 : end;
    }
    if (g_nwant)
        fprintf(stderr, "[shot] will save %u presented frame(s)\n", g_nwant);
}

/* Bottom-up 24-bit BGR, which is the one BMP layout every viewer agrees on. */
static int write_bmp(const char *path, const unsigned char *px, unsigned w,
                     unsigned h, unsigned pitch, int bgra, unsigned *lit)
{
    FILE *f = fopen(path, "wb");
    unsigned row = (w * 3 + 3) & ~3u, y, x;
    unsigned char *line;
    unsigned char hdr[54];
    unsigned size = 54 + row * h;

    if (!f) return 0;
    line = (unsigned char *)calloc(row, 1);
    if (!line) { fclose(f); return 0; }

    memset(hdr, 0, sizeof hdr);
    hdr[0] = 'B'; hdr[1] = 'M';
    memcpy(hdr + 2, &size, 4);
    hdr[10] = 54;
    hdr[14] = 40;
    memcpy(hdr + 18, &w, 4);
    memcpy(hdr + 22, &h, 4);
    hdr[26] = 1;
    hdr[28] = 24;
    memcpy(hdr + 34, &row, 4);
    fwrite(hdr, 1, sizeof hdr, f);

    *lit = 0;
    for (y = 0; y < h; y++) {
        const unsigned char *src = px + (size_t)(h - 1 - y) * pitch;
        for (x = 0; x < w; x++) {
            unsigned char r = src[x * 4 + (bgra ? 2 : 0)];
            unsigned char g = src[x * 4 + 1];
            unsigned char b = src[x * 4 + (bgra ? 0 : 2)];
            line[x * 3 + 0] = b;
            line[x * 3 + 1] = g;
            line[x * 3 + 2] = r;
            if (r > 12 || g > 12 || b > 12) (*lit)++;
        }
        fwrite(line, 1, row, f);
    }
    free(line);
    fclose(f);
    return 1;
}

/* Capture the next frame presented, whenever that is.
 *
 * ES3_SHOT names frames by number, which is the right handle when the
 * question is "what did it look like at frame 3000". It is the wrong one
 * when the question is "what did that button do", because the presser and
 * the frame counter run on different clocks and land differently every run.
 * This is the other handle. */
static volatile LONG g_shot_now;

void es3_shot_now(void) { InterlockedExchange(&g_shot_now, 1); }

void es3_dxgi_present(uint32_t swapchain)
{
    IDXGISwapChain *sc = (IDXGISwapChain *)(uintptr_t)swapchain;
    ID3D10Texture2D *back = NULL, *stage = NULL;
    ID3D10Device *dev = NULL;
    D3D10_TEXTURE2D_DESC desc;
    D3D10_MAPPED_TEXTURE2D map;
    unsigned n, i, lit = 0;
    char path[64];
    int want = 0;

    if (!g_read) shot_init();
    n = ++g_frame;
    if (!sc) return;
    for (i = 0; i < g_nwant; i++) if (g_want[i] == n) want = 1;
    /* Asked for by something that knows WHEN it wants one - see
     * es3_shot_now(). A frame number cannot express "right after I pressed
     * that", because the frame counter and any other clock in this process
     * drift apart from one run to the next. */
    if (InterlockedExchange(&g_shot_now, 0)) want = 1;
    if (!want) return;

    if (FAILED(IDXGISwapChain_GetBuffer(sc, 0, &IID_Tex2D_, (void **)&back))) {
        fprintf(stderr, "[shot] frame %u: no back buffer\n", n);
        return;
    }
    if (FAILED(IDXGISwapChain_GetDevice(sc, &IID_Dev_, (void **)&dev))) {
        fprintf(stderr, "[shot] frame %u: no device\n", n);
        ID3D10Texture2D_Release(back);
        return;
    }

    ID3D10Texture2D_GetDesc(back, &desc);
    /* The same surface, but readable by us rather than by the GPU. */
    desc.Usage = D3D10_USAGE_STAGING;
    desc.BindFlags = 0;
    desc.CPUAccessFlags = D3D10_CPU_ACCESS_READ;
    desc.MiscFlags = 0;
    if (SUCCEEDED(ID3D10Device_CreateTexture2D(dev, &desc, NULL, &stage))) {
        ID3D10Device_CopyResource(dev, (ID3D10Resource *)stage,
                                  (ID3D10Resource *)back);
        if (SUCCEEDED(ID3D10Texture2D_Map(stage, 0, D3D10_MAP_READ, 0, &map))) {
            unsigned total = desc.Width * desc.Height;
            sprintf(path, "es3_frame_%u.bmp", n);
            if (write_bmp(path, (const unsigned char *)map.pData, desc.Width,
                          desc.Height, map.RowPitch,
                          desc.Format == DXGI_FORMAT_B8G8R8A8_UNORM ||
                          desc.Format == DXGI_FORMAT_B8G8R8X8_UNORM,
                          &lit))
                fprintf(stderr, "\n[shot] frame %u -> %s  %ux%u, %u of %u "
                                "pixels are not black (%u%%)\n\n",
                        n, path, desc.Width, desc.Height, lit, total,
                        total ? lit * 100 / total : 0);
            ID3D10Texture2D_Unmap(stage, 0);
        } else {
            fprintf(stderr, "[shot] frame %u: the staging copy would not map\n", n);
        }
        ID3D10Texture2D_Release(stage);
    } else {
        fprintf(stderr, "[shot] frame %u: no staging texture (format %u)\n",
                n, (unsigned)desc.Format);
    }
    ID3D10Device_Release(dev);
    ID3D10Texture2D_Release(back);
    fflush(stderr);
}

#else
void es3_dxgi_present(uint32_t swapchain) { (void)swapchain; }
#endif
