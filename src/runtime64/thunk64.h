/*
 * thunk64.h - the frame thunk64.asm reads.
 *
 * The layout is fixed and asserted, because the assembly addresses it by
 * hardcoded byte offsets. A field inserted above one of these would otherwise
 * change what the thunk reads with nothing to say so - the compiler is happy,
 * the assembler is happy, and the game receives its third argument in the
 * register meant for its fourth.
 */
#ifndef ES3_THUNK64_H
#define ES3_THUNK64_H

#include "cpu64.h"

/* How many stack argument slots to copy across on a native call.
 *
 * The IAT says nothing about a function's arity, so there is no right answer
 * available at the call site - only a window. 24 covers the widest thing this
 * game calls (D3D9's CreateDevice family and the Wwise init structs are the
 * long ones) with room to spare. Copying too much is harmless: the callee only
 * reads up to its own argument count, and the source is the guest's own stack.
 * Copying too little would pass garbage.
 */
#define HLE_STACK_ARGS 24

typedef struct {
    void    *fn;          /*   0 */
    uint64_t rcx;         /*   8 */
    uint64_t rdx;         /*  16 */
    uint64_t r8;          /*  24 */
    uint64_t r9;          /*  32 */
    uint64_t stack;       /*  40 - guest address of the 5th-argument slot */
    uint64_t nstack;      /*  48 - qwords to copy from there */
    uint64_t _pad0;       /*  56 - so the XMMs land 16-aligned */
    XMM      x0;          /*  64 */
    XMM      x1;          /*  80 */
    XMM      x2;          /*  96 */
    XMM      x3;          /* 112 */
    uint64_t rax_out;     /* 128 */
    uint64_t _pad1;       /* 136 */
    XMM      xmm0_out;    /* 144 */
} HLEFRAME;

#if defined(_MSC_VER) || __STDC_VERSION__ >= 201112L
#define ES3_ASSERT_OFF(field, off) \
    typedef char es3_off_##field[(offsetof(HLEFRAME, field) == (off)) ? 1 : -1]
#include <stddef.h>
ES3_ASSERT_OFF(fn, 0);
ES3_ASSERT_OFF(rcx, 8);
ES3_ASSERT_OFF(rdx, 16);
ES3_ASSERT_OFF(r8, 24);
ES3_ASSERT_OFF(r9, 32);
ES3_ASSERT_OFF(stack, 40);
ES3_ASSERT_OFF(nstack, 48);
ES3_ASSERT_OFF(x0, 64);
ES3_ASSERT_OFF(x1, 80);
ES3_ASSERT_OFF(x2, 96);
ES3_ASSERT_OFF(x3, 112);
ES3_ASSERT_OFF(rax_out, 128);
ES3_ASSERT_OFF(xmm0_out, 144);
#endif

/* Implemented in thunk64.asm. */
void hle_invoke(HLEFRAME *f);

#endif /* ES3_THUNK64_H */
