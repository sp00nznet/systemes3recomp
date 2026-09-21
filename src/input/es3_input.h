/*
 * es3_input.h - read a human, once, for every ES3 target.
 *
 * The 32-bit runtime already does this inside jvs.c, wired directly to JVS
 * report bytes and analog channels. That is the right shape for a cabinet that
 * speaks JVS over a serial port and the wrong shape for one that does not:
 * Star Wars Battle Pods never opens a port, and its I/O arrives through a
 * library whose node records hold one BYTE per switch and 16-bit analog
 * channels at fixed offsets.
 *
 * What both want is the same and is neither JVS nor Namco-specific: which
 * buttons a person is holding, where the stick is, and whether a coin was just
 * inserted. So that part lives here, with no protocol in it, and each board
 * layer maps the result onto whatever its game reads.
 *
 * jvs.c has not been changed to use this - it is being worked on elsewhere.
 * When it is quiet, its sampler and this one should become one.
 */
#ifndef ES3_INPUT_H
#define ES3_INPUT_H

#include <stdint.h>

/* Axes are signed, centred on zero, and full scale is +/-32000 - the range an
 * XInput thumbstick reports, so a stick passes through unscaled. A board layer
 * converts to whatever its hardware claims to be. */
typedef struct {
    int      x, y;          /* stick: right positive, up positive */
    int      throttle;      /* 0..255, a trigger or a key */
    int      brake;         /* 0..255 */
    unsigned start   : 1;
    unsigned fire    : 1;   /* the main action button */
    unsigned fire2   : 1;
    unsigned up      : 1;
    unsigned down    : 1;
    unsigned left    : 1;
    unsigned right   : 1;
    unsigned service : 1;
    unsigned test    : 1;
    unsigned any     : 1;   /* any of the above - "press any button to start" */
    unsigned coin    : 1;   /* edge, true for one poll per insertion */
} es3_input_t;

/* Samples the keyboard and pad 0. Safe to call from any thread, at any rate;
 * the coin edge is latched so a caller polling at frame rate sees it exactly
 * once. Does nothing and reports nothing pressed when ES3_NO_INPUT is set or
 * when no window of this process has the foreground. */
void es3_input_poll(es3_input_t *out);

#endif /* ES3_INPUT_H */
