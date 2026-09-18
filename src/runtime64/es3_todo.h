/*
 * es3_todo.h - force-included ahead of every generated translation unit.
 *
 * cpu64.h defines RECOMP_TODO as plain abort() unless something defines it
 * first, and that default cannot be left in place: MSVC compiles abort() to
 * __fastfail, which no exception handler and no vectored filter can observe,
 * so the process disappears with 0xC0000409 and produces no output at all. A
 * run that had got further than any before it read as "it crashed somewhere".
 *
 * This has to arrive BEFORE cpu64.h in every generated file, and the obvious
 * way to arrange that does not work: MSVC does not accept function-like macro
 * definitions on the command line, so /D"RECOMP_TODO(va,text)=..." is silently
 * ignored - it compiles, it links, and the default survives. /FI (forced
 * include) is the mechanism that does work.
 */
#ifndef ES3_TODO_H
#define ES3_TODO_H

#include <stdint.h>

/* Reports the guest address, the mnemonic, the lifted call stack and the
 * dispatch trail, then exits. Defined in trace64.c. */
void es3_todo(uint64_t va, const char *text);

#define RECOMP_TODO(va, text) es3_todo((uint64_t)(va), (text))

#endif /* ES3_TODO_H */
