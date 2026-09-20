# Stacks and arenas compete for one address space

Measured on Mario Kart Arcade GP DX, from a run that crashed with
`C00000FD` after about ten minutes.

Lifted code carries the guest call graph on the real stack - one C frame per
guest function, plus dispatch in between - so a guest call chain that is
comfortable on a cabinet can exhaust a host thread's stack with no recursion
involved. `crash.c` prints "runaway recursion in the game" when that happens,
and that is an inference rather than a finding: the dispatch trail for the
thread that died showed ordinary work, a `log10f` wrapper calling an import
thunk, and its most frequent address by far was `fabsf`.

## The budget

This game puts **31 threads** into lifted code. Each gets a real stack and a
hybrid arena, and both are reserved out of the same 32-bit address space:

| stack per thread | arena per thread | total | result |
| --- | --- | --- | --- |
| 32 MB | 16 MB | ~1.5 GB | boots, dies after ~10 minutes |
| 64 MB | 16 MB | ~2.5 GB | does not fit - boot stops at 7 of 10 rows |
| 48 MB |  8 MB | ~1.7 GB | boots, ten of ten rows, **thirty minutes with no fault** |

Raising `ES3_THREAD_STACK_MB` alone is therefore not a fix and not even
neutral: at 64 MB the failure looks nothing like an out-of-memory error, it
looks like a boot that stalls part way down the startup checklist, which is
easy to mistake for a regression somewhere else entirely. It was so mistaken
here, for three runs.

The lever is the pair. Arenas and stacks trade against each other, and
`ES3_HYBRID_ARENA_MB=8` with `ES3_THREAD_STACK_MB=48` buys 50% more stack
headroom than the default while still fitting.

## The workaround, and why it is believable

`ES3_HYBRID_ARENA_MB=8 ES3_THREAD_STACK_MB=48` ran thirty minutes and ended
only because the test's own timeout killed it - no `C00000FD`, no SEH event
of any kind, against ten minutes to a stack overflow on the default pair.

That the extra headroom removes the fault rather than postponing it is the
useful part. Something consuming stack without bound would have bought about
fifteen minutes from fifty per cent more stack, not an indefinite run. So the
call depth has a ceiling, and the default simply sits under it.

## What would actually fix it

Frame size. A lifted frame is much larger than the guest frame it stands for,
and that multiplier is what turns a legal call depth into an overflow. Making
it smaller is a pcrecomp concern rather than a per-game one, and it would buy
more than any amount of tuning here.
