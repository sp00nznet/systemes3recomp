/* Stand-in for the per-game generated file: IAT slot -> import id.
   The addresses are inside the selftest's own fake IAT, not a real image -
   guest_load() is what reads this for a real title, and the first real game is
   what covers it. */
#define IAT_SLOTS(X) \
    X(0x00000000u, 0)
