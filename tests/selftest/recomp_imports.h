/* Stand-in for the per-game generated file, so the runtime builds standalone.
   Fields: id, name, DLL, argument bytes the real callee pops.

   The four here are chosen to cover every shape the runtime has to handle:
   a stdcall Win32 export, a cdecl CRT export that pops nothing, an
   ordinal-only import from a DLL that exists nowhere but a cabinet, and one
   whose purge could not be derived at all. */
#define HLE_IMPORTS(X) \
    X(HLE_Sleep,       "Sleep",       "KERNEL32.dll", 4) \
    X(HLE_memcpy,      "memcpy",      "MSVCR100.dll", 0) \
    X(HLE_ordinal_302, "ordinal_302", "eOkaoDt.dll",  8) \
    X(HLE_D3DXMatrixMultiply, "D3DXMatrixMultiply", "d3dx9_43.dll", -1)
