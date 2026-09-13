/* Stand-in for the per-game generated file, so the runtime builds standalone.
   Fields: id, name, DLL, argument bytes the real callee pops.

   Chosen to cover every shape the runtime has to handle: a stdcall Win32
   export, a cdecl CRT export that pops nothing, one whose purge could not be
   derived at all, and - the one that bit us on a real game - the SAME import
   name exported by two different cabinet DLLs. The OKAO Vision libraries
   export by ordinal only, so eOkaoDt and eOkaoGn both import "ordinal_302"
   and they are different functions. Those two take the DLL stem as a prefix
   in their enumerator, exactly as the driver emits them. */
#define HLE_IMPORTS(X) \
    X(HLE_Sleep,  "Sleep",  "KERNEL32.dll", 4) \
    X(HLE_memcpy, "memcpy", "MSVCR100.dll", 0) \
    X(HLE_eOkaoDt_ordinal_302, "ordinal_302", "eOkaoDt.dll", 8) \
    X(HLE_eOkaoGn_ordinal_302, "ordinal_302", "eOkaoGn.dll", 12) \
    X(HLE_D3DXMatrixMultiply, "D3DXMatrixMultiply", "d3dx9_43.dll", -1)
