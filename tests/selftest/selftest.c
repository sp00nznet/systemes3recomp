/*
 * Runtime self-check. Stands in for the generated parts of a game so the
 * runtime can be built and run on its own.
 *
 * Covers the pieces with logic in them and no dependency on a real executable:
 * the dispatch table's search, the import sentinel range (the one constant
 * that is duplicated between the C and the Python, and whose drift would be
 * invisible), the purge unwind, and the board's DLL notes. guest_load() is not
 * covered here - it needs a real PE, and the first title exercises it.
 */

#include <stdio.h>
#include <string.h>

#include "es3_rt.h"

static int g_hit;

void L_00401000(CPU *c) { (void)c; g_hit = 1; }
void L_00401200(CPU *c) { (void)c; g_hit = 2; }
void L_0058FF00(CPU *c) { (void)c; g_hit = 3; }

static int fails;

#define CHECK(cond) \
    do { if (!(cond)) { fprintf(stderr, "FAIL %s:%d  %s\n", \
                                __FILE__, __LINE__, #cond); fails++; } } while (0)

static void test_dispatch(void)
{
    CPU c;
    memset(&c, 0, sizeof c);
    /* Every entry reachable, including the first and last - an off-by-one in
     * the binary search hides at exactly those two. */
    g_hit = 0; dispatch(&c, 0x00401000u); CHECK(g_hit == 1);
    g_hit = 0; dispatch(&c, 0x00401200u); CHECK(g_hit == 2);
    g_hit = 0; dispatch(&c, 0x0058FF00u); CHECK(g_hit == 3);
    CHECK(dispatch_has(0x00401000u));
    CHECK(!dispatch_has(0x00401001u));
}

/* The sentinel range has to be recognised for every id and for nothing else.
 * If HLE_BASE ever drifts from the copy in tools/recomp/driver.py, or the
 * stride stops matching, an import call becomes an unresolved dispatch at an
 * address that looks like it could have been real - which is the worst kind of
 * bug to chase. So this pins the arithmetic in both directions. */
static void test_sentinel_range(void)
{
    unsigned i;
    for (i = 0; i < HLE_COUNT; i++) {
        uint32_t va = HLE_ADDR(i);
        CHECK(HLE_IS_ADDR(va));
        CHECK(HLE_ID_OF(va) == (HleId)i);
    }
    CHECK(!HLE_IS_ADDR(HLE_BASE - 1));
    CHECK(!HLE_IS_ADDR(HLE_BASE + HLE_STRIDE * HLE_COUNT));
    /* And not anywhere a real ES3 image or its heap could be. */
    CHECK(!HLE_IS_ADDR(0x00400000u));
    CHECK(!HLE_IS_ADDR(0x013FFFFFu));
}

static uint32_t g_seen_arg;
static HleId    g_seen_id;

static void fake_sleep(CPU *c, HleId id)
{
    g_seen_arg = A32(0);      /* argument 0, above the pushed return address */
    g_seen_id = id;
    RET(0);
}

static void unwinds_itself(CPU *c, HleId id)
{
    (void)id;
    c->esp += 4u + 12u;       /* what a forwarded callee's own `ret 12` did */
    RET(0x1234);
}

static void test_purge_unwind(void)
{
    uint32_t stack[8];
    CPU c;

    CHECK(hle_bind("Sleep", fake_sleep) == 1);
    CHECK(hle_bind("NotImportedByThisGame", fake_sleep) == 0);

    /* A stdcall import: esp on entry points at the return address, argument 0
     * is the slot above, and the callee pops 4 bytes of arguments. */
    memset(&c, 0, sizeof c);
    stack[0] = 0x00401234u;              /* return address the lifter pushed */
    stack[1] = 250;                      /* Sleep(250) */
    c.esp = (uint32_t)(uintptr_t)&stack[0];
    hle_call(&c, HLE_Sleep);
    CHECK(g_seen_arg == 250);
    CHECK(g_seen_id == HLE_Sleep);
    CHECK(c.esp == (uint32_t)(uintptr_t)&stack[0] + 4u + 4u);

    /* cdecl pops nothing: the return address, and not one byte more. */
    CHECK(hle_purge(HLE_memcpy) == 0);
    /* An ordinal-only import from a DLL that exists nowhere but a cabinet
     * still has a derived purge, which is the whole point of reading it out of
     * the callee's own `ret N`. */
    CHECK(hle_purge(HLE_eOkaoDt_ordinal_302) == 8);
    /* And one that could not be derived says so rather than guessing 0. */
    CHECK(hle_purge(HLE_D3DXMatrixMultiply) == -1);

    /* A handler for an underivable import is allowed, but only if it unwinds
     * for itself - and then its answer is the one that stands. */
    CHECK(hle_bind("D3DXMatrixMultiply", unwinds_itself) == 1);
    memset(&c, 0, sizeof c);
    c.esp = (uint32_t)(uintptr_t)&stack[0];
    hle_call(&c, HLE_D3DXMatrixMultiply);
    CHECK(c.esp == (uint32_t)(uintptr_t)&stack[0] + 4u + 12u);
    CHECK(c.eax == 0x1234);
}

/* The bug this pins: an import's identity is (DLL, name). Two cabinet DLLs
 * exporting the same ordinal must stay two ids with two handlers, or face
 * detection's calls are answered by gender estimation - which produces no
 * error anywhere, just wrong behaviour a long way from the cause. */
static void hit_dt(CPU *c, HleId id) { (void)c; (void)id; g_hit = 101; }
static void hit_gn(CPU *c, HleId id) { (void)c; (void)id; g_hit = 102; }

static void test_dll_qualified_bind(void)
{
    uint32_t stack[4] = { 0x00401234u, 0, 0, 0 };
    CPU c;

    CHECK(hle_bind_dll("eOkaoDt.dll", "ordinal_302", hit_dt) == 1);
    CHECK(hle_bind_dll("eokaogn.DLL", "ordinal_302", hit_gn) == 1);  /* caseless */
    CHECK(hle_bind_dll("eOkaoPt.dll", "ordinal_302", hit_dt) == 0);  /* not imported */

    memset(&c, 0, sizeof c);
    c.esp = (uint32_t)(uintptr_t)&stack[0];
    g_hit = 0; hle_call(&c, HLE_eOkaoDt_ordinal_302); CHECK(g_hit == 101);
    memset(&c, 0, sizeof c);
    c.esp = (uint32_t)(uintptr_t)&stack[0];
    g_hit = 0; hle_call(&c, HLE_eOkaoGn_ordinal_302); CHECK(g_hit == 102);

    /* ...and they can have different purges, because they are different
     * functions that happen to share a number. */
    CHECK(hle_purge(HLE_eOkaoDt_ordinal_302) == 8);
    CHECK(hle_purge(HLE_eOkaoGn_ordinal_302) == 12);
}

static void test_names(void)
{
    CHECK(strcmp(hle_name(HLE_Sleep), "Sleep") == 0);
    CHECK(strcmp(hle_dll(HLE_Sleep), "KERNEL32.dll") == 0);
    CHECK(HLE_COUNT == 5);

    /* The board notes are what turn "eOkaoDt.dll ordinal_302 is not
     * implemented" into a sentence worth reading. */
    CHECK(hle_board_note("eOkaoDt.dll") != NULL);
    CHECK(hle_board_note("eokaodt.DLL") != NULL);     /* DLL names are caseless */
    CHECK(hle_board_note("KERNEL32.dll") == NULL);
}

int main(void)
{
    test_dispatch();
    test_sentinel_range();
    test_purge_unwind();
    test_dll_qualified_bind();
    test_names();
    if (fails) { fprintf(stderr, "%d check(s) failed\n", fails); return 1; }
    printf("ok: dispatch table, sentinel range, purge unwind, "
           "DLL-qualified binding, board notes\n");
    return 0;
}
