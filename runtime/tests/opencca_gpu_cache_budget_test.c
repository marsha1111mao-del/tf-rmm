/* SPDX-License-Identifier: BSD-3-Clause */
/* Actual page-table/cache core; ownership, CPU attributes and AS are models. */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "opencca_gpu_private.c"

#define PAGE 4096UL
#define VA 0x200000UL
#define NC_IPA 0x100000UL
#define WB_IPA 0x10000000UL
#define TOKEN 123UL
/* Keep two complete metadata continuations plus a tail at either budget. */
#define NC_PAGES (2U * CACHE_SCAN_BATCH + 1U)
static int client, service, other;
static bool converting, fail_sync, fail_barrier;
static unsigned int device_pages, cpu_pages, barriers, conversion_pages;
static unsigned int nc_pages, wb_pages;
static unsigned long mutate_bo;
static unsigned long pa_of(unsigned long ipa) { return ipa + 0x40000000UL; }
static bool source(const void *owner, unsigned long ipa, unsigned long *pa)
{
    assert(owner == &client);
    if (gpu_private_range_busy(owner, ipa, PAGE)) return false;
    *pa = pa_of(ipa); return true;
}
static bool hide(const void *owner, unsigned long ipa, unsigned long pa)
{ assert(owner == &client && pa == pa_of(ipa)); return true; }
static bool restore(const void *owner, unsigned long ipa, unsigned long pa)
{ assert(owner == &client && pa == pa_of(ipa)); return true; }
static bool clear(unsigned long pa) { assert(pa); return true; }
static bool sync_device(unsigned long pa)
{
    if (converting) {
        assert(pa == pa_of(NC_IPA + conversion_pages * PAGE));
        conversion_pages++; return true;
    }
    assert(device_pages < wb_pages && pa == pa_of(WB_IPA + device_pages * PAGE));
    device_pages++;
    if (mutate_bo) bo_lookup(&client, mutate_bo)->closing = true;
    return !fail_sync;
}
static bool sync_cpu(unsigned long pa)
{
    assert(cpu_pages < wb_pages && pa == pa_of(WB_IPA + cpu_pages * PAGE));
    cpu_pages++; return !fail_sync;
}
static bool barrier(void) { barriers++; return !fail_barrier; }
static unsigned long table_pa(const void *p)
{ return 0x100000000UL + (const unsigned char *)p - (const unsigned char *)tables; }
static void clean(const void *p, size_t bytes) { assert(p && bytes); }
static bool prepare(unsigned long root, unsigned int slot, unsigned long fw, bool existing)
{ (void)existing; assert(root && slot && fw); return true; }
static bool detach(unsigned long root, unsigned int slot, unsigned long fw, bool detached)
{ (void)detached; assert(root && slot && fw); return true; }
static const struct gpu_private_ops ops = {
    .source_page=source, .hide_page=hide, .restore_page=restore,
    .restore_page_uncached=restore, .clear_page=clear, .cache_barrier=barrier,
    .table_pa=table_pa, .clean=clean, .prepare_as=prepare, .detach_as=detach,
    .sync_page_for_device=sync_device, .sync_page_for_cpu=sync_cpu
};
static unsigned long make_bo(unsigned int count, unsigned long ipa)
{
    struct gpu_private_result r; unsigned long ipas[512];
    gpu_private_bo_create(&client, &service, count * PAGE, 3, &r); assert(!r.status);
    unsigned long bo = r.value[0];
    for (unsigned int first = 0; first < count; first += 512) {
        unsigned int n = count - first; if (n > 512) n = 512;
        for (unsigned int i = 0; i < n; i++) ipas[i] = ipa + (first + i) * PAGE;
        gpu_private_bo_append(&ops, &client, bo, first * PAGE, ipas, n, &r); assert(!r.status);
    }
    return bo;
}
static void map_bo(unsigned long ctx, unsigned long bo, unsigned long va, unsigned int pages)
{
    struct gpu_private_result r;
    for (unsigned int first = 0; first < pages; first += 512) {
        unsigned int n = pages - first; if (n > 512) n = 512;
        gpu_private_map(&ops, &client, ctx, bo, first * PAGE, va + first * PAGE, n, 3|8, &r);
        assert(!r.status);
    }
}
static void damage_pte_at(unsigned long ctx, unsigned int page)
{
    unsigned long va = VA + page * PAGE;
    unsigned int table = walk(&ops, ctx_lookup(&client, ctx), va, NULL);
    tables[table][(va >> 12) & 511] &= ~PTE_AF;
}
int main(int argc, char **argv)
{
    assert(argc == 2);
    unsigned int scenario = (unsigned int)strtoul(argv[1], NULL, 10); assert(scenario < 21);
    struct gpu_private_result r;
    unsigned long ctx, nc = 0, wb = 0, nc2 = 0;
    unsigned int ready_calls = 0, return_calls = 0;
    nc_pages = scenario == 10 ? 0 : NC_PAGES;
    wb_pages = scenario == 1 ? 513 : (scenario == 6 || scenario == 20) ? 1 : scenario == 10 ? NC_PAGES : 0;
    if (nc_pages) {
        nc = make_bo(nc_pages, NC_IPA); converting = true;
        do {
            if (scenario == 9) gpu_private_bo_seal(&ops, &client, nc, &r);
            else gpu_private_bo_uncached(&ops, &client, nc, &r);
        } while (r.status == GPU_PRIVATE_INCOMPLETE);
        assert(!r.status && conversion_pages == nc_pages); converting = false;
    }
    if (wb_pages) wb = make_bo(wb_pages, WB_IPA);
    if (scenario >= 12 && scenario <= 16) {
        nc2 = make_bo(1, NC_IPA + NC_PAGES * PAGE);
        converting = true;
        gpu_private_bo_uncached(&ops, &client, nc2, &r);
        assert(!r.status); converting = false;
    }
    gpu_private_context_create(&ops, &client, &service, &r); assert(!r.status); ctx = r.value[0];
    if (nc) map_bo(ctx, nc, VA, nc_pages);
    if (wb) map_bo(ctx, wb, VA + nc_pages * PAGE, wb_pages);
    if (nc2) map_bo(ctx, nc2, VA + NC_PAGES * PAGE, 1);
    if (scenario == 20) {
        map_bo(ctx, nc, VA + (NC_PAGES + 1UL) * PAGE, 1);
        mutate_bo = nc;
    }
    if (scenario == 11) damage_pte_at(ctx, 100);
    if (scenario == 19) {
        unsigned int t = walk(&ops, ctx_lookup(&client, ctx), VA + 100 * PAGE, NULL);
        leaf_object[t][100] = GPU_PRIVATE_OBJECTS + 1U;
    }
    if (nc2) {
        struct private_bo *b = bo_lookup(&client, nc2);
        if (scenario == 12) b->owner = &other;
        if (scenario == 13) b->hidden--;
        if (scenario == 14) b->service = &other;
        if (scenario == 15) b->closing = true;
        if (scenario == 16) b->cache_context = 1UL;
    }
    assert(gpu_private_context_hold(&service, &client, ctx));
    for (unsigned int round = 0; round < (scenario == 8 ? 2U : 1U); round++) {
        struct gpu_private_command_range empty = {0};
        device_pages = cpu_pages = ready_calls = return_calls = 0;
        assert(gpu_private_task_hold_batch(&ops, &service, &client, ctx, &empty, 1));
        gpu_private_context_prepare(&ops, &service, &client, ctx, 1, &r); assert(!r.status);
        do {
            unsigned int before = device_pages;
            unsigned int old_cursor = ctx_lookup(&client, ctx)->cache_cursor;
            if (scenario == 2 && ready_calls == 1) damage_pte_at(ctx, CACHE_SCAN_BATCH + 904U);
            if (scenario == 17 && ready_calls == 1) bo_lookup(&client, nc)->closing = true;
            if (scenario == 3 && ready_calls == 1) bo_lookup(&client, nc)->owner = &other;
            if (scenario == 4 && ready_calls == 1) bo_lookup(&client, nc)->hidden--;
            if (scenario == 5 && ready_calls == 1) fail_barrier = true;
            if (scenario == 6 && ready_calls == 1) fail_sync = true;
            gpu_private_task_cache(&ops, &service, &client, ctx, TOKEN + round, &r);
            assert(device_pages - before <= 512 && ++ready_calls < 100);
            /* Full dense metadata must still yield at a bounded cursor. */
            if (ready_calls == 1 && nc_pages && scenario != 11 && scenario != 19) {
                assert(r.status == GPU_PRIVATE_INCOMPLETE);
                assert(ctx_lookup(&client, ctx)->cache_cursor > old_cursor);
                unsigned int visited = 0;
                for (unsigned int i = 0; i < ctx_lookup(&client, ctx)->cache_cursor; i++)
                    visited += leaf_object[i / ENTRIES][i % ENTRIES] != 0;
                assert(visited > CACHE_SCAN_BATCH - 96U && visited <= CACHE_SCAN_BATCH);
            }
        } while (r.status == GPU_PRIVATE_INCOMPLETE);
        if ((scenario >= 2 && scenario <= 6) || (scenario >= 11 && scenario <= 17) || scenario >= 19) {
            assert(r.status == GPU_PRIVATE_STATE && ctx_lookup(&client, ctx)->quarantined);
            assert(!gpu_private_task_retire(&service, &client, ctx, TOKEN));
            if (scenario == 3) objects[(nc & 0xffffUL) - 1].owner = &client;
            if (scenario == 4) bo_lookup(&client, nc)->hidden++;
            goto cleanup;
        }
        assert(!r.status && r.value[0] == wb_pages && device_pages == wb_pages);
        if (nc_pages) assert(ready_calls == (scenario == 1 ? 4U : 3U));
        else assert(ready_calls >= (wb_pages + 511U) / 512U &&
                    ready_calls <= (wb_pages + 511U) / 512U + 1U);
        gpu_private_context_quiesce(&ops, &service, &client, ctx, TOKEN + round, 1, &r); assert(!r.status);
        if (scenario == 7 || scenario == 18)
            damage_pte_at(ctx, scenario == 18 ? 100U : CACHE_SCAN_BATCH + 904U);
        do {
            unsigned int before = cpu_pages;
            gpu_private_task_return(&ops, &service, &client, ctx, TOKEN + round, &r);
            assert(cpu_pages - before <= 512 && ++return_calls < 100);
        } while (r.status == GPU_PRIVATE_INCOMPLETE);
        if (scenario == 7 || scenario == 18) {
            assert(r.status == GPU_PRIVATE_STATE && ctx_lookup(&client, ctx)->quarantined);
            assert(!gpu_private_task_retire(&service, &client, ctx, TOKEN)); goto cleanup;
        }
        assert(!r.status && r.value[0] == wb_pages && cpu_pages == wb_pages);
        assert(return_calls == ready_calls);
        assert(gpu_private_task_retire(&service, &client, ctx, TOKEN + round));
        if (nc) assert(!bo_lookup(&client, nc)->cache_context);
        if (wb) assert(!bo_lookup(&client, wb)->cache_context);
    }
cleanup:
    fail_barrier = fail_sync = false; mutate_bo = 0;
    if (nc) bo_lookup(&client, nc)->closing = false;
    if (nc2) {
        struct private_bo *b = &objects[(nc2 & 0xffffUL) - 1U];
        b->owner = &client; b->service = &service; b->closing = false;
        if (scenario == 13) b->hidden++;
        b->cache_context = 0UL;
    }
    /* Invalid tags are injected only into trusted-model storage. Restore
     * that corruption so the independent trusted-reset teardown can run.
     */
    if (scenario == 19) {
        unsigned int t = walk(&ops, ctx_lookup(&client, ctx), VA + 100 * PAGE, NULL);
        leaf_object[t][100] = (unsigned short)(nc & 0xffffUL);
    }
    gpu_private_context_put(&client, ctx);
    gpu_private_device_revoked(&ops);
    if (nc) {
        do { gpu_private_bo_release(&ops, &client, nc, &r); } while (r.status == GPU_PRIVATE_INCOMPLETE);
        assert(!r.status);
    }
    if (nc2) {
        do { gpu_private_bo_release(&ops, &client, nc2, &r); } while (r.status == GPU_PRIVATE_INCOMPLETE);
        assert(!r.status);
    }
    if (wb) {
        do { gpu_private_bo_destroy(&client, wb, &r); } while (r.status == GPU_PRIVATE_INCOMPLETE);
        assert(!r.status);
    }
    gpu_private_context_destroy(&ops, &client, ctx, &r); assert(!r.status);
    assert(!gpu_private_owner_busy(&client));
    printf("GPU_PRIVATE_CACHE_BUDGET=PASS scenario=%u ready_calls=%u return_calls=%u; models only\n", scenario, ready_calls, return_calls);
    return 0;
}
