/* SPDX-License-Identifier: BSD-3-Clause */
/* Fixed workloads compare actual old/new core budgets; hardware is modeled. */
#define main gpu_cache_budget_fixture_main
#include "opencca_gpu_cache_budget_test.c"
#undef main

int main(int argc, char **argv)
{
    assert(argc == 3);
    unsigned int scenario = (unsigned int)strtoul(argv[1], NULL, 10);
    bool reference = strcmp(argv[2], "reference") == 0;
    assert(scenario < 8U);
    assert(CACHE_SCAN_BATCH == (reference ? 4096U : 16384U));
    struct gpu_private_result r;
    unsigned long nc = 0UL, wb = 0UL;
    unsigned int ready_calls = 0U, return_calls = 0U;

    nc_pages = scenario == 1U ? 32769U :
        (scenario == 3U || scenario == 5U || scenario == 7U) ? 0U : 8193U;
    wb_pages = scenario == 2U || scenario == 3U || scenario == 7U ? 513U :
        scenario == 5U ? 8193U : 0U;
    if (nc_pages) {
        nc = make_bo(nc_pages, NC_IPA);
        converting = true;
        do { gpu_private_bo_uncached(&ops, &client, nc, &r); }
        while (r.status == GPU_PRIVATE_INCOMPLETE);
        assert(!r.status && conversion_pages == nc_pages);
        converting = false;
    }
    if (wb_pages) wb = make_bo(wb_pages, WB_IPA);
    gpu_private_context_create(&ops, &client, &service, &r);
    assert(!r.status);
    unsigned long ctx = r.value[0];
    if (nc) map_bo(ctx, nc, VA, nc_pages);
    if (wb) map_bo(ctx, wb, VA + nc_pages * PAGE, wb_pages);
    if (scenario == 4U) damage_pte_at(ctx, 8192U);
    if (scenario == 6U) fail_barrier = true;
    if (scenario == 7U) fail_sync = true;
    assert(gpu_private_context_hold(&service, &client, ctx));
    struct gpu_private_command_range empty = {0};
    assert(gpu_private_task_hold_batch(&ops, &service, &client, ctx, &empty, 1U));
    gpu_private_context_prepare(&ops, &service, &client, ctx, 1UL, &r);
    assert(!r.status);
    do {
        unsigned int before = device_pages;
        gpu_private_task_cache(&ops, &service, &client, ctx, TOKEN, &r);
        assert(device_pages - before <= 512U && ++ready_calls < 100U);
    } while (r.status == GPU_PRIVATE_INCOMPLETE);
    if (scenario >= 4U && scenario != 5U) {
        assert(r.status == GPU_PRIVATE_STATE && ctx_lookup(&client, ctx)->quarantined);
        assert(!gpu_private_task_retire(&service, &client, ctx, TOKEN));
        goto cleanup;
    }
    assert(!r.status && device_pages == wb_pages && r.value[0] == wb_pages);
    unsigned int expected = scenario == 0U ? (reference ? 3U : 1U) :
        scenario == 1U ? (reference ? 9U : 3U) :
        scenario == 2U ? (reference ? 4U : 2U) : scenario == 3U ? 2U : 17U;
    assert(ready_calls == expected);
    gpu_private_context_quiesce(&ops, &service, &client, ctx, TOKEN, 1UL, &r);
    assert(!r.status);
    do {
        unsigned int before = cpu_pages;
        gpu_private_task_return(&ops, &service, &client, ctx, TOKEN, &r);
        assert(cpu_pages - before <= 512U && ++return_calls < 100U);
    } while (r.status == GPU_PRIVATE_INCOMPLETE);
    assert(!r.status && cpu_pages == wb_pages && r.value[0] == wb_pages);
    assert(return_calls == expected);
    assert(gpu_private_task_retire(&service, &client, ctx, TOKEN));
cleanup:
    fail_barrier = fail_sync = false;
    gpu_private_device_revoked(&ops);
    if (nc) {
        do { gpu_private_bo_release(&ops, &client, nc, &r); }
        while (r.status == GPU_PRIVATE_INCOMPLETE);
        assert(!r.status);
    }
    if (wb) {
        do { gpu_private_bo_destroy(&client, wb, &r); }
        while (r.status == GPU_PRIVATE_INCOMPLETE);
        assert(!r.status);
    }
    gpu_private_context_destroy(&ops, &client, ctx, &r);
    assert(!r.status && !gpu_private_owner_busy(&client));
    printf("GPU_PRIVATE_SCAN_WINDOW=PASS scenario=%u budget=%u ready=%u return=%u; models only\n",
        scenario, CACHE_SCAN_BATCH, ready_calls, return_calls);
    return 0;
}
