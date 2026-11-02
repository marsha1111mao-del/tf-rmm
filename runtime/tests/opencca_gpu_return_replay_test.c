/* SPDX-License-Identifier: BSD-3-Clause */
/* Share the actual-core sparse-PT fixture; hardware callbacks remain models. */
#define main gpu_sparse_fixture_main
#include "opencca_gpu_sparse_cache_test.c"
#undef main

int main(int argc, char **argv)
{
    assert(argc == 2);
    unsigned int scenario = (unsigned int)strtoul(argv[1], NULL, 10);
    assert(scenario < 23U);
    struct gpu_private_result r;
    unsigned long ctx = make_context(&client), bo = make_bo(&client, 513U);
    map(&client, ctx, bo, 0U, VA, 512U);
    map(&client, ctx, bo, 512U, VA + 512U * PAGE, 1U);
    expect(&client, bo, 0U, 513U);
    begin(&client, ctx);
    gpu_private_task_returned(&service, &client, ctx, TOKEN, &r);
    assert(r.status == GPU_PRIVATE_STATE); /* No cache/return cursor yet. */
    do { gpu_private_task_cache(&ops, &service, &client, ctx, TOKEN, &r); }
    while (r.status == GPU_PRIVATE_INCOMPLETE);
    assert(!r.status && device_count == 513U);
    gpu_private_task_returned(&service, &client, ctx, TOKEN, &r);
    assert(r.status == GPU_PRIVATE_STATE); /* Prepared AS is still live. */
    gpu_private_context_quiesce(&ops, &service, &client, ctx, TOKEN, 1UL, &r);
    assert(!r.status);
    gpu_private_task_return(&ops, &service, &client, ctx, TOKEN, &r);
    assert(r.status == GPU_PRIVATE_INCOMPLETE && cpu_count == 512U);
    gpu_private_task_returned(&service, &client, ctx, TOKEN, &r);
    assert(r.status == GPU_PRIVATE_STATE); /* A partial return never certifies. */
    do { gpu_private_task_return(&ops, &service, &client, ctx, TOKEN, &r); }
    while (r.status == GPU_PRIVATE_INCOMPLETE);
    assert(!r.status && cpu_count == 513U);

    struct private_context *c = ctx_lookup(&client, ctx), saved = *c;
    unsigned long saved_slot_owner = slot_owner[c->slot];
    const void *caller = &client, *trusted = &service;
    unsigned long context = ctx, token = TOKEN;
    switch (scenario) {
    case 0: break;
    case 1: trusted = &other; break;
    case 2: caller = &other; break;
    case 3: token++; break;
    case 4: c->return_cursor--; break;
    case 5: c->cache_cursor--; break;
    case 6: c->return_pages++; break;
    case 7: c->pending = 1U; break;
    case 8: c->extension_object = 1UL; break;
    case 9: c->task_refs = 0U; break;
    case 10: c->cache_task++; break;
    case 11: c->live_prepared = true; break;
    case 12: c->quiesced = false; break;
    case 13: c->quarantined = true; break;
    case 14: c->revoked = true; break;
    case 15: c->activated = false; break;
    case 16: slot_owner[c->slot] = ctx + 1UL; break;
    case 17: c->slot = 0U; break;
    case 18: c->slot = GPU_PRIVATE_AS_SLOTS; break;
    case 19: caller = &service; break;
    case 20: trusted = NULL; break;
    case 21: context++; break;
    case 22: token = 0UL; break;
    }
    struct private_context before = *c;
    unsigned int old_cpu = cpu_count, old_device = device_count;
    gpu_private_task_returned(trusted, caller, context, token, &r);
    assert(memcmp(c, &before, sizeof(before)) == 0);
    assert(cpu_count == old_cpu && device_count == old_device);
    if (scenario == 0U) {
        assert(!r.status && r.value[0] == 513UL && !r.value[1] && !r.value[2] && !r.value[3]);
        gpu_private_task_returned(trusted, caller, context, token, &r);
        assert(!r.status && r.value[0] == 513UL && cpu_count == old_cpu);
    } else {
        assert(r.status != GPU_PRIVATE_SUCCESS);
        for (unsigned int i = 0U; i < 4U; i++) assert(!r.value[i]);
    }
    *c = saved; slot_owner[saved.slot] = saved_slot_owner;
    assert(gpu_private_task_retire(&service, &client, ctx, TOKEN));
    gpu_private_task_returned(&service, &client, ctx, TOKEN, &r);
    assert(r.status == GPU_PRIVATE_STATE); /* Retired token cannot replay. */
    gpu_private_context_put(&client, ctx);
    gpu_private_unmap_bo(&ops, &client, ctx, bo, 0UL, VA, 512UL, &r); assert(!r.status);
    gpu_private_unmap_bo(&ops, &client, ctx, bo, 512UL * PAGE, VA + 512UL * PAGE, 1UL, &r); assert(!r.status);
    do { gpu_private_bo_destroy(&client, bo, &r); } while (r.status == GPU_PRIVATE_INCOMPLETE);
    assert(!r.status);
    gpu_private_context_destroy(&ops, &client, ctx, &r); assert(!r.status);
    assert(!gpu_private_owner_busy(&client));
    printf("GPU_PRIVATE_RETURN_REPLAY=PASS scenario=%u pure metadata, incomplete/stale/foreign/lease refusal; models only\n", scenario);
    return 0;
}
