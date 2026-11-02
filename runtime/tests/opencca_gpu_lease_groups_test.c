/* SPDX-License-Identifier: BSD-3-Clause */
/* Actual PT/lease core, synthetic hardware callbacks: no physical proof. */
#define main gpu_sparse_fixture_main
#include "opencca_gpu_sparse_cache_test.c"
#undef main

static unsigned long handles[GPU_PRIVATE_OBJECTS];

static void populate(unsigned int index)
{
    struct gpu_private_result r;
    unsigned long ipas[32];

    for (unsigned int i = 0; i < 32U; i++) {
        ipas[i] = next_ipa;
        next_ipa += PAGE;
    }
    gpu_private_bo_append(&ops, &client, handles[index], 0UL, ipas, 32U, &r);
    assert(!r.status);
}

static void ready(unsigned long ctx)
{
    struct gpu_private_result r;

    device_count = 0U;
    do { gpu_private_task_cache(&ops, &service, &client, ctx, TOKEN, &r); }
    while (r.status == GPU_PRIVATE_INCOMPLETE);
    assert(!r.status && device_count == expected_count);
}

static void returned(unsigned long ctx)
{
    struct gpu_private_result r;

    cpu_count = 0U;
    gpu_private_context_quiesce(&ops, &service, &client, ctx, TOKEN, 1UL, &r);
    assert(!r.status);
    do { gpu_private_task_return(&ops, &service, &client, ctx, TOKEN, &r); }
    while (r.status == GPU_PRIVATE_INCOMPLETE);
    assert(!r.status && cpu_count == expected_count);
}

static bool extend(unsigned long root, unsigned int slot, unsigned long fw)
{ assert(root && slot && fw); return true; }

int main(int argc, char **argv)
{
    assert(argc == 2);
    unsigned int scenario = (unsigned int)strtoul(argv[1], NULL, 10);
    assert(scenario < 26U);
    assert(sizeof(struct private_context) == 112U && sizeof(struct private_bo) == 600U);
    struct gpu_private_result r;
    unsigned long ctx = make_context(&client);
    struct private_context *c = ctx_lookup(&client, ctx);
    assert(!c->cache_groups);
    for (unsigned int i = 0; i < GPU_PRIVATE_OBJECTS; i++) {
        gpu_private_bo_create(&client, &service, 32UL * PAGE, 3UL, &r);
        assert(!r.status);
        handles[i] = r.value[0];
        assert(bo_lookup(&client, handles[i]) == &objects[i]);
    }
    unsigned int slots[3], count = 0U;
    if (scenario < 16U) {
        unsigned int last = (scenario + 1U) * CACHE_LEASE_GROUP_SIZE;
        if (last > GPU_PRIVATE_OBJECTS) last = GPU_PRIVATE_OBJECTS;
        /* Small configurable tables can have empty trailing groups. */
        if (scenario * CACHE_LEASE_GROUP_SIZE < GPU_PRIVATE_OBJECTS)
            slots[count++] = last - 1U;
    } else if (scenario != 23U && scenario != 24U && scenario != 25U) {
        slots[count++] = 0U;
        slots[count++] = CACHE_LEASE_GROUP_SIZE;
        slots[count++] = GPU_PRIVATE_OBJECTS - 1U;
    }
    uint16_t bits = 0U;
    for (unsigned int i = 0; i < count; i++) {
        populate(slots[i]);
        map(&client, ctx, handles[slots[i]], 0U, VA + i * PAGE, 1U);
        expect(&client, handles[slots[i]], 0U, 1U);
        bits |= (uint16_t)(1U << (slots[i] / CACHE_LEASE_GROUP_SIZE));
    }
    if (scenario == 23U || scenario == 24U) {
        /* Live heap extension is a separate lease-acquisition path. */
        unsigned int index = GPU_PRIVATE_OBJECTS - 1U;
        populate(index);
        begin(&client, ctx);
        ready(ctx);
        assert(!c->cache_groups);
        expected_count = 0U;
        expect(&client, handles[index], 0U, 32U);
        struct gpu_private_ops extension_ops = ops;
        extension_ops.extend_as = extend;
        fail_sync = scenario == 24U;
        gpu_private_task_extend(&extension_ops, &service, &client, ctx, TOKEN,
                               handles[index], VA, 1UL, &r);
        assert(c->cache_groups == (uint16_t)(1U << (index / CACHE_LEASE_GROUP_SIZE)));
        assert(objects[index].cache_context == ctx);
        if (fail_sync) {
            assert(r.status == GPU_PRIVATE_STATE && c->quarantined);
            assert(!gpu_private_task_retire(&service, &client, ctx, TOKEN));
        } else {
            assert(!r.status && device_count == 32U);
            returned(ctx);
            assert(gpu_private_task_retire(&service, &client, ctx, TOKEN));
            assert(!c->cache_groups && !objects[index].cache_context);
        }
        goto cleanup;
    }
    begin(&client, ctx);
    if (scenario == 21U) {
        fail_sync = true;
        gpu_private_task_cache(&ops, &service, &client, ctx, TOKEN, &r);
        assert(r.status == GPU_PRIVATE_STATE && c->quarantined);
        assert(c->cache_groups == 1U && objects[0].cache_context == ctx);
        assert(!gpu_private_task_retire(&service, &client, ctx, TOKEN));
        goto cleanup;
    }
    ready(ctx);
    assert(c->cache_groups == bits);
    returned(ctx);
    if (scenario >= 17U && scenario <= 19U) {
        /* Invalid later group must not release a valid earlier lease. */
        struct private_bo *last = &objects[GPU_PRIVATE_OBJECTS - 1U], saved = *last;
        if (scenario == 17U) last->owner = &other;
        if (scenario == 18U) last->service = &other;
        if (scenario == 19U) last->control = true;
        struct private_context before = *c;
        assert(!gpu_private_task_retire(&service, &client, ctx, TOKEN));
        assert(!memcmp(&before, c, sizeof(before)));
        for (unsigned int i = 0; i < count; i++) assert(objects[slots[i]].cache_context == ctx);
        *last = saved;
    }
    unsigned long second = 0UL;
    if (scenario == 20U) {
        /* A second context's real lease in the SAME selected group survives. */
        second = make_context(&client);
        populate(1U);
        map(&client, second, handles[1], 0U, VA, 1U);
        expected_count = 0U;
        expect(&client, handles[1], 0U, 1U);
        begin(&client, second);
        ready(second);
        returned(second);
        assert(objects[1].cache_context == second);
    }
    assert(gpu_private_task_retire(&service, &client, ctx, TOKEN));
    assert(!c->cache_groups);
    for (unsigned int i = 0; i < count; i++) assert(!objects[slots[i]].cache_context);
    if (second) {
        assert(objects[1].cache_context == second && ctx_lookup(&client, second)->cache_groups == 1U);
        assert(gpu_private_task_retire(&service, &client, second, TOKEN));
    }
    gpu_private_context_put(&client, ctx);
    if (scenario == 22U) {
        /* Retired context must reacquire its complete summary next task. */
        exercise(&client, ctx);
        assert(!c->cache_groups);
    }
cleanup:
    gpu_private_device_revoked(&ops);
    for (unsigned int i = 0; i < GPU_PRIVATE_CONTEXTS; i++) assert(!contexts[i].cache_groups);
    for (unsigned int i = 0; i < GPU_PRIVATE_OBJECTS; i++) {
        assert(!objects[i].cache_context);
        do { gpu_private_bo_destroy(&client, handles[i], &r); }
        while (r.status == GPU_PRIVATE_INCOMPLETE);
        assert(!r.status);
    }
    for (unsigned int i = 0; i < GPU_PRIVATE_CONTEXTS; i++) {
        if (contexts[i].handle) {
            gpu_private_context_destroy(&ops, &client, contexts[i].handle, &r);
            assert(!r.status);
        }
    }
    assert(!gpu_private_owner_busy(&client));
    printf("GPU_PRIVATE_LEASE_GROUPS=PASS scenario=%u objects=%u; models only\n", scenario, GPU_PRIVATE_OBJECTS);
    return 0;
}
