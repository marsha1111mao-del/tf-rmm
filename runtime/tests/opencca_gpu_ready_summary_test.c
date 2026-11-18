/* SPDX-License-Identifier: BSD-3-Clause */
/* Actual core; AS/visibility/cache callbacks are models, not hardware tests. */
#define main ready_summary_reference_main
#include "opencca_gpu_cache_set_test.c"
#undef main

static bool invalidate_in_barrier(void)
{
	struct gpu_private_result r;
	gpu_private_bo_create(&other, &service, 4096UL, 3UL, &r);
	assert(!r.status);
	return barrier();
}

int main(int argc, char **argv)
{
	assert(argc == 4);
	unsigned int scenario = (unsigned int)strtoul(argv[1], NULL, 10);
	bool optimized = strtoul(argv[2], NULL, 10) != 0UL;
	unsigned int mode = (unsigned int)strtoul(argv[3], NULL, 10);
	assert(scenario < 21U && (mode == 1U || mode == 2U));
	ops.protected_mapping_summary = true;
	unsigned long bo = object(&client, 0U, 8U, mode), ctx = context(&client);
	map(&client, ctx, bo, TEST_VA, 8U);
	if (scenario == 20U) {
		struct gpu_private_result r;
		unsigned long ipa = TEST_IPA + 100U * 4096UL;
		unsigned int pages;
		gpu_private_control_create(&service, 4096UL, &r); assert(!r.status);
		unsigned long control = r.value[0];
		gpu_private_control_append(&ops, &service, control, 0UL, &ipa, 1U, &r); assert(!r.status);
		assert(gpu_private_control_acquire(&ops, &service, control, &pages));
		gpu_private_control_mapping(&ops, &service, &client, ctx, control, 0U, 1U, true, true, &r);
		assert(!r.status);
	}
	begin(&client, ctx); handoff(&client, ctx, 101UL, 0U, false);
	struct private_context *c = ctx_lookup(&client, ctx);
	struct private_cache_set *set = cache_set_for(ctx);
	struct gpu_private_result r;
	assert(gpu_private_task_live_eligible(&ops, &service, &client, ctx, 101UL));
	assert(set->live_epoch == cache_metadata_epoch && c->cache_groups != 0U);
	struct gpu_private_command_range empty = {0};
	assert(gpu_private_task_mark_drained(&ops, &service, &client, ctx, 101UL));
	assert(gpu_private_task_hold_live(&ops, &service, &client, ctx, 101UL, &empty, 1U));
	assert(gpu_private_task_handoff_live(&ops, &service, &client, ctx, 101UL, 102UL));
	unsigned long before = fx_checks;
	unsigned int barrier_before = barriers;
	const void *sender = &service, *owner = &client;
	unsigned long token = 102UL;
	bool expect_failure = false, expect_scan = !optimized;
	if (scenario == 1U) { c->pending = 1U; expect_failure = true; }
	if (scenario == 2U) { c->quarantined = true; expect_failure = true; }
	if (scenario == 3U) { token = 101UL; expect_failure = true; }
	if (scenario == 4U) { owner = &other; expect_failure = true; }
	if (scenario == 5U) { sender = &other; expect_failure = true; }
	if (scenario == 6U) { c->cache_pages = 1U; expect_failure = true; }
	if (scenario == 7U) { c->revoked = true; expect_failure = true; }
	if (scenario == 8U) { ops.cache_barrier = NULL; expect_failure = mode == 1U; }
	if (scenario == 9U) { fail_barrier = barriers + 1U; expect_failure = mode == 1U; }
	if (scenario == 10U) {
		gpu_private_bo_create(&other, &service, 4096UL, 3UL, &r); assert(!r.status);
		expect_scan = true;
	}
	if (scenario == 11U || scenario == 12U || scenario == 13U) {
		/* Model an audited trusted mutation boundary with a bad predicate.
		 * Real mutators are also covered by live-summary/cache-set tests. */
		cache_metadata_invalidate();
		struct private_bo *b = bo_lookup(&client, bo);
		if (scenario == 11U) b->closing = true;
		if (scenario == 12U) b->cache_context = ctx + 1UL;
		if (scenario == 13U) b->hidden--;
		expect_failure = true; expect_scan = true;
	}
	if (scenario == 14U) { cache_metadata_epoch = set->live_epoch = 0UL; expect_scan = true; }
	if (scenario == 15U) { set->live_epoch = ULONG_MAX; cache_metadata_epoch = 0UL; expect_scan = true; }
	if (scenario == 16U) { ops.cache_barrier = invalidate_in_barrier; }
	if (scenario == 17U) {
		gpu_private_task_cache(&ops, sender, owner, ctx, token, &r); assert(!r.status);
		assert(fx_checks - before == (optimized ? 0UL : 2UL));
		before = fx_checks; barrier_before = barriers;
		gpu_private_context_quiesce(&ops, &service, &client, ctx, token, TEST_FW, &r);
		assert(!r.status);
	}
	if (scenario == 18U) { c->extension_object = bo; expect_failure = true; }
	if (scenario == 19U) { c->task_refs = 0U; expect_failure = true; }
	if (scenario == 17U) gpu_private_task_return(&ops, sender, owner, ctx, token, &r);
	else gpu_private_task_cache(&ops, sender, owner, ctx, token, &r);
	if (expect_failure) {
		assert(r.status != GPU_PRIVATE_SUCCESS);
		if (scenario == 11U || scenario == 12U || scenario == 13U)
			assert(fx_checks > before && barriers == barrier_before && c->quarantined);
	} else {
		assert(!r.status && r.value[0] == 0UL);
		assert(fx_checks - before == (expect_scan ? 2UL : 0UL));
		assert(barriers - barrier_before == (mode == 1U ? 1U : 0U));
		assert(c->cache_groups != 0U && bo_lookup(&client, bo)->cache_context == ctx);
		if (scenario == 16U && mode == 1U) {
			assert(set->live_epoch != cache_metadata_epoch);
			before = fx_checks;
			ops.cache_barrier = barrier;
			gpu_private_task_cache(&ops, sender, owner, ctx, token, &r);
			assert(!r.status && fx_checks - before == 2UL);
		}
	}
	printf("GPU_PRIVATE_READY_SUMMARY=PASS scenario=%u mode=%u status=%lu barriers=%u ACTUAL_CORE_MODEL_ONLY\n",
		scenario, mode, r.status, barriers);
	return 0;
}
