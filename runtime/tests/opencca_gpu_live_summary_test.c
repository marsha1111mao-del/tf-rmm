/* SPDX-License-Identifier: BSD-3-Clause */
/* Actual memory core; AS, visibility and physical cache operations are models. */
#define main live_summary_reference_main
#include "opencca_gpu_cache_set_test.c"
#undef main

static unsigned long clean_context;
static unsigned int clean_observations;
static void summary_clean(const void *p, size_t size)
{
	clean(p, size);
	assert(gpu_private_task_live_eligible(&ops, &service, &client, clean_context, 101UL));
	clean_observations++;
}

int main(int argc, char **argv)
{
	assert(argc == 2);
	unsigned int scenario = (unsigned int)strtoul(argv[1], NULL, 10);
	assert(scenario < 20U);
	ops.protected_mapping_summary = true;
	unsigned long bo = object(&client, 0U, 8U, 1U), ctx = context(&client);
	map(&client, ctx, bo, TEST_VA, 8U);
	if (scenario == 19U) {
		/* FS/FT hint BO participates in the real mapping and lease set. */
		unsigned long hint = object(&client, 100U, 1U, 1U);
		struct gpu_private_result mapped;
		gpu_private_map(&ops, &client, ctx, hint, 0UL, TEST_VA + 0x10000UL,
			1U, GPU_PRIVATE_READ | GPU_PRIVATE_WRITE, &mapped);
		assert(!mapped.status);
	}
	begin(&client, ctx);
	handoff(&client, ctx, 101UL, 0U, false);
	struct private_context *c = ctx_lookup(&client, ctx);
	struct private_cache_set *set = cache_set_for(ctx);
	struct gpu_private_result result;
	assert(set->live_epoch == 0UL);
	assert(gpu_private_task_live_eligible(&ops, &service, &client, ctx, 101UL));
	assert(set->live_epoch == cache_metadata_epoch && set->live_uncached);
	unsigned long saved_epoch = cache_metadata_epoch;
	unsigned int sync_before = device_syncs + cpu_syncs, barrier_before = barriers;
	if (scenario == 19U) {
		unsigned long va = TEST_VA + 0x10000UL;
		assert(gpu_private_task_hint_check(&ops, &service, &client, ctx, va));
		assert(!gpu_private_task_hint_check(&ops, &other, &client, ctx, va));
		assert(!gpu_private_task_hint_check(&ops, &service, &other, ctx, va));
		unsigned int table = walk(&ops, c, va, NULL), leaf = (va >> 12U) & 511UL;
		assert(table < GPU_PRIVATE_TABLES);
		uint64_t saved_pte = tables[table][leaf];
		tables[table][leaf] ^= 4096UL;
		assert(!gpu_private_task_hint_check(&ops, &service, &client, ctx, va));
		tables[table][leaf] = saved_pte;
		assert(cache_metadata_epoch == saved_epoch && set->live_epoch == saved_epoch);
		assert(gpu_private_task_live_eligible(&ops, &service, &client, ctx, 101UL));
		assert(gpu_private_task_hint_check(&ops, &service, &client, ctx, va));
	} else if (scenario == 0U) {
		for (unsigned int i = 0U; i < 100U; i++)
			assert(gpu_private_task_live_eligible(&ops, &service, &client, ctx, 101UL));
		assert(cache_metadata_epoch == saved_epoch && set->live_epoch == saved_epoch);
	} else if (scenario >= 1U && scenario <= 8U) {
		/* A warm BO summary never substitutes for fresh context guards. */
		if (scenario == 1U) c->quarantined = true;
		if (scenario == 2U) c->pending = 1U;
		if (scenario == 3U) c->cache_task++;
		if (scenario == 4U) c->mapping_epoch++;
		if (scenario == 5U) slot_owner[c->slot] = 0UL;
		if (scenario == 6U) c->return_cursor = 1U;
		if (scenario == 7U) c->cache_pages = 1U;
		if (scenario == 8U) ops.cache_barrier = NULL;
		assert(!gpu_private_task_live_eligible(&ops, &service, &client, ctx, 101UL));
	} else if (scenario == 9U) {
		assert(!gpu_private_task_live_eligible(&ops, &other, &client, ctx, 101UL));
		assert(!gpu_private_task_live_eligible(&ops, &service, &other, ctx, 101UL));
		assert(gpu_private_task_live_eligible(&ops, &service, &client, ctx, 101UL));
	} else if (scenario == 10U || scenario == 11U) {
		/* A different Client's actual creation/mapping invalidates globally.
		 * Its lease cannot authorize this context or steal this BO's lease.
		 */
		unsigned long peer_bo = object(&other, 100U, 2U, 1U);
		unsigned long peer_ctx = context(&other);
		map(&other, peer_ctx, peer_bo, TEST_VA, 2U);
		if (scenario == 11U) {
			begin(&other, peer_ctx);
			handoff(&other, peer_ctx, 202UL, 0U, false);
			finish(&other, peer_ctx, 202UL, 0U);
		}
		assert(cache_metadata_epoch != saved_epoch && set->live_epoch == saved_epoch);
		assert(gpu_private_task_live_eligible(&ops, &service, &client, ctx, 101UL));
		assert(set->live_epoch == cache_metadata_epoch);
	} else if (scenario == 12U) {
		/* Retirement clears the real lease. A new launch has a new token,
		 * performs its handoff, and builds a fresh BO proof.
		 */
		finish(&client, ctx, 101UL, 0U);
		assert(cache_metadata_epoch != saved_epoch && bo_lookup(&client, bo)->cache_context == 0UL);
		assert(!gpu_private_task_live_eligible(&ops, &service, &client, ctx, 101UL));
		begin(&client, ctx); handoff(&client, ctx, 102UL, 0U, false);
		assert(gpu_private_task_live_eligible(&ops, &service, &client, ctx, 102UL));
		assert(!gpu_private_task_live_eligible(&ops, &service, &client, ctx, 101UL));
	} else if (scenario == 13U) {
		gpu_private_device_revoked(&ops);
		assert(!set->valid && !set->live_epoch && c->revoked);
		assert(!gpu_private_task_live_eligible(&ops, &service, &client, ctx, 101UL));
	} else if (scenario == 14U) {
		/* On wrap, later writes must keep reuse disabled, even if a stale
		 * proof carries a numerically matching historical generation.
		 */
		cache_metadata_epoch = ULONG_MAX;
		assert(gpu_private_task_live_eligible(&ops, &service, &client, ctx, 101UL));
		assert(set->live_epoch == ULONG_MAX);
		gpu_private_bo_create(&other, &service, 4096UL, 3UL, &result);
		assert(!result.status && cache_metadata_epoch == 0UL);
		gpu_private_bo_create(&other, &service, 4096UL, 3UL, &result);
		assert(!result.status && cache_metadata_epoch == 0UL);
		/* With caching disabled, actual corrupted BO metadata still rejects. */
		bo_lookup(&client, bo)->closing = true;
		assert(!gpu_private_task_live_eligible(&ops, &service, &client, ctx, 101UL));
	} else if (scenario == 15U) {
		/* Cache-slot eviction clears the proof as well as the old bitmap. */
		for (unsigned int i = 0U; i < 2U * CACHE_SET_SLOTS; i++)
			(void)cache_set_for(0xff0000UL + i);
		set = cache_set_for(ctx);
		assert(!set->valid && !set->live_epoch);
		assert(!gpu_private_task_live_eligible(&ops, &service, &client, ctx, 101UL));
	} else if (scenario == 16U) {
		/* A read-only idempotent uncached replay changes no predicate. */
		gpu_private_bo_uncached(&ops, &client, bo, &result);
		assert(!result.status && cache_metadata_epoch == saved_epoch);
		assert(gpu_private_task_live_eligible(&ops, &service, &client, ctx, 101UL));
	} else if (scenario == 18U) {
		/* The actual MAP clean callback can observe and warm an existing
		 * context before MAP publishes its BO reference count. Invalidate
		 * at the subsequent write, not only at mutator entry.
		 */
		unsigned long peer_ctx = context(&client);
		clean_context = ctx;
		ops.clean = summary_clean;
		map(&client, peer_ctx, bo, TEST_VA, 8U);
		assert(clean_observations > 0U);
		assert(set->live_epoch != cache_metadata_epoch);
		assert(bo_lookup(&client, bo)->cache_context == ctx);
		assert(gpu_private_task_live_eligible(&ops, &service, &client, ctx, 101UL));
		assert(set->live_epoch == cache_metadata_epoch);
	} else if (scenario == 17U) {
		/* Active-BO destroy is rejected before any lease/lifecycle write. */
		gpu_private_bo_release(&ops, &client, bo, &result);
		assert(result.status == GPU_PRIVATE_STATE && cache_metadata_epoch == saved_epoch);
		assert(gpu_private_task_live_eligible(&ops, &service, &client, ctx, 101UL));
	}
	if (scenario <= 9U || scenario == 14U || (scenario >= 15U && scenario <= 17U)) {
		assert(device_syncs + cpu_syncs == sync_before && barriers == barrier_before);
	}
	printf("GPU_PRIVATE_LIVE_SUMMARY=PASS scenario=%u ACTUAL_CORE_MODEL_ONLY\n", scenario);
	return 0;
}
