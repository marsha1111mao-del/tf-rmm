/* SPDX-License-Identifier: BSD-3-Clause */
/* Reuse the existing actual-core fixture, not a second lease implementation. */
#define main cache_set_reference_main
#include "opencca_gpu_cache_set_test.c"
#undef main

static unsigned int flushes, flush_case;
static unsigned long active_context;

static bool flush_live(unsigned long root, unsigned int slot, unsigned long firmware)
{
	struct private_context *ctx = ctx_lookup(&client, active_context);

	assert(root && slot && firmware == TEST_FW && ctx != NULL);
	assert(ctx->quarantined && !ctx->drained);
	flushes++;
	if (flush_case == 2U) ctx->mapping_epoch++;
	return flush_case != 1U;
}

int main(int argc, char **argv)
{
	assert(argc == 2);
	unsigned int scenario = (unsigned int)strtoul(argv[1], NULL, 10);
	assert(scenario < 31U);
	ops.protected_mapping_summary = true;
	ops.flush_as = flush_live;
	unsigned int mode = scenario == 2U ? 0U : scenario == 30U ? 2U : 1U;
	unsigned long bo = object(&client, 0U, 8U, mode), ctx = context(&client);
	active_context = ctx;
	map(&client, ctx, bo, TEST_VA, 8U);
	begin(&client, ctx);
	handoff(&client, ctx, 101UL, mode == 0U ? 8U : 0U, false);
	struct private_context *c = ctx_lookup(&client, ctx);
	struct private_bo *o = bo_lookup(&client, bo);
	struct private_cache_set *set = cache_set_for(ctx);
	struct gpu_private_command_range range = { .start = mode == 2U ? 0UL : TEST_VA, .bytes = mode == 2U ? 0UL : 64UL };
	unsigned int slot = c->slot, device_before = device_syncs, cpu_before = cpu_syncs;
	unsigned long epoch = c->mapping_epoch, root_index = c->root;
	uint16_t leases = c->cache_groups;
	assert(!c->drained && c->task_refs == 1U);
	if (scenario == 0U || scenario == 30U) {
		unsigned long token = 101UL;

		for (unsigned int repeat = 0U; repeat < 32U; repeat++) {
			assert(gpu_private_task_live_eligible(&ops, &service, &client, ctx, token));
			assert(gpu_private_task_flush_live(&ops, &service, &client, ctx, token, TEST_FW));
			assert(!c->drained && !c->quarantined && !c->quiesced && c->live_prepared);
			assert(gpu_private_task_mark_drained(&ops, &service, &client, ctx, token));
			assert(!gpu_private_task_hold_batch(&ops, &service, &client, ctx, &range, 1U));
			assert(!gpu_private_task_put(&client, ctx));
			assert(gpu_private_task_hold_live(&ops, &service, &client, ctx, token, &range, 1U));
			assert(c->task_refs == 2U);
			unsigned int callbacks = barriers;

			assert(gpu_private_task_handoff_live(&ops, &service, &client, ctx, token, token + 1UL));
			assert(c->task_refs == 1U && c->cache_task == token + 1UL && !c->drained);
			assert(c->cache_cursor == 0U && !c->return_cursor && c->slot == slot);
			assert(c->root == root_index && c->mapping_epoch == epoch && c->cache_groups == leases);
			assert(slot_owner[slot] == ctx && o->cache_context == ctx && barriers == callbacks);
			struct gpu_private_result r;

			gpu_private_task_cache(&ops, &service, &client, ctx, token, &r);
			assert(r.status == GPU_PRIVATE_STATE);
			assert(!gpu_private_task_retire(&service, &client, ctx, token));
			assert(!gpu_private_task_mark_drained(&ops, &service, &client, ctx, token + 1UL));
			handoff(&client, ctx, ++token, 0U, false);
			assert(device_syncs == device_before && cpu_syncs == cpu_before);
		}
		finish(&client, ctx, token, 0U);
		assert(!c->drained && !c->activated && !c->task_refs && o->cache_context == 0UL);
	} else if (scenario == 1U || scenario == 25U || scenario == 26U || scenario == 27U || scenario == 28U || scenario == 29U) {
		assert(!gpu_private_task_live_eligible(&ops, &service, &client, ctx, 100UL));
		assert(!gpu_private_task_mark_drained(&ops, &service, &client, ctx, 100UL));
		assert(gpu_private_task_flush_live(&ops, &service, &client, ctx, 101UL, TEST_FW));
		assert(gpu_private_task_mark_drained(&ops, &service, &client, ctx, 101UL));
		assert(!gpu_private_task_flush_live(&ops, &service, &client, ctx, 100UL, TEST_FW));
		assert(c->drained);
		assert(!gpu_private_task_hold_live(&ops, &service, &client, ctx, 100UL, &range, 1U));
		assert(!gpu_private_task_put_live(&ops, &service, &client, ctx, 101UL));
		assert(!gpu_private_task_handoff_live(&ops, &service, &client, ctx, 101UL, 102UL));
		if (scenario == 26U) {
			struct gpu_private_command_range bad[] = {
				{ .start = TEST_VA + 1UL, .bytes = 64UL },
				{ .start = GPU_PRIVATE_CONTROL_GPU_VA, .bytes = 64UL },
				{ .start = TEST_VA + 0x100000UL, .bytes = 64UL },
				{ .start = 1UL, .bytes = 0UL }
			};
			for (unsigned int i = 0U; i < sizeof(bad) / sizeof(bad[0]); i++)
				assert(!gpu_private_task_hold_live(&ops, &service, &client, ctx, 101UL, &bad[i], 1U));
			assert(c->task_refs == 1U);
		}
		if (scenario == 28U) {
			gpu_private_task_clear_drained(&service, &other, ctx, 101UL);
			assert(c->drained);
			gpu_private_task_clear_drained(&service, &client, ctx, 100UL);
			assert(c->drained);
			gpu_private_task_clear_drained(&service, &client, ctx, 101UL);
			assert(!c->drained && !gpu_private_task_hold_live(&ops, &service, &client, ctx, 101UL, &range, 1U));
			assert(gpu_private_task_mark_drained(&ops, &service, &client, ctx, 101UL));
		}
		assert(gpu_private_task_hold_live(&ops, &service, &client, ctx, 101UL, &range, 1U));
		assert(c->task_refs == 2U);
		assert(!gpu_private_task_handoff_live(&ops, &service, &client, ctx, 101UL, 0UL));
		assert(!gpu_private_task_handoff_live(&ops, &service, &client, ctx, 101UL, 101UL));
		assert(!gpu_private_task_handoff_live(&ops, &service, &other, ctx, 101UL, 102UL));
		assert(!gpu_private_task_handoff_live(&ops, &other, &client, ctx, 101UL, 102UL));
		if (scenario == 27U) {
			c->mapping_epoch++;
			assert(!gpu_private_task_handoff_live(&ops, &service, &client, ctx, 101UL, 102UL));
			assert(c->task_refs == 2U && c->cache_task == 101UL && o->cache_context == ctx);
			c->mapping_epoch = epoch;
		}
		if (scenario == 29U) {
			gpu_private_device_revoked(&ops);
			assert(!c->drained && !c->task_refs && c->revoked);
			assert(!gpu_private_task_handoff_live(&ops, &service, &client, ctx, 101UL, 102UL));
			assert(!gpu_private_task_mark_drained(&ops, &service, &client, ctx, 101UL));
		} else {
			assert(gpu_private_task_put_live(&ops, &service, &client, ctx, 101UL));
			assert(c->task_refs == 1U && c->drained && c->slot == slot && o->cache_context == ctx);
			finish(&client, ctx, 101UL, 0U);
		}
	} else if (scenario >= 20U && scenario <= 24U) {
		assert(gpu_private_task_mark_drained(&ops, &service, &client, ctx, 101UL));
		assert(gpu_private_task_hold_live(&ops, &service, &client, ctx, 101UL, &range, 1U));
		if (scenario == 20U) flush_case = 1U;
		if (scenario == 21U) fail_barrier = barriers + 1U;
		if (scenario == 22U) flush_case = 2U;
		if (scenario == 23U) ops.flush_as = NULL;
		if (scenario == 24U) ops.cache_barrier = NULL;
		assert(!gpu_private_task_flush_live(&ops, &service, &client, ctx, 101UL, TEST_FW));
		assert(!c->drained && c->task_refs == 2U && c->cache_task == 101UL);
		assert(c->slot == slot && slot_owner[slot] == ctx && o->cache_context == ctx);
		assert(c->quarantined == (scenario <= 22U));
		assert(!gpu_private_task_handoff_live(&ops, &service, &client, ctx, 101UL, 102UL));
		assert(!gpu_private_task_retire(&service, &client, ctx, 101UL));
	} else {
		if (scenario == 3U) ops.protected_mapping_summary = false;
		if (scenario == 4U) c->mapping_epoch++;
		if (scenario == 5U) set->context++;
		if (scenario == 6U) set->valid = false;
		if (scenario == 7U) o->closing = true;
		if (scenario == 8U) o->owner = &other;
		if (scenario == 9U) o->cache_context = 0UL;
		if (scenario == 10U) o->hidden--;
		if (scenario == 11U) o->mapped = 0U;
		if (scenario == 12U) c->quarantined = true;
		if (scenario == 13U) c->revoked = true;
		if (scenario == 14U) c->pending = 1U;
		if (scenario == 15U) c->extension_object = bo;
		if (scenario == 16U) c->cache_cursor--;
		if (scenario == 17U) c->cache_pages = 1U;
		if (scenario == 18U) c->return_cursor = 1U;
		if (scenario == 19U) slot_owner[slot] = 0UL;
		assert(!gpu_private_task_live_eligible(&ops, &service, &client, ctx, 101UL));
		assert(!gpu_private_task_mark_drained(&ops, &service, &client, ctx, 101UL));
		assert(!gpu_private_task_hold_live(&ops, &service, &client, ctx, 101UL, &range, 1U));
		assert(!gpu_private_task_flush_live(&ops, &service, &client, ctx, 101UL, TEST_FW));
		assert(!gpu_private_task_handoff_live(&ops, &service, &client, ctx, 101UL, 102UL));
		assert(!c->drained && c->task_refs == 1U && !flushes);
	}
	printf("GPU_LIVE_LEASE=PASS scenario=%u actual core, fixed mapping/AS/lease ownership, no CPU return or early reclaim; MODEL_ONLY\n", scenario);
	return 0;
}
