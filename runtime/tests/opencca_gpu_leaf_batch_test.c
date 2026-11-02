/* SPDX-License-Identifier: BSD-3-Clause */
/* Every lane, group edge and READY/RETURN fault against the actual core. */
#define main gpu_cache_budget_fixture_main
#include "opencca_gpu_cache_budget_test.c"
#undef main

int main(int argc, char **argv)
{
	assert(argc == 2);
	unsigned int scenario = (unsigned int)strtoul(argv[1], NULL, 10);
	assert(scenario < 320U);
	unsigned int page = 1U + scenario % 32U;
	bool on_return = scenario < 192U ? scenario >= 96U :
		(scenario < 256U ? scenario >= 224U : scenario >= 288U);
	struct gpu_private_result r;
	nc_pages = 128U;
	unsigned long nc = make_bo(nc_pages, NC_IPA);
	converting = true;
	gpu_private_bo_uncached(&ops, &client, nc, &r);
	assert(!r.status);
	unsigned long nc2 = 0UL;
	if (scenario >= 256U) {
		nc2 = make_bo(1U, NC_IPA + nc_pages * PAGE);
		gpu_private_bo_uncached(&ops, &client, nc2, &r);
		assert(!r.status);
	}
	converting = false;
	gpu_private_context_create(&ops, &client, &service, &r);
	assert(!r.status);
	unsigned long ctx = r.value[0];
	map_bo(ctx, nc, VA, nc_pages);
	if (nc2) map_bo(ctx, nc2, VA + nc_pages * PAGE, 1U);
	assert(gpu_private_context_hold(&service, &client, ctx));
	struct gpu_private_command_range empty = {0};
	assert(gpu_private_task_hold_batch(&ops, &service, &client, ctx, &empty, 1U));
	gpu_private_context_prepare(&ops, &service, &client, ctx, 1UL, &r);
	assert(!r.status);
	if (on_return) {
		gpu_private_task_cache(&ops, &service, &client, ctx, TOKEN, &r);
		assert(!r.status && !r.value[0]);
		gpu_private_context_quiesce(&ops, &service, &client, ctx, TOKEN, 1UL, &r);
		assert(!r.status);
	}
	unsigned long va = VA + page * PAGE;
	unsigned int table = walk(&ops, ctx_lookup(&client, ctx), va, NULL);
	unsigned int entry = (unsigned int)((va >> 12U) & 511U);
	unsigned short saved_tag = leaf_object[table][entry];
	if (scenario < 192U) {
		uint64_t bit = (scenario / 32U) % 3U == 0U ? PTE_AF :
			(scenario / 32U) % 3U == 1U ? PTE_USER : 1UL;
		tables[table][entry] &= ~bit;
	} else if (scenario < 256U) {
		leaf_object[table][entry] = GPU_PRIVATE_OBJECTS + 1U;
	} else {
		bo_lookup(&client, nc2)->closing = true;
		leaf_object[table][entry] = (unsigned short)(nc2 & 0xffffUL);
	}
	if (on_return) gpu_private_task_return(&ops, &service, &client, ctx, TOKEN, &r);
	else gpu_private_task_cache(&ops, &service, &client, ctx, TOKEN, &r);
	struct private_context *state = ctx_lookup(&client, ctx);
	assert(r.status == GPU_PRIVATE_STATE && state->quarantined);
	assert((on_return ? state->return_cursor : state->cache_cursor) == table * ENTRIES + entry);
	assert(!device_pages && !cpu_pages);
	assert(!gpu_private_task_retire(&service, &client, ctx, TOKEN));
	leaf_object[table][entry] = saved_tag;
	if (nc2) bo_lookup(&client, nc2)->closing = false;
	gpu_private_context_put(&client, ctx);
	gpu_private_device_revoked(&ops);
	gpu_private_bo_release(&ops, &client, nc, &r);
	assert(!r.status);
	if (nc2) {
		gpu_private_bo_release(&ops, &client, nc2, &r);
		assert(!r.status);
	}
	gpu_private_context_destroy(&ops, &client, ctx, &r);
	assert(!r.status && !gpu_private_owner_busy(&client));
	printf("GPU_PRIVATE_LEAF_BATCH_FAULT=PASS scenario=%u page=%u return=%u; MODEL_ONLY\n",
		scenario, page, on_return);
	return 0;
}
