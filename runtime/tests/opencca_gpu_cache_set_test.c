/* SPDX-License-Identifier: BSD-3-Clause */
/* Real core/mapping APIs; CPU visibility, AS and caches are models only. */
#include <stdio.h>
#include <stdlib.h>
#include "opencca_gpu_private.c"

#define TEST_PAGES 17000U
#define TEST_IPA 0x100000UL
#define TEST_PA 0x60000000UL
#define TEST_VA 0x200000UL
#define TEST_FW 1UL
static int client, other, service;
static unsigned int device_syncs, cpu_syncs, barriers, fail_barrier;
static unsigned char visibility[TEST_PAGES * 2U]; /* 0 WB, 1 hidden, 2 NC */
static unsigned int page_index(unsigned long pa)
{
	assert(pa >= TEST_PA && (pa & PAGE_MASK) == 0UL);
	unsigned long i = (pa - TEST_PA) / 4096UL;
	assert(i < TEST_PAGES * 2U);
	return (unsigned int)i;
}
static bool source(const void *owner, unsigned long ipa, unsigned long *pa)
{
	if ((owner != &client && owner != &other && owner != &service) ||
	    ipa < TEST_IPA || ipa >= TEST_IPA + TEST_PAGES * 4096UL ||
	    (ipa & PAGE_MASK) != 0UL)
		return false;
	*pa = TEST_PA + ipa - TEST_IPA + (owner == &other ? TEST_PAGES * 4096UL : 0UL);
	return visibility[page_index(*pa)] == 0U;
}
static bool hide(const void *owner, unsigned long ipa, unsigned long pa)
{
	(void)owner; (void)ipa;
	visibility[page_index(pa)] = 1U;
	return true;
}
static bool restore_nc(const void *owner, unsigned long ipa, unsigned long pa)
{
	(void)owner; (void)ipa;
	assert(visibility[page_index(pa)] == 1U);
	visibility[page_index(pa)] = 2U;
	return true;
}
static bool restore_wb(const void *owner, unsigned long ipa, unsigned long pa)
{
	(void)owner; (void)ipa;
	assert(visibility[page_index(pa)] == 1U);
	visibility[page_index(pa)] = 0U;
	return true;
}
static bool sync_device(unsigned long pa) { (void)page_index(pa); device_syncs++; return true; }
static bool sync_cpu(unsigned long pa) { (void)page_index(pa); cpu_syncs++; return true; }
static bool barrier(void) { return ++barriers != fail_barrier; }
static bool clear(unsigned long pa) { (void)page_index(pa); return true; }
static void clean(const void *p, size_t size) { assert(p != NULL && size != 0U); }
static unsigned long table_pa(const void *p)
{ return 0x100000000UL + (const unsigned char *)p - (const unsigned char *)tables; }
static bool prepare(unsigned long root, unsigned int slot, unsigned long fw, bool replay)
{ (void)replay; assert(root && slot && fw); return true; }
static bool detach(unsigned long root, unsigned int slot, unsigned long fw, bool replay)
{ (void)replay; assert(root && slot && fw); return true; }
static bool extend(unsigned long root, unsigned int slot, unsigned long fw)
{ assert(root && slot && fw); return true; }
static struct gpu_private_ops ops = {
	.source_page = source, .table_pa = table_pa, .clean = clean,
	.hide_page = hide, .restore_page = restore_wb, .restore_page_uncached = restore_nc,
	.cache_barrier = barrier, .clear_page = clear, .sync_page_for_device = sync_device,
	.sync_page_for_cpu = sync_cpu, .prepare_as = prepare, .detach_as = detach, .extend_as = extend
};
static unsigned long object(const void *owner, unsigned int first, unsigned int pages, unsigned int mode)
{
	struct gpu_private_result r;
	unsigned long ipas[GPU_PRIVATE_BATCH];
	gpu_private_bo_create(owner, &service, pages * 4096UL, mode == 2U ? 3UL : 7UL, &r);
	assert(!r.status);
	unsigned long bo = r.value[0];
	for (unsigned int i = 0U; i < pages; i += GPU_PRIVATE_BATCH) {
		unsigned int n = pages - i;
		if (n > GPU_PRIVATE_BATCH) n = GPU_PRIVATE_BATCH;
		for (unsigned int j = 0U; j < n; j++) ipas[j] = TEST_IPA + (first + i + j) * 4096UL;
		gpu_private_bo_append(&ops, owner, bo, i * 4096UL, ipas, n, &r);
		assert(!r.status);
	}
	if (mode != 0U) {
		do {
			if (mode == 1U) gpu_private_bo_uncached(&ops, owner, bo, &r);
			else gpu_private_bo_seal(&ops, owner, bo, &r);
		} while (r.status == GPU_PRIVATE_INCOMPLETE);
		assert(!r.status);
	}
	return bo;
}
static unsigned long context(const void *owner)
{
	struct gpu_private_result r;
	gpu_private_context_create(&ops, owner, &service, &r); assert(!r.status);
	assert(gpu_private_context_hold(&service, owner, r.value[0]));
	return r.value[0];
}
static void map(const void *owner, unsigned long ctx, unsigned long bo, unsigned long va, unsigned int pages)
{
	struct gpu_private_result r;
	for (unsigned int i = 0U; i < pages; i += GPU_PRIVATE_BATCH) {
		unsigned int n = pages - i; if (n > GPU_PRIVATE_BATCH) n = GPU_PRIVATE_BATCH;
		gpu_private_map(&ops, owner, ctx, bo, i * 4096UL, va + i * 4096UL, n,
			bo_lookup(owner, bo)->access | GPU_PRIVATE_CACHE, &r);
		assert(!r.status);
	}
}
static void begin(const void *owner, unsigned long ctx)
{
	struct gpu_private_command_range empty = {0};
	struct gpu_private_result r;
	assert(gpu_private_task_hold_batch(&ops, &service, owner, ctx, &empty, 1U));
	gpu_private_context_prepare(&ops, &service, owner, ctx, TEST_FW, &r); assert(!r.status);
}
static void handoff(const void *owner, unsigned long ctx, unsigned long token, unsigned int pages, bool cpu)
{
	struct gpu_private_result r;
	unsigned int calls = 0U;
	do {
		if (cpu) gpu_private_task_return(&ops, &service, owner, ctx, token, &r);
		else gpu_private_task_cache(&ops, &service, owner, ctx, token, &r);
		assert(++calls < 128U);
	} while (r.status == GPU_PRIVATE_INCOMPLETE);
	assert(!r.status && r.value[0] == pages);
}
static void finish(const void *owner, unsigned long ctx, unsigned long token, unsigned int pages)
{
	struct gpu_private_result r;
	gpu_private_context_quiesce(&ops, &service, owner, ctx, token, TEST_FW, &r); assert(!r.status);
	handoff(owner, ctx, token, pages, true);
	assert(gpu_private_task_retire(&service, owner, ctx, token));
}
int main(int argc, char **argv)
{
	assert(argc == 3);
	unsigned int scenario = (unsigned int)strtoul(argv[1], NULL, 10);
	assert(scenario < 28U);
	ops.protected_mapping_summary = strtoul(argv[2], NULL, 10) != 0UL;
	unsigned int mode = scenario == 1U ? 2U : 1U;
	unsigned int count = scenario == 17U || scenario == 26U ? 16500U : 8U;
	unsigned long bo = object(&client, 0U, count, mode), ctx = context(&client), control = 0UL;
	map(&client, ctx, bo, TEST_VA, count);
	struct gpu_private_result r;
	struct private_context *c = ctx_lookup(&client, ctx);
	struct private_cache_set *set = cache_set_for(ctx);
	unsigned int wb_pages = 0U;
	if (scenario == 22U || scenario == 23U) {
		unsigned long ipa = TEST_IPA + 100U * 4096UL;
		unsigned int pages;
		gpu_private_control_create(&service, 4096UL, &r); assert(!r.status); control = r.value[0];
		gpu_private_control_append(&ops, &service, control, 0UL, &ipa, 1U, &r); assert(!r.status);
		assert(gpu_private_control_acquire(&ops, &service, control, &pages) && pages == 1U);
		gpu_private_control_mapping(&ops, &service, &client, ctx, control, 0U, 1U, true, true, &r);
		assert(!r.status);
	}
	if (scenario == 2U) {
		unsigned long wb = object(&client, 100U, 1U, 0U);
		map(&client, ctx, wb, TEST_VA + 0x8000000UL, 1U); wb_pages = 1U;
	}
	if (scenario == 19U) {
		for (unsigned int i = 0U; i < 70U; i++) {
			unsigned long extra = object(&client, 100U + i, 1U, 1U);
			map(&client, ctx, extra, TEST_VA + 0x8000000UL + i * 4096UL, 1U);
		}
	}
	begin(&client, ctx);
	if (scenario == 17U || scenario == 26U) {
		gpu_private_task_cache(&ops, &service, &client, ctx, 100UL, &r);
		assert(r.status == GPU_PRIVATE_INCOMPLETE && !set->valid);
	}
	if (scenario == 26U) {
		for (unsigned int i = 0U; i < 8U; i++) {
			unsigned long extra = object(&client, 16600U + i, 1U, 1U);
			unsigned long peer_ctx = context(&client);
			map(&client, peer_ctx, extra, TEST_VA, 1U);
			begin(&client, peer_ctx); handoff(&client, peer_ctx, 300UL + i, 0U, false);
			finish(&client, peer_ctx, 300UL + i, 0U);
		}
		set = cache_set_for(ctx);
		assert(!set->valid && !set->eligible);
	}
	handoff(&client, ctx, 100UL, wb_pages, false);
	assert(!ops.protected_mapping_summary || set->valid == (wb_pages == 0U && scenario != 26U));
	if (scenario == 18U || scenario == 24U || scenario == 25U) {
		unsigned long extra = object(&client, 100U, 32U, scenario == 18U ? 1U : 0U);
		unsigned long epoch = c->mapping_epoch;
		gpu_private_task_extend(&ops, &service, &client, ctx, 100UL, extra,
			TEST_VA + 0x8000000UL, TEST_FW, &r);
		assert(!r.status && c->mapping_epoch > epoch && (!set->valid || set->epoch != c->mapping_epoch));
		if (scenario != 18U) wb_pages = 32U;
	}
	finish(&client, ctx, 100UL, wb_pages);
	if (scenario == 27U) {
		for (unsigned int i = 0U; i < 8U; i++) {
			unsigned long extra = object(&client, 200U + i, 1U, 1U);
			unsigned long peer_ctx = context(&client);
			map(&client, peer_ctx, extra, TEST_VA, 1U);
			begin(&client, peer_ctx); handoff(&client, peer_ctx, 300UL + i, 0U, false);
			finish(&client, peer_ctx, 300UL + i, 0U);
		}
		set = cache_set_for(ctx); assert(!set->valid);
	}
	if (scenario == 23U) {
		unsigned long epoch = c->mapping_epoch;
		gpu_private_control_mapping(&ops, &service, &client, ctx, control, 0U, 1U, true, false, &r);
		assert(!r.status && c->mapping_epoch > epoch);
	}
	if (scenario == 25U) {
		gpu_private_unmap(&ops, &client, ctx, TEST_VA + 0x8000000UL, 32U, &r);
		assert(!r.status); wb_pages = 0U;
	}
	if (scenario == 8U) {
		unsigned long wb = object(&client, 100U, 1U, 0U);
		map(&client, ctx, wb, TEST_VA + 0x8000000UL, 1U); wb_pages = 1U;
	}
	if (scenario == 9U) {
		gpu_private_unmap_bo(&ops, &client, ctx, bo, 0UL, TEST_VA, count, &r); assert(!r.status);
		map(&client, ctx, bo, TEST_VA + 0x400000UL, count);
	}
	if (scenario == 15U) {
		unsigned long old = ctx;
		gpu_private_unmap_bo(&ops, &client, ctx, bo, 0UL, TEST_VA, count, &r); assert(!r.status);
		gpu_private_context_put(&client, ctx);
		gpu_private_context_destroy(&ops, &client, ctx, &r); assert(!r.status);
		ctx = context(&client); assert(ctx != old);
		unsigned long wb = object(&client, 100U, 1U, 0U);
		map(&client, ctx, wb, TEST_VA, 1U); wb_pages = 1U;
		c = ctx_lookup(&client, ctx);
	}
	if (scenario == 3U || scenario == 20U) {
		const void *peer = scenario == 3U ? &client : &other;
		unsigned long peer_bo = scenario == 3U ? bo : object(peer, 0U, 8U, 1U);
		unsigned long peer_ctx = context(peer);
		map(peer, peer_ctx, peer_bo, TEST_VA, 8U);
		begin(peer, peer_ctx); handoff(peer, peer_ctx, 300UL, 0U, false);
		if (scenario == 20U) finish(peer, peer_ctx, 300UL, 0U);
	}
	begin(&client, ctx);
	if (scenario == 4U) {
		gpu_private_task_return(&ops, &service, &client, ctx, 101UL, &r);
		assert(r.status); goto done;
	}
	if (scenario == 6U || scenario == 7U) {
		gpu_private_task_cache(&ops, scenario == 7U ? &other : &service,
			scenario == 6U ? &other : &client, ctx, 101UL, &r);
		assert(r.status); goto done;
	}
	if (scenario == 10U) fail_barrier = barriers + 1U;
	if (scenario == 12U) bo_lookup(&client, bo)->closing = true;
	if (scenario == 13U) bo_lookup(&client, bo)->hidden--;
	if (scenario == 16U) gpu_private_device_revoked(&ops);
	unsigned int before = barriers;
	gpu_private_task_cache(&ops, &service, &client, ctx, 101UL, &r);
	if (scenario == 3U || scenario == 10U || scenario == 12U || scenario == 13U || scenario == 16U) {
		assert(r.status && (scenario == 16U || c->quarantined)); goto done;
	}
	while (r.status == GPU_PRIVATE_INCOMPLETE)
		gpu_private_task_cache(&ops, &service, &client, ctx, 101UL, &r);
	assert(!r.status && r.value[0] == wb_pages);
	if (mode == 1U && scenario != 15U) assert(barriers > before);
	if (scenario == 5U) {
		gpu_private_task_cache(&ops, &service, &client, ctx, 102UL, &r); assert(r.status);
		assert(!gpu_private_task_retire(&service, &client, ctx, 101UL)); goto done;
	}
	if (scenario == 14U) {
		c->mapping_epoch = ULONG_MAX;
		gpu_private_map(&ops, &client, ctx, bo, 0UL, TEST_VA + 0x1000000UL, 1U, 15UL, &r);
		assert(r.status);
	}
	if (scenario == 11U || scenario == 21U) {
		gpu_private_context_quiesce(&ops, &service, &client, ctx, 101UL, TEST_FW, &r); assert(!r.status);
		if (scenario == 11U) fail_barrier = barriers + 1U;
		else bo_lookup(&client, bo)->cache_context = 0UL;
		gpu_private_task_return(&ops, &service, &client, ctx, 101UL, &r);
		assert(r.status && c->quarantined); goto done;
	}
	finish(&client, ctx, 101UL, wb_pages);
	assert(!bo_lookup(&client, bo)->cache_context);
done:
	fail_barrier = 0U;
	gpu_private_device_revoked(&ops);
	assert(!set->valid);
	printf("GPU_PRIVATE_CACHE_SET=PASS scenario=%u; actual core, modeled AS/cache/CPU visibility\n", scenario);
	return 0;
}
