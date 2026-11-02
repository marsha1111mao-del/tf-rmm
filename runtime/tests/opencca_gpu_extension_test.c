/* SPDX-License-Identifier: BSD-3-Clause */
/* Actual private PT core, synthetic RTT/cache/AS backends. No GPU execution. */
#include <assert.h>
#include <limits.h>
#include <opencca_gpu_private.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAGE 4096UL
#define TABLE_PA 0x100000000UL
#define ADDRESS_MASK 0x0000fffffffff000UL
#define VA 0x200000UL
#define TOKEN 123UL
#define FW_ROOT 0x300000UL

static int client, other_client, service, stranger;
static const unsigned char *table_base;
static unsigned long live_root;
static unsigned int live_slot, device_syncs, cpu_syncs, flushes, prepares, detaches;
static unsigned int fail_sync, fail_flush;
static bool bad_root, after_flush_fault;
static unsigned long object_base, destination;
static unsigned int extension_pages;
static unsigned long next_ipa = 0x1000000UL;

static unsigned long table_pa(const void *p)
{
	if (table_base == NULL)
		table_base = p;
	return TABLE_PA + (const unsigned char *)p - table_base;
}

static uint64_t leaf(unsigned long va)
{
	unsigned long pa = live_root;

	for (unsigned int level = 0U; level < 4U; level++) {
		assert(pa >= TABLE_PA && pa < TABLE_PA + GPU_PRIVATE_TABLES * PAGE);
		const uint64_t *table = (const void *)(table_base + pa - TABLE_PA);
		uint64_t pte = table[(va >> (39U - level * 9U)) & 511UL];

		if (pte == 0UL)
			return 0UL;
		assert((pte & 3UL) == 3UL);
		if (level == 3U)
			return pte;
		pa = pte & ADDRESS_MASK;
	}
	assert(false);
	return 0UL;
}

static bool source(const void *owner, unsigned long ipa, unsigned long *pa)
{
	assert(owner == &client || owner == &other_client);
	if (gpu_private_range_busy(owner, ipa, PAGE))
		return false;
	*pa = ipa + (owner == &client ? 0x40000000UL : 0x80000000UL);
	return true;
}

static void clean(const void *p, size_t bytes) { assert(p != NULL && bytes != 0U); }

static bool prepare(unsigned long root, unsigned int slot, unsigned long firmware_root, bool existing)
{
	assert(firmware_root == FW_ROOT && slot != 0U);
	prepares++;
	if (existing)
		return !bad_root && live_root == root && live_slot == slot;
	assert(live_root == 0UL);
	live_root = root;
	live_slot = slot;
	return true;
}

static bool device_sync(unsigned long pa)
{
	device_syncs++;
	/* The new page cannot become GPU-visible before CPU cache ownership has
	 * been handed over. Existing heap/data pages are never synchronized here.
	 */
	if (object_base != 0UL) {
		assert(pa >= object_base && (pa - object_base) / PAGE < extension_pages);
		assert(leaf(destination + pa - object_base) == 0UL);
	}
	return device_syncs != fail_sync;
}

static bool extend(unsigned long root, unsigned int slot, unsigned long firmware_root)
{
	assert(root == live_root && slot == live_slot && firmware_root == FW_ROOT);
	flushes++;
	/* This callback sees published, fixed-policy PTEs, after page sync. */
	unsigned int pages = device_syncs < extension_pages ? device_syncs : extension_pages;

	for (unsigned int i = 0U; i < pages; i++) {
		uint64_t pte = leaf(destination + i * PAGE);

		assert((pte & ADDRESS_MASK) == object_base + i * PAGE);
		assert((pte & (3UL << 53U)) == (3UL << 53U));
		assert((pte & (1UL << 7U)) == 0UL);
		assert((pte & (7UL << 2U)) == (1UL << 2U));
	}
	return flushes != fail_flush && !after_flush_fault;
}

static bool detach(unsigned long root, unsigned int slot, unsigned long firmware_root, bool detached)
{
	assert(root == live_root && slot == live_slot && firmware_root == FW_ROOT && !detached);
	detaches++;
	return true;
}

static bool cpu_sync(unsigned long pa)
{
	assert(detaches == 1U && pa >= object_base && (pa - object_base) / PAGE < extension_pages);
	cpu_syncs++;
	return true;
}

static const struct gpu_private_ops ops = {
	.source_page = source, .table_pa = table_pa, .clean = clean,
	.prepare_as = prepare, .extend_as = extend, .detach_as = detach,
	.sync_page_for_device = device_sync, .sync_page_for_cpu = cpu_sync
};

static unsigned long make_bo(const void *owner, unsigned int pages, unsigned long access, bool full)
{
	struct gpu_private_result r;
	unsigned long ipas[GPU_PRIVATE_BATCH];
	unsigned long base = next_ipa;

	next_ipa += (unsigned long)pages * PAGE;

	gpu_private_bo_create(owner, &service, pages * PAGE, access, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	unsigned long handle = r.value[0];

	if (!full)
		pages--;
	for (unsigned int first = 0U; first < pages; first += GPU_PRIVATE_BATCH) {
		unsigned int count = pages - first;

		if (count > GPU_PRIVATE_BATCH)
			count = GPU_PRIVATE_BATCH;
		for (unsigned int i = 0U; i < count; i++)
			ipas[i] = base + (first + i) * PAGE;
		gpu_private_bo_append(&ops, owner, handle, first * PAGE, ipas, count, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS);
	}
	return handle;
}

static unsigned long make_context(void)
{
	struct gpu_private_result r;

	gpu_private_context_create(&ops, &client, &service, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	return r.value[0];
}

int main(int argc, char **argv)
{
	assert(argc == 2);
	unsigned int scenario = (unsigned int)strtoul(argv[1], NULL, 10);
	unsigned int pages = scenario == 26U ? 1025U : scenario == 1U || scenario >= 18U ? 513U : scenario == 2U ? 2048U :
		scenario == 3U ? 31U : scenario == 4U ? 2049U : 32U;
	struct gpu_private_result r;
	unsigned long ctx = make_context(), second = 0UL;
	const void *owner = scenario == 7U ? &other_client : &client;
	unsigned long bo = make_bo(owner, pages, scenario == 5U ? GPU_PRIVATE_READ : scenario == 21U ? 7UL : 3UL, scenario != 6U);
	unsigned long reserved = 0UL, grant = 0UL;
	unsigned long extra_contexts[GPU_PRIVATE_CONTEXTS] = {0};
	unsigned int extra_count = 0U;
	struct gpu_private_ops use = ops;

	assert(scenario < 36U);
	if (scenario == 35U) {
		assert(GPU_PRIVATE_TABLES == 8U);
		/* Leave one table free: live preflight publishes an empty parent,
		 * then exhausts the pool before any data PTE or hardware flush.
		 */
		for (extra_count = 0U; extra_count < GPU_PRIVATE_TABLES - 2U; extra_count++)
			extra_contexts[extra_count] = make_context();
	}
	if (scenario == 17U || scenario == 18U) {
		reserved = make_bo(&client, 1U, GPU_PRIVATE_READ, true);
		gpu_private_map(&ops, &client, ctx, reserved, 0UL,
			VA + (scenario == 18U ? 512UL * PAGE : 0UL), 1U, GPU_PRIVATE_READ, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS);
	}
	if (scenario == 19U || scenario == 20U) {
		second = make_context();
		if (scenario == 19U)
			gpu_private_map(&ops, &client, second, bo, 0UL, VA, 1U, 3UL, &r);
		else {
			gpu_private_map_authorize(&client, second, bo, 0UL, VA, 1U, 3UL, &r);
			grant = r.value[0];
		}
		assert(r.status == GPU_PRIVATE_SUCCESS);
	}
	assert(gpu_private_context_hold(&service, &client, ctx));
	const struct gpu_private_command_range empty = {0};

	assert(gpu_private_task_hold_batch(&ops, &service, &client, ctx, &empty, 1U));
	gpu_private_context_prepare(&ops, &service, &client, ctx, FW_ROOT, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	if (scenario != 11U) {
		do {
			gpu_private_task_cache(&ops, &service, &client, ctx, TOKEN, &r);
		} while (r.status == GPU_PRIVATE_INCOMPLETE);
		assert(r.status == GPU_PRIVATE_SUCCESS);
	}
	device_syncs = 0U;
	object_base = 0x41000000UL;
	destination = VA;
	extension_pages = pages;
	if (scenario == 13U) use.extend_as = NULL;
	if (scenario == 14U) use.sync_page_for_device = NULL;
	if (scenario == 22U) fail_sync = 17U;
	if (scenario == 23U) fail_flush = 1U;
	if (scenario == 24U) bad_root = true;
	if (scenario == 25U) after_flush_fault = true;
	if (scenario == 26U) fail_sync = 522U;
	if (scenario == 27U) fail_flush = 2U;
	gpu_private_task_extend(&use, scenario == 9U ? &stranger : &service,
		scenario == 8U ? &other_client : scenario == 10U ? &service : &client,
		ctx, scenario == 12U ? TOKEN + 1UL : TOKEN, bo,
		scenario == 15U ? VA + 1UL : scenario == 16U ? GPU_PRIVATE_CONTROL_GPU_VA - PAGE : VA,
		FW_ROOT, &r);
	if (scenario == 35U) {
		assert(r.status == GPU_PRIVATE_STATE && device_syncs == GPU_PRIVATE_BATCH && !flushes);
		for (unsigned int i = 0U; i < pages; i++)
			assert(leaf(VA + i * PAGE) == 0UL);
		gpu_private_bo_destroy(&client, bo, &r);
		assert(r.status == GPU_PRIVATE_STATE);
		goto cleanup;
	}
	if ((scenario >= 3U && scenario <= 20U) || scenario == 24U) {
		assert(r.status != GPU_PRIVATE_SUCCESS && r.status != GPU_PRIVATE_INCOMPLETE);
		assert(device_syncs == 0U && flushes == 0U && detaches == 0U);
		goto cleanup;
	}
	if (scenario == 22U || scenario == 23U || scenario == 25U) {
		assert(r.status == GPU_PRIVATE_STATE);
		unsigned int previous = device_syncs;

		gpu_private_task_extend(&ops, &service, &client, ctx, TOKEN, bo, VA, FW_ROOT, &r);
		assert(r.status == GPU_PRIVATE_STATE && device_syncs == previous);
		gpu_private_bo_destroy(&client, bo, &r);
		assert(r.status == GPU_PRIVATE_STATE); /* Includes zero-leaf sync failure. */
		goto cleanup;
	}
	if (scenario >= 28U) {
		assert(r.status == GPU_PRIVATE_INCOMPLETE && r.value[0] == 512UL);
		unsigned int previous = device_syncs;

		if (scenario == 28U)
			gpu_private_task_extend(&ops, &service, &client, ctx, TOKEN + 1UL, bo, VA, FW_ROOT, &r);
		if (scenario == 29U)
			gpu_private_task_extend(&ops, &service, &client, ctx, TOKEN, bo + 0x10000UL, VA, FW_ROOT, &r);
		if (scenario == 30U)
			gpu_private_task_extend(&ops, &service, &client, ctx, TOKEN, bo, VA + PAGE, FW_ROOT, &r);
		if (scenario == 31U)
			gpu_private_context_quiesce(&ops, &service, &client, ctx, TOKEN, FW_ROOT, &r);
		if (scenario == 32U)
			gpu_private_task_return(&ops, &service, &client, ctx, TOKEN, &r);
		if (scenario == 33U)
			gpu_private_map(&ops, &client, ctx, bo, 512UL * PAGE, VA + 512UL * PAGE, 1U, 3UL, &r);
		if (scenario == 34U)
			gpu_private_bo_destroy(&client, bo, &r);
		assert(r.status != GPU_PRIVATE_SUCCESS && r.status != GPU_PRIVATE_INCOMPLETE);
		assert(device_syncs == previous && !detaches && !cpu_syncs);
	}
	while (device_syncs < pages && scenario != 26U && scenario != 27U) {
		gpu_private_task_extend(&ops, &service, &client, ctx, TOKEN, bo, VA, FW_ROOT, &r);
		assert(r.status == (device_syncs == pages ? GPU_PRIVATE_SUCCESS : GPU_PRIVATE_INCOMPLETE));
	}
	if (scenario == 26U || scenario == 27U) {
		assert(r.status == GPU_PRIVATE_INCOMPLETE);
		gpu_private_task_extend(&ops, &service, &client, ctx, TOKEN, bo, VA, FW_ROOT, &r);
		assert(r.status == GPU_PRIVATE_STATE);
		gpu_private_bo_destroy(&client, bo, &r);
		assert(r.status == GPU_PRIVATE_STATE);
		goto cleanup;
	}
	assert(device_syncs == pages && flushes == (pages + GPU_PRIVATE_BATCH - 1U) / GPU_PRIVATE_BATCH);
	for (unsigned int i = 0U; i < pages; i++)
		assert((leaf(VA + i * PAGE) & ADDRESS_MASK) == object_base + i * PAGE);
	gpu_private_task_extend(&ops, &service, &client, ctx, TOKEN, bo, VA, FW_ROOT, &r);
	assert(r.status == GPU_PRIVATE_STATE && device_syncs == pages); /* No implicit replay. */
	gpu_private_context_quiesce(&ops, &service, &client, ctx, TOKEN, FW_ROOT, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	do {
		gpu_private_task_return(&ops, &service, &client, ctx, TOKEN, &r);
	} while (r.status == GPU_PRIVATE_INCOMPLETE);
	assert(r.status == GPU_PRIVATE_SUCCESS && r.value[0] == pages && cpu_syncs == pages);
	assert(gpu_private_task_retire(&service, &client, ctx, TOKEN));
cleanup:
	/* Models a verified whole-device reset, not a service-provided claim. */
	gpu_private_device_revoked(&ops);
	if (grant != 0UL) {
		gpu_private_map_cancel(&client, grant, &r);
		assert(r.status == GPU_PRIVATE_INPUT);
	}
	do {
		gpu_private_bo_destroy(owner, bo, &r);
	} while (r.status == GPU_PRIVATE_INCOMPLETE);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	if (reserved != 0UL) {
		gpu_private_bo_destroy(&client, reserved, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS);
	}
	gpu_private_context_destroy(&ops, &client, ctx, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	if (second != 0UL) {
		gpu_private_context_destroy(&ops, &client, second, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS);
	}
	for (unsigned int i = 0U; i < extra_count; i++) {
		gpu_private_context_destroy(&ops, &client, extra_contexts[i], &r);
		assert(r.status == GPU_PRIVATE_SUCCESS);
	}
	printf("GPU_PRIVATE_EXTENSION=PASS scenario=%u actual PT core, cache-before-leaf, exact task/object/VA, bounded additive mappings, failure retention and reset cleanup; HOST_BACKEND_DOUBLES_ONLY\n", scenario);
	return 0;
}
