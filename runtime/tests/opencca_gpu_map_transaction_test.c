/* SPDX-License-Identifier: BSD-3-Clause */
/* Actual production core. Internal state is used only for fault injection and
 * independent reference accounting; requests use the public transaction API.
 */
#include <stdio.h>
#include <stdlib.h>
#include <opencca_gpu_private.c>

static int client, other, service;
static bool barrier_ok = true, activate_ok = true;
static unsigned int barriers, activations;
static unsigned long observed_context;

static bool source(const void *owner, unsigned long ipa, unsigned long *pa)
{
	if (gpu_private_range_busy(owner, ipa, GPU_PRIVATE_PAGE_SIZE))
		return false;
	*pa = ipa + (owner == &client ? 0x40000000UL : 0x80000000UL);
	return true;
}

static unsigned long physical_table(const void *table)
{
	return 0x100000000UL + (unsigned long)((const char *)table - (const char *)tables);
}

static void clean_table(const void *table, size_t bytes)
{
	assert(table != NULL && bytes != 0U);
}

static bool barrier(void)
{
	struct gpu_private_result result;

	barriers++;
	/* Publication must follow this callback, including when it fails. */
	gpu_private_mapping_version(&client, observed_context, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	return barrier_ok;
}

static bool activate(unsigned long context, unsigned long root, unsigned int slot)
{
	assert(context != 0UL && root >= 0x100000000UL && slot < GPU_PRIVATE_AS_SLOTS);
	activations++;
	return activate_ok;
}

static bool synchronize_root(unsigned long context, unsigned long root)
{
	assert(context != 0UL && root >= 0x100000000UL);
	return true;
}

static const struct gpu_private_ops ops = {
	.source_page = source, .table_pa = physical_table, .clean = clean_table,
	.cache_barrier = barrier, .activate = activate, .synchronize = synchronize_root
};

static unsigned long make_context(const void *owner)
{
	struct gpu_private_result result;

	gpu_private_context_create(&ops, owner, &service, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	return result.value[0];
}

static unsigned long make_bo(const void *owner, unsigned int pages, unsigned long base)
{
	struct gpu_private_result result;
	unsigned long ipas[GPU_PRIVATE_BATCH], handle;

	gpu_private_bo_create(owner, &service, pages * GPU_PRIVATE_PAGE_SIZE,
		GPU_PRIVATE_ACCESS, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	handle = result.value[0];
	for (unsigned int first = 0U; first < pages;) {
		unsigned int count = pages - first;

		if (count > GPU_PRIVATE_BATCH)
			count = GPU_PRIVATE_BATCH;
		for (unsigned int i = 0U; i < count; i++)
			ipas[i] = base + (first + i) * GPU_PRIVATE_PAGE_SIZE;
		gpu_private_bo_append(&ops, owner, handle, first * GPU_PRIVATE_PAGE_SIZE,
			ipas, count, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		first += count;
	}
	return handle;
}

static unsigned int allocated_tables(void)
{
	unsigned int count = 0U;

	for (unsigned int i = 0U; i < GPU_PRIVATE_TABLES; i++)
		count += table_owner[i] != 0UL;
	return count;
}

/* Independently traverse hardware-format descriptors, without walk(). */
static uint64_t pte(unsigned long context, unsigned long va)
{
	unsigned long pa = physical_table(tables[ctx_lookup(&client, context)->root]);

	for (unsigned int level = 0U; level < 4U; level++) {
		unsigned long table = (pa - 0x100000000UL) / GPU_PRIVATE_PAGE_SIZE;
		uint64_t entry;

		assert(table < GPU_PRIVATE_TABLES);
		entry = tables[table][(va >> (39U - 9U * level)) & 511UL];
		if (entry == 0UL || level == 3U)
			return entry;
		assert((entry & 3UL) == 3UL);
		pa = entry & ADDRESS_MASK;
	}
	abort();
}

static struct gpu_private_result begin(unsigned long context,
		const struct gpu_private_map_request *request)
{
	struct gpu_private_result result;

	observed_context = context;
	gpu_private_map_begin(&ops, &client, context, request, &result);
	return result;
}

static struct gpu_private_result step(unsigned long token, unsigned long sequence)
{
	struct gpu_private_result result;

	gpu_private_map_step(&ops, &client, token, sequence, &result);
	return result;
}

static struct gpu_private_result finish(struct gpu_private_result result)
{
	unsigned int calls = 0U;

	while (result.status == GPU_PRIVATE_INCOMPLETE) {
		assert(++calls < 2048U);
		result = step(result.value[0], result.value[2]);
	}
	return result;
}

static void reset_and_reclaim(unsigned long context, unsigned long bo)
{
	struct gpu_private_result result;

	gpu_private_device_revoked(&ops);
	assert(!ctx_lookup(&client, context)->map_transaction_active);
	assert(bo_lookup(&client, bo)->mapped == 0U && bo_lookup(&client, bo)->pending == 0U);
	do {
		gpu_private_bo_destroy(&client, bo, &result);
	} while (result.status == GPU_PRIVATE_INCOMPLETE);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	gpu_private_context_destroy(&ops, &client, context, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
}

int main(int argc, char **argv)
{
	unsigned int scenario = argc == 2 ? (unsigned int)strtoul(argv[1], NULL, 0) : 99U;
	unsigned long context = make_context(&client);
	unsigned long bo = make_bo(&client, scenario == 12U ? 4096U : 1025U, 0x100000UL);
	struct gpu_private_map_request request = {
		.request_id = 1UL, .object = bo, .iova = 0x200000UL,
		.count = scenario == 12U ? 4096UL : 1025UL,
		.prot = GPU_PRIVATE_READ | GPU_PRIVATE_WRITE | GPU_PRIVATE_CACHE
	};
	struct gpu_private_result result, check, replay;
	unsigned long token;
	unsigned int before = allocated_tables();

	assert(scenario <= 19U);
	if (scenario == 19U) {
		/* Internal mappings can precede the first ordinary VM_BIND. */
		gpu_private_map(&ops, &client, context, bo, 0UL, 0x10000000UL, 1U,
			request.prot, &check);
		assert(check.status == GPU_PRIVATE_SUCCESS);
		gpu_private_mapping_version(&client, context, &check);
		assert(check.status == GPU_PRIVATE_SUCCESS && check.value[0] == 1UL);
		assert(gpu_private_mapping_accept(&service, &client, context, check.value[0]));
		assert(gpu_private_mapping_accept(&service, &client, context, 0UL));
		assert(!gpu_private_mapping_accept(&service, &client, context, check.value[0] + 1UL));
		request.version = check.value[0];
		result = finish(begin(context, &request));
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[1] == 2UL);
		assert(gpu_private_mapping_accept(&service, &client, context, 2UL));
		assert(!gpu_private_mapping_accept(&service, &client, context, 0UL));
		assert(!gpu_private_mapping_accept(&service, &client, context, 1UL));
	} else if (scenario == 1U) {
		gpu_private_map_begin(&ops, &other, context, &request, &result);
		assert(result.status == GPU_PRIVATE_INPUT);
		request.object = make_bo(&other, 1U, 0x100000UL);
		result = begin(context, &request);
		assert(result.status != GPU_PRIVATE_SUCCESS && result.status != GPU_PRIVATE_INCOMPLETE);
		assert(!ctx_lookup(&client, context)->map_transaction_active);
	} else if (scenario == 2U) {
		struct gpu_private_map_request bad = request;

		bad.iova = GPU_PRIVATE_CONTROL_GPU_VA;
		assert(begin(context, &bad).status == GPU_PRIVATE_INPUT);
		bad = request; bad.offset = 1UL;
		assert(begin(context, &bad).status == GPU_PRIVATE_INPUT);
		bad = request; bad.prot = 16UL | GPU_PRIVATE_READ;
		assert(begin(context, &bad).status == GPU_PRIVATE_INPUT);
		bad = request; bad.count++;
		assert(begin(context, &bad).status == GPU_PRIVATE_INPUT);
		bad = request; bad.iova = GPU_PRIVATE_CONTROL_GPU_VA - GPU_PRIVATE_PAGE_SIZE;
		assert(begin(context, &bad).status == GPU_PRIVATE_INPUT);
		bo_lookup(&client, bo)->access = GPU_PRIVATE_READ;
		assert(begin(context, &request).status == GPU_PRIVATE_INPUT);
		bo_lookup(&client, bo)->access = GPU_PRIVATE_ACCESS;
		bo_lookup(&client, bo)->registered--;
		assert(begin(context, &request).status == GPU_PRIVATE_INPUT);
	} else if (scenario == 3U) {
		assert(gpu_private_context_hold(&service, &client, context));
		const struct gpu_private_command_range empty = { 0 };
		assert(gpu_private_task_hold_batch(&ops, &service, &client, context, &empty, 1U));
		assert(begin(context, &request).status == GPU_PRIVATE_STATE);
		assert(gpu_private_task_put(&client, context));
		result = begin(context, &request);
		assert(result.status == GPU_PRIVATE_INCOMPLETE);
		assert(!gpu_private_mapping_accept(&service, &client, context, 0UL));
		assert(!gpu_private_task_hold_batch(&ops, &service, &client, context, &empty, 1U));
		gpu_private_context_activate(&ops, &service, context, 1UL, &check);
		assert(check.status == GPU_PRIVATE_STATE && activations == 0U);
		gpu_private_map(&ops, &client, context, bo, 0UL, 0x10000000UL, 1U,
			request.prot, &check);
		assert(check.status == GPU_PRIVATE_STATE);
		gpu_private_unmap(&ops, &client, context, request.iova, 1U, &check);
		assert(check.status == GPU_PRIVATE_STATE);
		gpu_private_mapping_check(&ops, &client, context, 0UL, 0UL,
			request.iova, 1U, 0UL, &check);
		assert(check.status == GPU_PRIVATE_STATE);
	} else if (scenario == 4U || scenario == 5U || scenario == 6U) {
		result = begin(context, &request);
		token = result.value[0];
		while (result.value[3] == GPU_PRIVATE_MAP_RESERVE)
			result = step(token, result.value[2]);
		assert(pte(context, request.iova) == 0UL);
		if (scenario != 4U)
			result = step(token, result.value[2]);
		if (scenario == 6U) {
			while (result.value[3] != GPU_PRIVATE_MAP_COMMIT)
				result = step(token, result.value[2]);
			barrier_ok = false;
			result = step(token, result.value[2]);
		} else {
			gpu_private_map_abort(&ops, &client, token, &result);
		}
		if (scenario == 4U) {
			assert(result.status == GPU_PRIVATE_SUCCESS && result.value[3] == GPU_PRIVATE_MAP_ABORTED);
			assert(allocated_tables() == before && pte(context, request.iova) == 0UL);
			assert(bo_lookup(&client, bo)->pending == 0U && bo_lookup(&client, bo)->mapped == 0U);
			gpu_private_mapping_version(&client, context, &check);
			assert(check.status == GPU_PRIVATE_SUCCESS && check.value[0] == 0UL);
		} else {
			assert(result.status == GPU_PRIVATE_STATE && result.value[1] == 0UL);
			assert(ctx_lookup(&client, context)->quarantined);
			assert(bo_lookup(&client, bo)->pending == 1U && bo_lookup(&client, bo)->mapped != 0U);
			gpu_private_bo_destroy(&client, bo, &check);
			assert(check.status != GPU_PRIVATE_SUCCESS && bo_lookup(&client, bo) != NULL);
			reset_and_reclaim(context, bo);
		}
	} else if (scenario == 7U || scenario == 8U || scenario == 9U) {
		result = finish(begin(context, &request));
		assert(result.status == GPU_PRIVATE_SUCCESS);
		unsigned long old = bo;
		request.version = result.value[1];
		request.request_id++;
		request.object = scenario == 8U ? 0UL : make_bo(&client, 1025U, 0x2000000UL);
		if (scenario == 8U) request.prot = 0UL;
		result = begin(context, &request);
		token = result.value[0];
		while (result.value[3] != GPU_PRIVATE_MAP_COMMIT)
			result = step(token, result.value[2]);
		assert(bo_lookup(&client, old)->mapped == 1025U);
		assert(ctx_lookup(&client, context)->mapped == (scenario == 8U ? 0U : 1025U));
		if (scenario == 9U) barrier_ok = false;
		result = step(token, result.value[2]);
		assert(result.status == (scenario == 9U ? GPU_PRIVATE_STATE : GPU_PRIVATE_SUCCESS));
		if (scenario != 9U) {
			assert(result.value[1] == 2UL && bo_lookup(&client, old)->mapped == 0U);
			assert((pte(context, request.iova) & ADDRESS_MASK) ==
				(scenario == 8U ? 0UL : 0x42000000UL));
		} else {
			assert(bo_lookup(&client, old)->mapped == 1025U);
			assert(bo_lookup(&client, request.object)->mapped == 1025U);
			reset_and_reclaim(context, old);
			assert(bo_lookup(&client, request.object)->mapped == 0U);
		}
	} else if (scenario == 10U) {
		result = finish(begin(context, &request));
		assert(result.status == GPU_PRIVATE_SUCCESS);
		unsigned long second = make_context(&client);
		request.request_id++;
		request.prot &= ~GPU_PRIVATE_CACHE;
		assert(begin(second, &request).status == GPU_PRIVATE_STATE);
		gpu_private_map(&ops, &client, second, bo, 0UL, request.iova, 1U, request.prot, &check);
		assert(check.status == GPU_PRIVATE_STATE);
		request.prot |= GPU_PRIVATE_CACHE;
		result = finish(begin(second, &request));
		assert(result.status == GPU_PRIVATE_SUCCESS && bo_lookup(&client, bo)->mapped == 2050U);
	} else if (scenario == 11U) {
		result = begin(context, &request);
		token = result.value[0];
		replay = begin(context, &request);
		assert(memcmp(&result, &replay, sizeof(result)) == 0);
		request.iova += GPU_PRIVATE_PAGE_SIZE;
		assert(begin(context, &request).status == GPU_PRIVATE_STATE);
		request.iova -= GPU_PRIVATE_PAGE_SIZE;
		assert(step(token, 1UL).status == GPU_PRIVATE_STATE);
		gpu_private_map_step(&ops, &other, token, 0UL, &check);
		assert(check.status == GPU_PRIVATE_INPUT);
		result = finish(result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		replay = begin(context, &request);
		assert(memcmp(&result, &replay, sizeof(result)) == 0);
		unsigned int saved_barriers = barriers;
		replay = step(token, result.value[2] - 1UL);
		assert(memcmp(&result, &replay, sizeof(result)) == 0 && barriers == saved_barriers);
		request.request_id++;
		assert(begin(context, &request).status == GPU_PRIVATE_STATE); /* stale version */
	} else if (scenario == 12U) {
		assert(GPU_PRIVATE_TABLES == 8U);
		result = finish(begin(context, &request));
		assert(result.status == GPU_PRIVATE_STATE && allocated_tables() == before);
		assert(pte(context, request.iova) == 0UL && bo_lookup(&client, bo)->pending == 0U);
		request.request_id++;
		request.count = 1UL;
		result = finish(begin(context, &request));
		assert(result.status == GPU_PRIVATE_SUCCESS);
	} else if (scenario == 13U) {
		result = begin(context, &request);
		unsigned long second = make_context(&client);
		assert(begin(second, &request).status == GPU_PRIVATE_STATE);
		observed_context = context;
		before = allocated_tables();
		bo_lookup(&client, bo)->closing = true;
		check = step(result.value[0], 0UL);
		assert(check.status == GPU_PRIVATE_STATE && allocated_tables() == before);
		assert(!ctx_lookup(&client, context)->map_transaction_active);
	} else if (scenario == 14U) {
		ctx_lookup(&client, context)->mapping_epoch = ULONG_MAX;
		request.version = ULONG_MAX;
		assert(begin(context, &request).status == GPU_PRIVATE_STATE);
	} else if (scenario == 15U) {
		result = finish(begin(context, &request));
		assert(result.status == GPU_PRIVATE_SUCCESS);
		assert(!gpu_private_mapping_accept(&service, &other, context, result.value[1]));
		assert(!gpu_private_mapping_accept(&other, &client, context, result.value[1]));
		assert(!gpu_private_mapping_accept(&service, &client, context, result.value[1] - 1UL));
		assert(gpu_private_mapping_accept(&service, &client, context, result.value[1]));
		gpu_private_service_unmap(&ops, &service, &client, context, request.iova, 1U, &check);
		assert(check.status == GPU_PRIVATE_INPUT && pte(context, request.iova) != 0UL);
		gpu_private_map_authorize(&client, context, bo, 0UL, 0x10000000UL, 1U, request.prot, &check);
		assert(check.status == GPU_PRIVATE_STATE);
		activate_ok = false;
		gpu_private_context_activate(&ops, &service, context, 1UL, &check);
		assert(check.status == GPU_PRIVATE_STATE && activations == 1U);
		assert(ctx_lookup(&client, context)->quarantined && bo_lookup(&client, bo)->mapped == 1025U);
		reset_and_reclaim(context, bo);
	} else if (scenario == 16U) {
		unsigned int remaining = GPU_PRIVATE_BLOCKS - 3U;
		unsigned long address = 0x2000000UL, first_bo = 0UL;

		while (remaining != 0U) {
			unsigned int blocks = remaining > GPU_PRIVATE_BO_BLOCKS ? GPU_PRIVATE_BO_BLOCKS : remaining;
			unsigned long extra = make_bo(&client, blocks * ENTRIES, address);

			if (first_bo == 0UL) first_bo = extra;
			address += blocks * ENTRIES * GPU_PRIVATE_PAGE_SIZE + 0x100000UL;
			remaining -= blocks;
		}
		assert(begin(context, &request).status == GPU_PRIVATE_FULL);
		assert(!ctx_lookup(&client, context)->map_transaction_active);
		assert(bo_lookup(&client, bo)->pending == 0U && allocated_tables() == before);
		do { gpu_private_bo_destroy(&client, first_bo, &check); }
		while (check.status == GPU_PRIVATE_INCOMPLETE);
		assert(check.status == GPU_PRIVATE_SUCCESS);
		assert(finish(begin(context, &request)).status == GPU_PRIVATE_SUCCESS);
	} else if (scenario == 17U) {
		unsigned long address = (1UL << 44U) - 0x40000000UL - 8192UL;
		unsigned long high = make_bo(&client, 2U, address);

		assert(!gpu_private_range_busy(&client, address - 4096UL, 4096UL));
		assert(gpu_private_range_busy(&client, address - 1UL, 2UL));
		assert(gpu_private_range_busy(&client, address + 8191UL, 1UL));
		assert(!gpu_private_range_busy(&client, address + 8192UL, 1UL));
		request.object = high;
		request.count = 2UL;
		assert(finish(begin(context, &request)).status == GPU_PRIVATE_SUCCESS);
		assert((pte(context, request.iova + 4096UL) & ADDRESS_MASK) == (1UL << 44U) - 4096UL);
	} else if (scenario == 18U) {
		result = finish(begin(context, &request));
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[1] == 1UL);
		gpu_private_map(&ops, &client, context, bo, 0UL, 0x10000000UL, 1U, request.prot, &check);
		assert(check.status == GPU_PRIVATE_SUCCESS);
		check = begin(context, &request);
		assert(check.status == GPU_PRIVATE_SUCCESS && check.value[1] == 1UL);
		assert(!gpu_private_mapping_accept(&service, &client, context, check.value[1]));
		gpu_private_mapping_version(&client, context, &check);
		assert(check.status == GPU_PRIVATE_SUCCESS && check.value[0] == 2UL);
	} else {
		result = begin(context, &request);
		assert(result.status == GPU_PRIVATE_INCOMPLETE);
		token = result.value[0];
		while (result.status == GPU_PRIVATE_INCOMPLETE) {
			gpu_private_mapping_version(&client, context, &check);
			assert(check.status == GPU_PRIVATE_STATE);
			unsigned long sequence = result.value[2];
			result = step(token, sequence);
			replay = step(token, sequence);
			assert(memcmp(&result, &replay, sizeof(result)) == 0);
		}
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[1] == 1UL && barriers == 1U);
		for (unsigned int i = 0U; i < 1025U; i++) {
			uint64_t leaf = pte(context, request.iova + i * GPU_PRIVATE_PAGE_SIZE);
			assert((leaf & ADDRESS_MASK) == 0x40100000UL + i * GPU_PRIVATE_PAGE_SIZE);
			assert((leaf & PTE_XN) == PTE_XN && (leaf & PTE_RO) == 0UL);
		}
		gpu_private_mapping_version(&client, context, &check);
		assert(check.status == GPU_PRIVATE_SUCCESS && check.value[0] == 1UL);
	}
	printf("MAP_TRANSACTION scenario=%u PASS\n", scenario);
	return 0;
}
