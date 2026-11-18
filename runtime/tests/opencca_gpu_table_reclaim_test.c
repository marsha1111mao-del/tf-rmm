/* SPDX-License-Identifier: BSD-3-Clause */
/* Public mapping operations with the production core. Private state is read
 * for independent reference accounting and changed only for fault injection.
 */
#include <stdio.h>
#include <stdlib.h>
#include <opencca_gpu_private.c>

static int clients[4], service;
static unsigned long next_request = 1UL;
static bool barrier_ok = true;
static unsigned int cleans;

static bool source(const void *owner, unsigned long ipa, unsigned long *pa)
{
	assert(owner == &clients[0] || owner == &clients[1] ||
		owner == &clients[2] || owner == &clients[3]);
	if (gpu_private_range_busy(owner, ipa, GPU_PRIVATE_PAGE_SIZE))
		return false;
	*pa = ipa + 0x40000000UL;
	return true;
}

static unsigned long physical_table(const void *table)
{
	return 0x100000000UL + (const unsigned char *)table - (const unsigned char *)tables;
}

static void clean_table(const void *table, size_t bytes)
{
	assert(table != NULL && bytes != 0U);
	cleans++;
}

static bool barrier(void) { return barrier_ok; }
static const struct gpu_private_ops ops = {
	.source_page = source, .table_pa = physical_table,
	.clean = clean_table, .cache_barrier = barrier
};

static unsigned long make_context(unsigned int owner)
{
	struct gpu_private_result r;

	gpu_private_context_create(&ops, &clients[owner], &service, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	return r.value[0];
}

static unsigned long make_bo(unsigned int owner, unsigned int pages)
{
	struct gpu_private_result r;
	unsigned long ipas[GPU_PRIVATE_BATCH];

	gpu_private_bo_create(&clients[owner], &service, pages * GPU_PRIVATE_PAGE_SIZE, 3UL, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	unsigned long bo = r.value[0];

	for (unsigned int first = 0U; first < pages;) {
		unsigned int count = pages - first;

		if (count > GPU_PRIVATE_BATCH) count = GPU_PRIVATE_BATCH;
		for (unsigned int i = 0U; i < count; i++)
			ipas[i] = 0x40000000UL * (owner + 1U) + (first + i) * GPU_PRIVATE_PAGE_SIZE;
		gpu_private_bo_append(&ops, &clients[owner], bo, first * GPU_PRIVATE_PAGE_SIZE,
			ipas, count, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS);
		first += count;
	}
	return bo;
}

static unsigned int allocated(void)
{
	unsigned int n = 0U;

	for (unsigned int i = 0U; i < GPU_PRIVATE_TABLES; i++) n += table_owner[i] != 0UL;
	return n;
}

/* Inspect actual hardware-format links, independently of walk/table_index. */
static void visit(unsigned int table, unsigned int level, unsigned long context,
		bool seen[GPU_PRIVATE_TABLES])
{
	assert(table < GPU_PRIVATE_TABLES && !seen[table] && table_owner[table] == context);
	seen[table] = true;
	for (unsigned int i = 0U; i < ENTRIES; i++) {
		uint64_t entry = tables[table][i];

		if (entry == 0UL) {
			assert(leaf_object[table][i] == 0U);
			continue;
		}
		assert((entry & 3UL) == 3UL);
		if (level == 3U) {
			assert(leaf_object[table][i] != 0U);
			continue;
		}
		unsigned long pa = entry & ADDRESS_MASK;

		assert(pa >= physical_table(tables[0]));
		unsigned long child = (pa - physical_table(tables[0])) / GPU_PRIVATE_PAGE_SIZE;

		assert(child < GPU_PRIVATE_TABLES && physical_table(tables[child]) == pa);
		visit((unsigned int)child, level + 1U, context, seen);
	}
}

static void audit(void)
{
	bool seen[GPU_PRIVATE_TABLES] = {false};

	for (unsigned int i = 0U; i < GPU_PRIVATE_CONTEXTS; i++)
		if (contexts[i].handle != 0UL)
			visit(contexts[i].root, 0U, contexts[i].handle, seen);
	for (unsigned int i = 0U; i < GPU_PRIVATE_TABLES; i++)
		assert(seen[i] == (table_owner[i] != 0UL));
}

static struct gpu_private_result begin(unsigned int owner, unsigned long ctx,
		unsigned long bo, unsigned long va, unsigned long count)
{
	struct gpu_private_result r;

	gpu_private_mapping_version(&clients[owner], ctx, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	struct gpu_private_map_request request = {
		.request_id = next_request++, .version = r.value[0], .object = bo,
		.iova = va, .count = count, .prot = bo != 0UL ? 3UL : 0UL
	};

	gpu_private_map_begin(&ops, &clients[owner], ctx, &request, &r);
	return r;
}

static struct gpu_private_result finish(unsigned int owner, struct gpu_private_result r)
{
	unsigned int calls = 0U;

	while (r.status == GPU_PRIVATE_INCOMPLETE) {
		struct gpu_private_result replay;
		unsigned long token = r.value[0], sequence = r.value[2];

		assert(++calls < 2048U);
		gpu_private_map_step(&ops, &clients[owner], token, sequence, &r);
		unsigned int before = cleans;

		gpu_private_map_step(&ops, &clients[owner], token, sequence, &replay);
		assert(cleans == before);
		/* A quarantined context rejects before the replay cache lookup. */
		if (r.status == GPU_PRIVATE_STATE)
			assert(replay.status == GPU_PRIVATE_STATE);
		else
			assert(memcmp(&r, &replay, sizeof(r)) == 0);
	}
	return r;
}

static void change(unsigned int owner, unsigned long ctx, unsigned long bo,
		unsigned long va, unsigned long count)
{
	struct gpu_private_result r = finish(owner, begin(owner, ctx, bo, va, count));

	if (r.status != GPU_PRIVATE_SUCCESS)
		fprintf(stderr, "mapping failed owner=%u status=%lu phase=%lu tables=%u/%u\n",
			owner, r.status, r.value[3], allocated(), GPU_PRIVATE_TABLES);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	audit();
}

int main(int argc, char **argv)
{
	unsigned int scenario = argc == 2 ? (unsigned int)strtoul(argv[1], NULL, 0) : 99U;
	unsigned long ctx[4], bo[4];
	struct gpu_private_result r;

	assert(scenario <= 5U);
	for (unsigned int i = 0U; i < 4U; i++) {
		ctx[i] = make_context(i);
		bo[i] = make_bo(i, 513U);
	}
	if (scenario == 0U) {
		/* Four independent owners, more distinct VA regions than the global
		 * capacity, but only one live data page at a time. No context close.
		 */
		for (unsigned int n = 0U; n < GPU_PRIVATE_TABLES + 8U; n++)
			for (unsigned int i = 0U; i < 4U; i++) {
				unsigned long va = (n + 1UL) * 0x200000UL;

				change(i, ctx[i], bo[i], va, 1UL);
				change(i, ctx[i], 0UL, va, 1UL);
			}
		assert(allocated() == 4U);
	} else if (scenario == 1U) {
		change(1U, ctx[1], bo[1], 0x1ff000UL, 513UL);
		change(0U, ctx[0], bo[0], 0x1ff000UL, 513UL);
		unsigned int before = allocated();

		change(0U, ctx[0], 0UL, 0x200000UL, 511UL);
		assert(allocated() == before); /* Both neighboring leaves remain. */
		change(0U, ctx[0], 0UL, 0x1ff000UL, 1UL);
		change(0U, ctx[0], 0UL, 0x3ff000UL, 1UL);
		assert(ctx_lookup(&clients[0], ctx[0])->mapped == 0U);
		assert(ctx_lookup(&clients[1], ctx[1])->mapped == 513U);
		change(1U, ctx[1], 0UL, 0x1ff000UL, 513UL);
		assert(allocated() == 4U);
	} else if (scenario == 2U) {
		/* Exercise both legacy unmap APIs and all three intermediate levels. */
		change(0U, ctx[0], bo[0], 0x8000000000UL, 1UL);
		gpu_private_unmap(&ops, &clients[0], ctx[0], 0x8000000000UL, 1UL, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS && allocated() == 4U);
		audit();
		change(1U, ctx[1], bo[1], 0x40000000UL, 1UL);
		gpu_private_unmap_bo(&ops, &clients[1], ctx[1], bo[1], 0UL, 0x40000000UL, 1UL, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS && allocated() == 4U);
		audit();
	} else if (scenario == 3U) {
		change(0U, ctx[0], bo[0], 0x200000UL, 1UL);
		struct private_context *c = ctx_lookup(&clients[0], ctx[0]);
		unsigned int before = allocated();

		for (unsigned int bad = 0U; bad < 4U; bad++) {
			c->activated = bad == 0U; c->task_refs = bad == 1U;
			c->quarantined = bad == 2U; c->revoked = bad == 3U;
			struct gpu_private_map_request q = {
				.request_id = next_request++, .version = c->mapping_epoch,
				.iova = 0x200000UL, .count = 1UL
			};

			gpu_private_map_begin(&ops, &clients[0], ctx[0], &q, &r);
			assert(r.status == GPU_PRIVATE_STATE && allocated() == before && c->mapped == 1U);
			audit();
		}
		c->activated = c->quarantined = c->revoked = false; c->task_refs = 0U;
		change(0U, ctx[0], 0UL, 0x200000UL, 1UL);
		assert(allocated() == 4U);
	} else if (scenario == 4U) {
		/* Another owner's unmap cannot reclaim this transaction's empty
		 * reserved tables. Check both abort and the subsequent fresh commit.
		 */
		r = begin(0U, ctx[0], bo[0], 0x200000UL, 513UL);
		assert(r.status == GPU_PRIVATE_INCOMPLETE);
		gpu_private_map_step(&ops, &clients[0], r.value[0], 0UL, &r);
		assert(r.status == GPU_PRIVATE_INCOMPLETE && r.value[3] == GPU_PRIVATE_MAP_RESERVE);
		unsigned long token = r.value[0];
		unsigned int before = allocated();

		change(1U, ctx[1], bo[1], 0x200000UL, 1UL);
		change(1U, ctx[1], 0UL, 0x200000UL, 1UL);
		assert(allocated() == before);
		gpu_private_map_abort(&ops, &clients[0], token, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS && allocated() == 4U);
		change(0U, ctx[0], bo[0], 0x200000UL, 513UL);
		change(0U, ctx[0], 0UL, 0x200000UL, 513UL);
		assert(allocated() == 4U);
	} else {
		change(0U, ctx[0], bo[0], 0x200000UL, 1UL);
		barrier_ok = false;
		r = finish(0U, begin(0U, ctx[0], 0UL, 0x200000UL, 1UL));
		assert(r.status == GPU_PRIVATE_STATE);
		struct private_context *c = ctx_lookup(&clients[0], ctx[0]);

		assert(c->quarantined && c->map_transaction_active && !c->activated);
		assert(bo_lookup(&clients[0], bo[0])->mapped == 1U); /* No backing release. */
		gpu_private_bo_destroy(&clients[0], bo[0], &r);
		assert(r.status == GPU_PRIVATE_STATE);
		barrier_ok = true;
		change(1U, ctx[1], bo[1], 0x200000UL, 1UL);
		assert(c->quarantined && bo_lookup(&clients[0], bo[0])->mapped == 1U);
	}
	printf("GPU_TABLE_RECLAIM scenario=%u PASS; actual core, modeled memory\n", scenario);
	return 0;
}
