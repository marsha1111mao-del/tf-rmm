/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <limits.h>
#include <opencca_gpu_private.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PAGE 4096UL
#define TABLE_PA 0x100000000UL
#define PTE_PA 0x0000fffffffff000UL

static int client_a, client_b, proxy, stranger;
static const unsigned char *table_base;
static unsigned int source_reads, cleans, synchronizations;
static unsigned int activations;
static unsigned long backend_root;
static unsigned long fail_ipa = ULONG_MAX;
static bool sync_success;

static bool source_page(const void *owner, unsigned long ipa, unsigned long *pa)
{
	source_reads++;
	if (owner == NULL || ipa == fail_ipa ||
	    gpu_private_range_busy(owner, ipa, PAGE))
		return false;
	/* Model the trusted RTT's metadata translation, not a data-page read. */
	*pa = ipa + (owner == &client_a ? 0x40000000UL : 0x80000000UL);
	return true;
}

static unsigned long table_pa(const void *table)
{
	if (table_base == NULL)
		table_base = table;
	assert((const unsigned char *)table >= table_base);
	return TABLE_PA + (unsigned long)((const unsigned char *)table - table_base);
}

static void clean(const void *table, size_t bytes)
{
	assert(table != NULL && bytes != 0U);
	cleans++;
}

static bool synchronize(unsigned long context, unsigned long root)
{
	assert(context != 0UL && root >= TABLE_PA && (root & 4095UL) == 0UL);
	synchronizations++;
	return sync_success;
}

static bool activate(unsigned long context, unsigned long root, unsigned int slot)
{
	assert(context != 0UL && root >= TABLE_PA && (root & 4095UL) == 0UL);
	assert(slot < GPU_PRIVATE_AS_SLOTS);
	backend_root = root;
	activations++;
	return sync_success;
}

static const struct gpu_private_ops ops = {
	.source_page = source_page, .table_pa = table_pa,
	.clean = clean, .activate = activate, .synchronize = synchronize
};

static unsigned long object(const void *owner, unsigned int pages, unsigned long access)
{
	struct gpu_private_result result;

	gpu_private_bo_create(owner, &proxy, pages * PAGE, access, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] != 0UL);
	return result.value[0];
}

static unsigned long context(const void *owner)
{
	struct gpu_private_result result;

	gpu_private_context_create(&ops, owner, &proxy, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	return result.value[0];
}

static struct gpu_private_result append(const void *owner, unsigned long handle,
		unsigned long offset, unsigned long ipa, size_t count)
{
	unsigned long pages[GPU_PRIVATE_BATCH];
	struct gpu_private_result result;

	assert(count <= GPU_PRIVATE_BATCH);
	for (size_t i = 0U; i < count; i++)
		pages[i] = ipa + i * PAGE;
	gpu_private_bo_append(&ops, owner, handle, offset, pages, count, &result);
	return result;
}

static struct gpu_private_result map(const void *owner, unsigned long ctx,
		unsigned long bo, unsigned long offset, unsigned long va,
		size_t count, unsigned long prot)
{
	struct gpu_private_result result;

	gpu_private_map(&ops, owner, ctx, bo, offset, va, count, prot, &result);
	return result;
}

static void destroy_object(const void *owner, unsigned long bo)
{
	struct gpu_private_result result;

	do {
		gpu_private_bo_destroy(owner, bo, &result);
	} while (result.status == GPU_PRIVATE_INCOMPLETE);
	assert(result.status == GPU_PRIVATE_SUCCESS);
}

static void destroy_context(const void *owner, unsigned long ctx)
{
	struct gpu_private_result result;

	gpu_private_context_destroy(&ops, owner, ctx, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
}

static unsigned long authorize(const void *owner, unsigned long ctx,
		unsigned long bo, unsigned long offset, unsigned long va,
		size_t count, unsigned long prot)
{
	struct gpu_private_result result;

	gpu_private_map_authorize(owner, ctx, bo, offset, va, count, prot, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] != 0UL);
	return result.value[0];
}

/* Independently walk the real four-level hardware descriptors. */
static uint64_t pte_at(unsigned long root, unsigned long va)
{
	unsigned long pa = root;

	for (unsigned int level = 0U; level < 4U; level++) {
		const uint64_t *table;
		uint64_t pte;

		assert(pa >= TABLE_PA && pa < TABLE_PA + GPU_PRIVATE_TABLES * PAGE);
		table = (const uint64_t *)(table_base + pa - TABLE_PA);
		pte = table[(va >> (39U - level * 9U)) & 511UL];
		assert((pte & 3UL) == 3UL);
		if (level == 3U)
			return pte;
		pa = (unsigned long)pte & PTE_PA;
	}
	assert(false);
	return 0;
}

static int table_exhaustion(void)
{
	struct gpu_private_result result;
	unsigned long bo = object(&client_a, 1U, 3UL);
	unsigned long ctx = context(&client_a);
	unsigned long grant;

	assert(GPU_PRIVATE_TABLES == 8U);
	assert(append(&client_a, bo, 0UL, 0x100000UL, 1U).status == 0UL);
	assert(map(&client_a, ctx, bo, 0UL, 0UL, 1U, 3UL).status == 0UL);
	assert(map(&client_a, ctx, bo, 0UL, 1UL << 30U, 1U, 3UL).status == 0UL);
	/* Six tables are live; a distant root branch needs three more. Repeated
	 * failures must return their empty preflight allocations to the pool.
	 */
	grant = authorize(&client_a, ctx, bo, 0UL, 1UL << 39U, 1U, 3UL);
	for (unsigned int i = 0U; i < 64U; i++) {
		gpu_private_service_map(&ops, &proxy, &client_a, ctx, grant,
			0UL, 1UL << 39U, 1U, 3UL, &result);
		assert(result.status == GPU_PRIVATE_FULL);
	}
	gpu_private_map_cancel(&client_a, grant, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	assert(map(&client_a, ctx, bo, 0UL, 1UL << 21U, 1U, 3UL).status == 0UL);
	gpu_private_query(&client_a, ctx, 0UL, &result);
	assert(result.status == 0UL && result.value[0] == 3UL);
	gpu_private_unmap(&ops, &client_a, ctx, 0UL, 1U, &result);
	assert(result.status == 0UL);
	gpu_private_unmap(&ops, &client_a, ctx, 1UL << 30U, 1U, &result);
	assert(result.status == 0UL);
	gpu_private_unmap(&ops, &client_a, ctx, 1UL << 21U, 1U, &result);
	assert(result.status == 0UL);
	destroy_context(&client_a, ctx);
	destroy_object(&client_a, bo);
	assert(!gpu_private_owner_busy(&client_a));
	puts("GPU_PRIVATE_EXHAUSTION=PASS failed batches reclaim empty tables without publishing mappings");
	return 0;
}

static int root_boundary(void)
{
	struct gpu_private_result result;
	unsigned long bo = object(&client_a, 2U, 3UL);
	unsigned long ctx = context(&client_a);
	unsigned long va = (1UL << 39U) - PAGE;

	assert(append(&client_a, bo, 0UL, 0x400000UL, 2U).status == 0UL);
	/* Both sides of an L0 boundary need a full three-table subtree. */
	assert(map(&client_a, ctx, bo, 0UL, va, 2U, 3UL).status == 0UL);
	sync_success = true;
	gpu_private_context_activate(&ops, &proxy, ctx, GPU_PRIVATE_AS_SLOTS - 1UL, &result);
	assert(result.status == 0UL && result.value[0] == ctx);
	assert((pte_at(backend_root, va) & PTE_PA) == 0x40400000UL);
	assert((pte_at(backend_root, va + PAGE) & PTE_PA) == 0x40401000UL);
	puts("GPU_PRIVATE_ROOT_BOUNDARY=PASS six new non-leaf tables and independent walks across 512 GiB boundary");
	return 0;
}

static int service_mapping(void)
{
	struct gpu_private_result result;
	unsigned long a = object(&client_a, 2U, GPU_PRIVATE_READ);
	unsigned long b = object(&client_b, 1U, 3UL);
	unsigned long ca = context(&client_a), cb = context(&client_b);
	unsigned long other, stale, grant;
	unsigned int reads;

	gpu_private_bo_inspect(&proxy, &client_a, a, &result);
	assert(result.status == GPU_PRIVATE_STATE); /* incomplete backing */
	assert(append(&client_a, a, 0UL, 0x100000UL, 2U).status == 0UL);
	assert(append(&client_b, b, 0UL, 0x100000UL, 1U).status == 0UL);
	reads = source_reads;
	gpu_private_bo_inspect(&proxy, &client_a, a, &result);
	assert(result.status == 0UL && result.value[0] == 2UL * PAGE);
	assert(result.value[1] == GPU_PRIVATE_READ && result.value[2] == 2UL);
	assert(result.value[3] == 0UL);
	gpu_private_bo_inspect(&stranger, &client_a, a, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_bo_inspect(&proxy, &client_b, a, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_context_inspect(&stranger, &client_a, ca, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_context_inspect(&proxy, &client_b, ca, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_context_inspect(&proxy, &client_a, ca, &result);
	assert(result.status == 0UL && result.value[0] == 0UL && result.value[1] == 0UL);
	assert(result.value[2] == 0UL && result.value[3] == 0UL);
	grant = authorize(&client_a, ca, a, 0UL, 0x1000UL, 2U,
		GPU_PRIVATE_READ | GPU_PRIVATE_CACHE);

	/* Same service handles both Clients, but neither a substituted channel
	 * peer nor another Client's object/context can authorize a mapping.
	 */
	gpu_private_service_map(&ops, &stranger, &client_a, ca, grant,
		0UL, 0x1000UL, 1U, GPU_PRIVATE_READ, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_service_map(&ops, &proxy, &client_b, ca, grant,
		0UL, 0x1000UL, 1U, GPU_PRIVATE_READ, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_service_map(&ops, &proxy, &client_a, cb, grant,
		0UL, 0x1000UL, 1U, GPU_PRIVATE_READ, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_service_map(&ops, &proxy, &client_a, ca, b,
		0UL, 0x1000UL, 1U, GPU_PRIVATE_READ, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_bo_create(&client_a, &stranger, PAGE, 3UL, &result);
	assert(result.status == 0UL);
	other = result.value[0];
	assert(append(&client_a, other, 0UL, 0x300000UL, 1U).status == 0UL);
	gpu_private_map_authorize(&client_a, ca, other, 0UL, 0x1000UL, 1U,
		GPU_PRIVATE_READ, &result);
	assert(result.status == GPU_PRIVATE_INPUT); /* different bound service */
	gpu_private_service_map(&ops, &proxy, &client_a, ca, other,
		0UL, 0x1000UL, 1U, GPU_PRIVATE_READ, &result);
	assert(result.status == GPU_PRIVATE_INPUT); /* different bound service */
	destroy_object(&client_a, other);

	gpu_private_service_map(&ops, &proxy, &client_a, ca, grant,
		0UL, 0x1000UL, 1U, 3UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT); /* no write expansion */
	gpu_private_service_map(&ops, &proxy, &client_a, ca, grant,
		PAGE, 0x1000UL, 2U, GPU_PRIVATE_READ, &result);
	assert(result.status == GPU_PRIVATE_INPUT); /* no range expansion */
	gpu_private_service_map(&ops, &proxy, &client_a, ca, grant,
		0UL, 0x1000UL, 2U, GPU_PRIVATE_READ | GPU_PRIVATE_CACHE, &result);
	assert(result.status == 0UL && result.value[0] == 2UL * PAGE);
	gpu_private_context_inspect(&proxy, &client_a, ca, &result);
	assert(result.status == 0UL && result.value[0] == 2UL);
	/* Mapping uses the registered translation; the service never supplies a
	 * PA or triggers a new source-page translation or data read.
	 */
	assert(source_reads == reads + 1U); /* only the separate 'other' BO */

	gpu_private_service_unmap(&ops, &stranger, &client_a, ca, 0x1000UL, 2U, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_service_unmap(&ops, &proxy, &client_b, ca, 0x1000UL, 2U, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_context_inspect(&proxy, &client_a, ca, &result);
	assert(result.status == 0UL && result.value[0] == 2UL);
	gpu_private_service_unmap(&ops, &proxy, &client_a, ca, 0x1000UL, 2U, &result);
	assert(result.status == 0UL);
	stale = a;
	destroy_object(&client_a, a);
	gpu_private_bo_inspect(&proxy, &client_a, stale, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_service_map(&ops, &proxy, &client_a, ca, stale,
		0UL, 0UL, 1U, GPU_PRIVATE_READ, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	destroy_context(&client_a, ca);
	destroy_context(&client_b, cb);
	destroy_object(&client_b, b);
	assert(!gpu_private_owner_busy(&proxy));
	puts("GPU_PRIVATE_SERVICE=PASS metadata-only import, authenticated peer, service/context/object substitution, access bounds, stale handles, cleanup");
	return 0;
}

static int mapping_authorization(void)
{
	struct gpu_private_result result;
	unsigned long a = object(&client_a, 513U, 3UL);
	unsigned long other = object(&client_a, 1U, GPU_PRIVATE_READ);
	unsigned long ca = context(&client_a), ca2 = context(&client_a);
	unsigned long grant, stale, grants[GPU_PRIVATE_CONTEXT_GRANTS];
	unsigned long va = 0x200000UL;
	unsigned int reads;

	assert(append(&client_a, a, 0UL, 0x100000UL, 512U).status == 0UL);
	assert(append(&client_a, a, 512UL * PAGE, 0x300000UL, 1U).status == 0UL);
	assert(append(&client_a, other, 0UL, 0x400000UL, 1U).status == 0UL);
	reads = source_reads;
	/* Registration does not grant a service permission to map a BO. */
	gpu_private_service_map(&ops, &proxy, &client_a, ca, a,
		0UL, va, 1U, 3UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_map_authorize(&client_b, ca, a, 0UL, va, 1U, 3UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_map_authorize(&client_a, ca, other, 0UL, va, 1U, 3UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT); /* permission expansion */
	gpu_private_map_authorize(&client_a, ca, a, 1UL, va, 1U, 3UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_map_authorize(&client_a, ca, a, PAGE, va, 513U, 3UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_map_authorize(&client_a, ca, a, 0UL, (1UL << 48U) - PAGE,
		2U, 3UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	grant = authorize(&client_a, ca, a, 0UL, va, 513U, 3UL | GPU_PRIVATE_CACHE);
	gpu_private_bo_destroy(&client_a, a, &result);
	assert(result.status == GPU_PRIVATE_STATE); /* pending grant pins backing */
	gpu_private_context_destroy(&ops, &client_a, ca, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_private_service_map(&ops, &proxy, &client_a, ca2, grant,
		0UL, va, 1U, 3UL | GPU_PRIVATE_CACHE, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_service_map(&ops, &proxy, &client_a, ca, grant,
		PAGE, va, 1U, 3UL | GPU_PRIVATE_CACHE, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_service_map(&ops, &proxy, &client_a, ca, grant,
		0UL, va + PAGE, 1U, 3UL | GPU_PRIVATE_CACHE, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_service_map(&ops, &proxy, &client_a, ca, grant,
		0UL, va, 1U, 3UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT); /* cache policy also bound */
	gpu_private_service_map(&ops, &proxy, &client_a, ca, grant,
		0UL, va, 1U, GPU_PRIVATE_READ | GPU_PRIVATE_CACHE, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_service_map(&ops, &proxy, &client_a, ca, grant,
		0UL, va, 513U, 3UL | GPU_PRIVATE_CACHE, &result);
	assert(result.status == GPU_PRIVATE_INPUT); /* per-call bound */
	gpu_private_service_map(&ops, &proxy, &client_a, ca, grant,
		0UL, va, 512U, 3UL | GPU_PRIVATE_CACHE, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == 512UL * PAGE);
	gpu_private_service_map(&ops, &proxy, &client_a, ca, grant,
		0UL, va, 1U, 3UL | GPU_PRIVATE_CACHE, &result);
	assert(result.status == GPU_PRIVATE_INPUT); /* consumed prefix cannot replay */
	gpu_private_service_map(&ops, &proxy, &client_a, ca, grant,
		512UL * PAGE, va + 512UL * PAGE, 2U, 3UL | GPU_PRIVATE_CACHE, &result);
	assert(result.status == GPU_PRIVATE_INPUT); /* remaining-range bound */
	gpu_private_service_map(&ops, &proxy, &client_a, ca, grant,
		512UL * PAGE, va + 512UL * PAGE, 1U, 3UL | GPU_PRIVATE_CACHE, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == PAGE);
	gpu_private_service_unmap(&ops, &proxy, &client_a, ca, va, 512U, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	gpu_private_service_unmap(&ops, &proxy, &client_a, ca, va + 512UL * PAGE, 1U, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	/* Even after unmapping, the terminal grant cannot create the mapping again. */
	gpu_private_service_map(&ops, &proxy, &client_a, ca, grant,
		0UL, va, 1U, 3UL | GPU_PRIVATE_CACHE, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	assert(source_reads == reads); /* no data read or caller-supplied PA */

	grant = authorize(&client_a, ca, a, 0UL, va, 1U, 3UL);
	gpu_private_map_cancel(&client_b, grant, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_service_map_release(&stranger, &client_a, ca, grant, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_service_map_release(&proxy, &client_a, ca2, grant, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_service_map_release(&proxy, &client_b, ca, grant, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_service_map_release(&proxy, &client_a, ca, grant, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	stale = grant;
	grant = authorize(&client_a, ca, a, 0UL, va, 1U, 3UL);
	assert(grant != stale);
	gpu_private_map_cancel(&client_a, stale, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_map_cancel(&client_a, grant, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);

	/* Pending authorizations are bounded and capacity is reusable. */
	for (unsigned int i = 0U; i < GPU_PRIVATE_CONTEXT_GRANTS; i++)
		grants[i] = authorize(&client_a, ca, a, 0UL, va, 1U, 3UL);
	gpu_private_map_authorize(&client_a, ca, a, 0UL, va, 1U, 3UL, &result);
	assert(result.status == GPU_PRIVATE_FULL);
	for (unsigned int i = 0U; i < GPU_PRIVATE_CONTEXT_GRANTS; i++) {
		gpu_private_map_cancel(&client_a, grants[i], &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
	}
	grant = authorize(&client_a, ca, a, 0UL, va, 2U, 3UL);
	gpu_private_service_map(&ops, &proxy, &client_a, ca, grant,
		0UL, va, 1U, 3UL, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	gpu_private_map_cancel(&client_a, grant, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	gpu_private_bo_destroy(&client_a, a, &result);
	assert(result.status == GPU_PRIVATE_STATE); /* cancellation retains mapped prefix */
	gpu_private_service_unmap(&ops, &proxy, &client_a, ca, va, 1U, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	/* Successful device release retires even unused/pending grants. */
	grant = authorize(&client_a, ca, a, 0UL, va, 1U, 3UL);
	gpu_private_device_revoked(&ops);
	gpu_private_map_cancel(&client_a, grant, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_map_authorize(&client_a, ca, a, 0UL, va, 1U, 3UL, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	destroy_object(&client_a, a);
	destroy_object(&client_a, other);
	destroy_context(&client_a, ca);
	destroy_context(&client_a, ca2);
	assert(!gpu_private_owner_busy(&proxy));
	puts("GPU_PRIVATE_MAP_AUTH=PASS exact tuple, permissions/cache, 513-page batches, replay, cancel/release, pending refs, quota, partial cancel and device revocation");
	return 0;
}

static int device_revocation(void)
{
	struct gpu_private_result result;
	unsigned long a = object(&client_a, 2U, 3UL);
	unsigned long b = object(&client_b, 1U, 3UL);
	unsigned long ca = context(&client_a), ca2 = context(&client_a);
	unsigned long cb = context(&client_b), inactive = context(&client_b);
	unsigned long root_a, root_b, replacement;

	assert(append(&client_a, a, 0UL, 0x100000UL, 2U).status == 0UL);
	assert(append(&client_b, b, 0UL, 0x100000UL, 1U).status == 0UL);
	assert(map(&client_a, ca, a, 0UL, 0x1000UL, 2U, 3UL).status == 0UL);
	assert(map(&client_a, ca2, a, PAGE, 0x4000UL, 1U, 3UL).status == 0UL);
	assert(map(&client_b, cb, b, 0UL, 0x1000UL, 1U, 3UL).status == 0UL);
	sync_success = true;
	gpu_private_context_activate(&ops, &proxy, ca, 1UL, &result);
	assert(result.status == 0UL);
	root_a = backend_root;
	gpu_private_context_activate(&ops, &proxy, ca2, 2UL, &result);
	assert(result.status == 0UL);
	sync_success = false;
	gpu_private_context_activate(&ops, &proxy, cb, 3UL, &result);
	assert(result.status == GPU_PRIVATE_STATE); /* uncertain hardware state */
	root_b = backend_root;
	gpu_private_bo_inspect(&proxy, &client_a, a, &result);
	assert(result.status == 0UL && result.value[3] == 3UL);
	gpu_private_context_destroy(&ops, &client_b, cb, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_private_bo_destroy(&client_a, a, &result);
	assert(result.status == GPU_PRIVATE_STATE);

	/* Only the trusted whole-device release adapter may call this entry.
	 * All aliases of a BO lose their GPU refs, including quarantined slots.
	 */
	gpu_private_device_revoked(&ops);
	gpu_private_device_revoked(&ops); /* idempotent RELEASE */
	gpu_private_bo_inspect(&proxy, &client_a, a, &result);
	assert(result.status == 0UL && result.value[3] == 0UL);
	gpu_private_bo_inspect(&proxy, &client_b, b, &result);
	assert(result.status == 0UL && result.value[3] == 0UL);
	gpu_private_query(&client_a, ca, 0UL, &result);
	assert(result.status == 0UL && result.value[0] == 0UL && result.value[1] == 0UL);
	assert(result.value[2] == 0UL && result.value[3] == 1UL);
	gpu_private_query(&client_b, cb, 0UL, &result);
	assert(result.status == 0UL && result.value[1] == 0UL && result.value[3] == 1UL);
	gpu_private_query(&client_b, inactive, 0UL, &result);
	assert(result.status == 0UL && result.value[3] == 1UL);
	/* The actual old roots were erased, not merely hidden by metadata. */
	for (size_t i = 0U; i < PAGE; i++) {
		assert(table_base[root_a - TABLE_PA + i] == 0U);
		assert(table_base[root_b - TABLE_PA + i] == 0U);
	}
	assert(map(&client_a, ca, a, 0UL, 0x1000UL, 1U, 3UL).status == GPU_PRIVATE_STATE);
	sync_success = true;
	gpu_private_context_activate(&ops, &proxy, ca, 1UL, &result);
	assert(result.status == GPU_PRIVATE_STATE); /* permanent, no resurrection */
	gpu_private_unmap(&ops, &client_a, ca, 0x1000UL, 2U, &result);
	assert(result.status == 0UL); /* native teardown remains idempotent */
	assert(gpu_private_range_busy(&client_a, 0x100000UL, PAGE));
	/* CPU backing is retained until the owner requests BO destruction. */
	destroy_object(&client_a, a);
	destroy_object(&client_b, b);
	destroy_context(&client_a, ca);
	destroy_context(&client_a, ca2);
	destroy_context(&client_b, cb);
	destroy_context(&client_b, inactive);
	assert(!gpu_private_owner_busy(&proxy));
	/* A fresh context can use a released slot; the old handle cannot. */
	replacement = context(&client_a);
	gpu_private_context_activate(&ops, &proxy, replacement, 1UL, &result);
	assert(result.status == 0UL);
	gpu_private_context_activate(&ops, &proxy, ca, 1UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_device_revoked(&ops);
	destroy_context(&client_a, replacement);
	assert(!gpu_private_owner_busy(&proxy));
	puts("GPU_PRIVATE_REVOKE=PASS active/quarantined/inactive roots erased, all mapping refs retired, old contexts cannot restart, owner retains CPU backing, slot reuse");
	return 0;
}

static int mapping_check_test(void)
{
    struct gpu_private_result r;
    unsigned long ca = context(&client_a), cb = context(&client_b);
    unsigned long a = object(&client_a, 513U, 7UL), b = object(&client_b, 1U, 3UL);
    unsigned long epoch, va = 0x1ff000UL;
    unsigned int reads, writes;

    assert(append(&client_a, a, 0UL, 0x100000UL, 512U).status == 0UL);
    assert(append(&client_a, a, 512UL * PAGE, 0x300000UL, 1U).status == 0UL);
    assert(append(&client_b, b, 0UL, 0x500000UL, 1U).status == 0UL);
    assert(map(&client_a, ca, a, 0UL, va, 512U, 11UL).status == 0UL);
    assert(map(&client_a, ca, a, 512UL * PAGE, va + 512UL * PAGE, 1U, 11UL).status == 0UL);
    reads = source_reads; writes = cleans;
    gpu_private_mapping_check(&ops, &client_a, ca, a, 0UL, va, 512U, 11UL, &r);
    assert(r.status == 0UL && r.value[0] == 512UL * PAGE && r.value[2] == 0UL && r.value[3] == 0UL);
    epoch = r.value[1];
    gpu_private_mapping_check(&ops, &client_a, ca, a, 512UL * PAGE, va + 512UL * PAGE, 1U, 11UL, &r);
    assert(r.status == 0UL && r.value[1] == epoch);
    assert(source_reads == reads && cleans == writes); /* Read-only metadata, no Client data access. */
    gpu_private_mapping_check(&ops, &proxy, ca, a, 0UL, va, 1U, 11UL, &r);
    assert(r.status != 0UL);
    gpu_private_mapping_check(&ops, &client_b, ca, a, 0UL, va, 1U, 11UL, &r);
    assert(r.status != 0UL);
    gpu_private_mapping_check(&ops, &client_a, cb, a, 0UL, va, 1U, 11UL, &r);
    assert(r.status != 0UL);
    gpu_private_mapping_check(&ops, &client_a, ca, b, 0UL, va, 1U, 11UL, &r);
    assert(r.status != 0UL);
    for (unsigned long prot = 1UL; prot < 16UL; prot++) {
        if (prot == 11UL) continue;
        gpu_private_mapping_check(&ops, &client_a, ca, a, 0UL, va, 1U, prot, &r);
        assert(r.status != 0UL); /* Exact access and cache mode, including stronger/weaker permissions. */
    }
    gpu_private_mapping_check(&ops, &client_a, ca, a, PAGE, va, 1U, 11UL, &r);
    assert(r.status != 0UL);
    gpu_private_mapping_check(&ops, &client_a, ca, 0UL, 0UL, va, 1U, 0UL, &r);
    assert(r.status != 0UL);
    gpu_private_mapping_check(&ops, &client_a, ca, a, 0UL, va, 513U, 11UL, &r);
    assert(r.status == GPU_PRIVATE_INPUT);
    gpu_private_mapping_check(&ops, &client_a, ca, 0UL, 0UL, 0x100000000UL, 1U, 0UL, &r);
    assert(r.status == 0UL && r.value[1] == epoch); /* Missing non-leaf is an empty range. */
    gpu_private_unmap(&ops, &client_a, ca, va, 1U, &r);
    assert(r.status == 0UL);
    gpu_private_mapping_check(&ops, &client_a, ca, 0UL, 0UL, va, 1U, 0UL, &r);
    assert(r.status == 0UL && r.value[1] != epoch);
    assert(map(&client_a, ca, a, 0UL, va, 1U, 11UL).status == 0UL);
    gpu_private_mapping_check(&ops, &client_a, ca, a, 0UL, va, 1U, 11UL, &r);
    assert(r.status == 0UL && r.value[1] > epoch); /* ABA remap is visible across verification batches. */
    sync_success = true;
    gpu_private_context_activate(&ops, &proxy, ca, 1UL, &r);
    assert(r.status == 0UL);
    uint64_t *root = (uint64_t *)(uintptr_t)(table_base + backend_root - TABLE_PA);
    uint64_t saved = root[0];
    root[0] = 1UL; /* A malformed non-leaf must never prove UNMAP. */
    gpu_private_mapping_check(&ops, &client_a, ca, 0UL, 0UL, va, 1U, 0UL, &r);
    assert(r.status == GPU_PRIVATE_STATE);
    root[0] = saved;
    gpu_private_device_revoked(&ops);
    gpu_private_mapping_check(&ops, &client_a, ca, 0UL, 0UL, va, 1U, 0UL, &r);
    assert(r.status == GPU_PRIVATE_STATE);
    destroy_context(&client_a, ca); destroy_context(&client_b, cb);
    destroy_object(&client_a, a); destroy_object(&client_b, b);
    puts("GPU_MAPPING_CHECK=PASS exact PTE/backing/object/access/cache, two Clients, 513-page snapshot epoch, ABA mutation, missing versus corrupt tables, revoked rejection; metadata-only MODEL");
    return 0;
}

int main(int argc, char **argv)
{
	if (argc == 2 && strcmp(argv[1], "--mapping-check") == 0)
		return mapping_check_test();
	struct gpu_private_result result;
	struct gpu_private_ops unavailable = ops;
	unsigned long a, b, ca, cb, stale, pages[2], root;
	unsigned int reads;
	uint64_t pte;

	if (argc == 2 && strcmp(argv[1], "--table-exhaustion") == 0)
		return table_exhaustion();
	if (argc == 2 && strcmp(argv[1], "--root-boundary") == 0)
		return root_boundary();
	if (argc == 2 && strcmp(argv[1], "--service-mapping") == 0)
		return service_mapping();
	if (argc == 2 && strcmp(argv[1], "--device-revocation") == 0)
		return device_revocation();
	if (argc == 2 && strcmp(argv[1], "--mapping-authorization") == 0)
		return mapping_authorization();
	assert(argc == 1);

	/* Invalid identities, widths and unsupported permissions fail closed. */
	gpu_private_bo_create(NULL, &proxy, PAGE, 3UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_bo_create(&proxy, &proxy, PAGE, 3UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_bo_create(&client_a, &proxy, ULONG_MAX, 3UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_bo_create(&client_a, &proxy, PAGE, GPU_PRIVATE_WRITE, &result);
	assert(result.status == GPU_PRIVATE_INPUT);

	a = object(&client_a, 513U, 3UL);
	b = object(&client_b, 1U, GPU_PRIVATE_READ);
	ca = context(&client_a);
	cb = context(&client_b);
	reads = source_reads;
	assert(append(&proxy, a, 0UL, 0x100000UL, 1U).status == GPU_PRIVATE_INPUT);
	assert(source_reads == reads);
	assert(append(&client_b, a, 0UL, 0x100000UL, 1U).status == GPU_PRIVATE_INPUT);
	assert(map(&client_a, ca, a, 0UL, 0x1000UL, 1U, 3UL).status != 0UL);

	/* A failed translation/duplicate must not publish a partial backing. */
	fail_ipa = 0x101000UL;
	assert(append(&client_a, a, 0UL, 0x100000UL, 2U).status != 0UL);
	assert(!gpu_private_range_busy(&client_a, 0x100000UL, PAGE));
	fail_ipa = ULONG_MAX;
	pages[0] = 0x100000UL;
	pages[1] = pages[0];
	gpu_private_bo_append(&ops, &client_a, a, 0UL, pages, 2U, &result);
	assert(result.status != 0UL);
	assert(!gpu_private_range_busy(&client_a, pages[0], PAGE));
	pages[1] = 1UL << 44U;
	gpu_private_bo_append(&ops, &client_a, a, 0UL, pages, 2U, &result);
	assert(result.status != 0UL);
	assert(append(&client_a, a, 0UL, 0x100000UL, 257U).status == 0UL);
	assert(append(&client_a, a, 257UL * PAGE, 0x201000UL, 256U).status == 0UL);
	assert(append(&client_a, a, 0UL, 0x100000UL, 1U).status != 0UL);
	assert(append(&client_b, b, 0UL, 0x100000UL, 1U).status == 0UL);
	assert(gpu_private_range_busy(&client_a, 0x100000UL, PAGE));
	assert(gpu_private_range_busy(&client_a, 0x100001UL, 1UL));
	assert(gpu_private_range_busy(&client_a, 0UL, ULONG_MAX));
	assert(!gpu_private_range_busy(&proxy, 0UL, ULONG_MAX));
	assert(!gpu_private_range_busy(&client_a, 0x301000UL, PAGE));
	assert(gpu_private_owner_busy(&proxy));

	/* Cross-Client/context/service substitution and permission expansion. */
	assert(map(&client_b, cb, a, 0UL, 0UL, 1U, 3UL).status != 0UL);
	assert(map(&client_a, cb, a, 0UL, 0UL, 1U, 3UL).status != 0UL);
	assert(map(&proxy, ca, a, 0UL, 0UL, 1U, 3UL).status != 0UL);
	assert(map(&client_b, cb, b, 0UL, 0UL, 1U, 3UL).status != 0UL);
	assert(map(&client_a, ca, a, 0UL, 0UL, 1U, 7UL).status != 0UL);
	assert(map(&client_a, ca, a, ULONG_MAX, 0UL, 1U, 3UL).status != 0UL);
	assert(map(&client_a, ca, a, 0UL, 1UL << 48U, 1U, 3UL).status != 0UL);
	assert(map(&client_a, ca, a, 0UL, 0UL, GPU_PRIVATE_BATCH + 1U, 3UL).status != 0UL);
	assert(map(&client_a, ca, a, 0UL, GPU_PRIVATE_CONTROL_GPU_VA, 1U, 3UL).status == GPU_PRIVATE_INPUT);
	gpu_private_map_authorize(&client_a, ca, a, 0UL, GPU_PRIVATE_CONTROL_GPU_VA,
		1U, 3UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	assert(map(&client_a, ca, a, 0UL, GPU_PRIVATE_CONTROL_GPU_VA - PAGE, 1U, 3UL).status == 0UL);
	gpu_private_unmap(&ops, &client_a, ca, GPU_PRIVATE_CONTROL_GPU_VA - PAGE, 2U, &result);
	assert(result.status == GPU_PRIVATE_INPUT); /* No partial public prefix unmap. */
	gpu_private_query(&client_a, ca, 0UL, &result);
	assert(result.value[0] == 1UL);
	gpu_private_unmap(&ops, &client_a, ca, GPU_PRIVATE_CONTROL_GPU_VA - PAGE, 1U, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	assert(map(&client_a, ca, a, 0UL, 0x1ff000UL, 2U, 3UL).status == 0UL);
	assert(map(&client_a, ca, a, 0UL, 0x1fe000UL, 2U, 3UL).status != 0UL);
	gpu_private_query(&client_a, ca, 0UL, &result);
	assert(result.status == 0UL && result.value[0] == 2UL);
	gpu_private_query(&proxy, ca, 0UL, &result);
	assert(result.status != 0UL);
	gpu_private_bo_destroy(&client_a, a, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_private_unmap(&ops, &proxy, ca, 0x1ff000UL, 2U, &result);
	assert(result.status != 0UL);
	gpu_private_unmap(&ops, &client_a, ca, 0x1ff000UL, 2U, &result);
	assert(result.status == 0UL);
	destroy_context(&client_a, ca);
	stale = a;
	destroy_object(&client_a, a);
	assert(!gpu_private_range_busy(&client_a, 0UL, ULONG_MAX));
	a = object(&client_a, 1U, 3UL);
	assert(a != stale);
	assert(append(&client_a, stale, 0UL, 0x100000UL, 1U).status != 0UL);
	destroy_object(&client_a, a);

	/* Context activation requires its actual service and trusted backend.
	 * A failed backend does not accidentally make the root executable.
	 */
	assert(map(&client_b, cb, b, 0UL, 0x1000UL, 1U, GPU_PRIVATE_READ).status == 0UL);
	gpu_private_context_activate(&ops, &stranger, cb, 0UL, &result);
	assert(result.status != 0UL);
	gpu_private_context_activate(&ops, &client_b, cb, 0UL, &result);
	assert(result.status != 0UL);
	gpu_private_context_activate(&ops, &proxy, cb, GPU_PRIVATE_AS_SLOTS, &result);
	assert(result.status != 0UL);
	unavailable.activate = NULL;
	gpu_private_context_activate(&unavailable, &proxy, cb, 0UL, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_private_query(&client_b, cb, 0UL, &result);
	assert(result.value[2] == 0UL);
	sync_success = true;
	gpu_private_context_activate(&ops, &proxy, cb, 0UL, &result);
	assert(result.status == 0UL && result.value[0] == cb && result.value[1] == 0UL);
	assert(result.value[2] == 0UL && result.value[3] == 0UL);
	root = backend_root; /* Visible only to this trusted backend, not RSI. */
	assert(result.value[0] != root);
	pte = pte_at(root, 0x1000UL);
	assert((pte & PTE_PA) == 0x80100000UL);
	assert((pte & (1UL << 7U)) != 0UL); /* read-only */
	assert((pte & (3UL << 53U)) == (3UL << 53U)); /* no execute */
	gpu_private_unmap(&ops, &client_b, cb, 0x1000UL, 1U, &result);
	assert(result.status == GPU_PRIVATE_STATE); /* not proof of quiescence */
	gpu_private_bo_destroy(&client_b, b, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_private_context_destroy(&ops, &client_b, cb, &result);
	assert(result.status == GPU_PRIVATE_STATE);

	/* Failed invalidation keeps newly published pages pinned/quarantined. */
	a = object(&client_b, 1U, 3UL);
	assert(append(&client_b, a, 0UL, 0x200000UL, 1U).status == 0UL);
	sync_success = false;
	assert(map(&client_b, cb, a, 0UL, 0x2000UL, 1U, 3UL).status == GPU_PRIVATE_STATE);
	gpu_private_query(&client_b, cb, 0UL, &result);
	assert(result.status == 0UL && result.value[0] == 2UL && result.value[1] == 1UL);
	gpu_private_bo_destroy(&client_b, a, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	assert(gpu_private_range_busy(&client_b, 0x200000UL, PAGE));
	ca = context(&client_a);
	gpu_private_context_activate(&ops, &proxy, ca, 0UL, &result);
	assert(result.status == GPU_PRIVATE_STATE); /* occupied by another Client */
	gpu_private_query(&client_a, ca, 0UL, &result);
	assert(result.value[1] == 0UL && result.value[2] == 0UL);
	gpu_private_context_activate(&ops, &proxy, ca, 1UL, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_private_query(&client_a, ca, 0UL, &result);
	assert(result.value[1] == 1UL && result.value[2] == 1UL);
	gpu_private_context_destroy(&ops, &client_a, ca, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	assert(source_reads != 0U && cleans != 0U && synchronizations >= 1U && activations == 2U);
	puts("GPU_PRIVATE_PT=PASS ownership, metadata-only translation, real PTEs, permissions, atomic batches, stale handles, opaque activation, slot ownership, quarantine");
	return 0;
}
