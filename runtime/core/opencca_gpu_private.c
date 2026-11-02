/* SPDX-License-Identifier: BSD-3-Clause */
#include <limits.h>
#include <assert.h>
#include <opencca_gpu_private.h>
#include <string.h>

#define ENTRIES 512U
#define BO_PREFIX 0xcca2000000000000UL
#define CTX_PREFIX 0xcca3000000000000UL
#define MAP_PREFIX 0xcca4000000000000UL
#define ADDRESS_MASK 0x0000fffffffff000UL
#define ADDRESS_LIMIT (1UL << 48U)
#define PAGE_MASK 4095UL
#define PTE_TABLE 3UL
#define PTE_AF (1UL << 10U)
#define PTE_NG (1UL << 11U)
#define PTE_USER (1UL << 6U)
#define PTE_RO (1UL << 7U)
#define PTE_XN (3UL << 53U)
#define NC_PENDING (1U << 31U)
#define NC_PREFIX (NC_PENDING - 1U)
/* Metadata inspection has no physical cache operations. Bound it separately
 * so NC/resident mappings do not consume a full RSI per 512 cheap checks.
 * Physical page maintenance keeps the original GPU_PRIVATE_BATCH limit.
 */
#define CACHE_SCAN_BATCH (32U * GPU_PRIVATE_BATCH)
/* Private lease summary: at most sixteen groups, including a partial last
 * group for non-default object counts. Only lease acquisition/reset updates
 * this index under the policy lock; no Client or service supplies its bits.
 */
#define CACHE_LEASE_GROUPS 16U
#define CACHE_LEASE_GROUP_SIZE ((GPU_PRIVATE_OBJECTS + CACHE_LEASE_GROUPS - 1U) / CACHE_LEASE_GROUPS)
_Static_assert(GPU_PRIVATE_OBJECTS > 0U, "private object table must not be empty");

struct backing_page {
	/* RK GPU PA policy is at most 40 bits. Page-number encoding retains
	 * 44-bit IPA/PA ranges without expanding the RMM reservation.
	 */
	uint32_t ipa_page;
	uint32_t pa_page;
};

struct private_bo {
	const void *owner;
	const void *service;
	unsigned long handle;
	unsigned long access;
	unsigned long min_ipa, max_ipa;
	unsigned int pages, registered, mapped, pending;
	unsigned short blocks[GPU_PRIVATE_BO_BLOCKS];
	bool closing;
	bool control;
	/* Irreversible CPU donation, distinct from service-owned control data. */
	bool resident;
	/* Mutually exclusive with resident/control; fits existing bool padding.
	 * hidden then holds the NC prefix, with NC_PENDING denoting exactly one
	 * CPU-hidden page at that index during a failed conversion/restoration.
	 */
	bool uncached;
	unsigned int hidden;
	unsigned int control_gpu_refs;
	unsigned long cache_context;
};

struct private_context {
	const void *owner;
	const void *service;
	unsigned long handle;
	unsigned long mapping_epoch;
	unsigned int root;
	unsigned int mapped;
	unsigned int pending;
	unsigned int group_refs;
	unsigned int task_refs;
	unsigned long cache_task;
	unsigned int cache_cursor, cache_pages;
	unsigned int return_cursor, return_pages;
	unsigned long extension_object, extension_va;
	unsigned int extension_cursor;
	bool live_prepared;
	bool quiesced;
	bool activated;
	bool drained;
	unsigned int slot;
	bool quarantined;
	bool revoked;
	/* Fits the existing tail padding on AArch64. */
	uint16_t cache_groups;
};

static struct private_bo objects[GPU_PRIVATE_OBJECTS];
static struct private_context contexts[GPU_PRIVATE_CONTEXTS];
/* Validated mapping set, not a completion/cache-coherence proof. Generation
 * prevents reuse when a context slot is recycled; the nonwrapping epoch
 * invalidates before every leaf edit, including control/heap mappings and
 * partial failed mutations. Only a complete successful device scan publishes
 * a set. Mapped BO refs prevent an object slot from being recycled underneath
 * an unchanged set. WB mappings always retain physical per-page maintenance.
 */
#define CACHE_SET_WORDS ((GPU_PRIVATE_OBJECTS + 63U) / 64U)
struct private_cache_set {
	unsigned long context, epoch;
	unsigned long live_epoch;
	uint64_t objects[CACHE_SET_WORDS];
	bool eligible, valid, live_uncached;
};
/* Bounded associative cache: eviction loses only an optimization. Keep the
 * existing RMM reservation and BO/PT capacities unchanged. A partially built
 * evicted set cannot become valid on continuation: eligible remains false
 * until a new device scan starts at cursor zero.
 */
#define CACHE_SET_SLOTS 4U
static struct private_cache_set cache_sets[CACHE_SET_SLOTS];
static unsigned int cache_set_victim;
/* All BO predicates below belong to RMM-private metadata under the policy
 * lock. Every mutator invalidates before it can touch them or call out. A
 * rejected mutation may discard an optimization, never an authorization.
 * Zero permanently disables reuse after unsigned wrap; old proofs cannot
 * become valid again. This is not a device/root/completion certificate.
 */
static unsigned long cache_metadata_epoch = 1UL;

static void cache_metadata_invalidate(void)
{
	if (cache_metadata_epoch != 0UL)
		cache_metadata_epoch++;
}

static struct private_cache_set *cache_set_for(unsigned long context)
{
	unsigned int available = CACHE_SET_SLOTS;

	for (unsigned int i = 0U; i < CACHE_SET_SLOTS; i++) {
		if (cache_sets[i].context == context)
			return &cache_sets[i];
		if (cache_sets[i].context == 0UL)
			available = i;
	}
	if (available == CACHE_SET_SLOTS)
		available = cache_set_victim++ % CACHE_SET_SLOTS;
	memset(&cache_sets[available], 0, sizeof(cache_sets[available]));
	cache_sets[available].context = context;
	return &cache_sets[available];
}
static struct backing_page backing[GPU_PRIVATE_BLOCKS][ENTRIES];
static unsigned long backing_owner[GPU_PRIVATE_BLOCKS];
static uint64_t tables[GPU_PRIVATE_TABLES][ENTRIES]
	__attribute__((aligned(4096)));
/* A leaf's object tag is RMM-private and never inferred from an untrusted PTE. */
static unsigned short leaf_object[GPU_PRIVATE_TABLES][ENTRIES]
	__attribute__((aligned(8)));
/* One trusted bit per 32 entries. Only mapping mutation under the common
 * policy lock updates this summary; neither PTEs nor Client hints supply it.
 * Skip empty groups, but inspect every tagged leaf and its actual PTE below.
 */
static uint16_t leaf_groups[GPU_PRIVATE_TABLES];
static unsigned long table_owner[GPU_PRIVATE_TABLES];
static unsigned long slot_owner[GPU_PRIVATE_AS_SLOTS];
static unsigned long next_id;

static void cache_lease_acquire(struct private_context *ctx, struct private_bo *bo)
{
	unsigned int index = (unsigned int)(bo - objects);

	assert(index < GPU_PRIVATE_OBJECTS);
	ctx->cache_groups |= (uint16_t)(1U << (index / CACHE_LEASE_GROUP_SIZE));
	if (bo->cache_context != ctx->handle)
		cache_metadata_invalidate();
	bo->cache_context = ctx->handle;
}

struct private_map_grant {
	const void *owner;
	unsigned long handle, context, object, offset, iova, prot;
	size_t count, progress;
};
static struct private_map_grant map_grants[GPU_PRIVATE_MAP_GRANTS];

/* A contiguous <=512-page batch can cross at most two entries at each
 * non-leaf level. Keep new table allocations private to this preflight.
 */
struct table_transaction {
	unsigned int count;
	unsigned short parent[6], entry[6], child[6];
};

_Static_assert(GPU_PRIVATE_OBJECTS < USHRT_MAX, "object tags must fit");
_Static_assert(sizeof(unsigned short) == 2U, "four tags must occupy one word");
_Static_assert(GPU_PRIVATE_BLOCKS < USHRT_MAX, "backing indices must fit");
_Static_assert(sizeof(tables[0]) == GPU_PRIVATE_PAGE_SIZE, "hardware PT size");
_Static_assert(GPU_PRIVATE_BO_BLOCKS * ENTRIES < NC_PENDING, "NC prefix encoding");

static void result_init(struct gpu_private_result *result)
{
	memset(result, 0, sizeof(*result));
	result->status = GPU_PRIVATE_INPUT;
}

static unsigned long new_handle(unsigned long prefix, unsigned int slot)
{
	/* Exhaustion fails closed; stale handles cannot become valid again. */
	if (next_id == UINT32_MAX)
		return 0UL;
	return prefix | (++next_id << 16U) | (slot + 1U);
}

static struct private_bo *bo_lookup(const void *owner, unsigned long handle)
{
	unsigned long slot = handle & 0xffffUL;
	struct private_bo *bo;

	if (owner == NULL || slot == 0UL || slot > GPU_PRIVATE_OBJECTS)
		return NULL;
	bo = &objects[slot - 1UL];
	return bo->handle == handle && bo->owner == owner ? bo : NULL;
}

static struct private_context *ctx_lookup(const void *owner, unsigned long handle)
{
	unsigned long slot = handle & 0xffffUL;
	struct private_context *ctx;

	if (owner == NULL || slot == 0UL || slot > GPU_PRIVATE_CONTEXTS)
		return NULL;
	ctx = &contexts[slot - 1UL];
	return ctx->handle == handle && ctx->owner == owner ? ctx : NULL;
}

static struct private_map_grant *grant_lookup(const void *owner, unsigned long handle)
{
	unsigned long slot = handle & 0xffffUL;
	struct private_map_grant *grant;

	if (owner == NULL || slot == 0UL || slot > GPU_PRIVATE_MAP_GRANTS)
		return NULL;
	grant = &map_grants[slot - 1UL];
	return grant->handle == handle && grant->owner == owner ? grant : NULL;
}

static void grant_forget(struct private_map_grant *grant)
{
	struct private_bo *bo = bo_lookup(grant->owner, grant->object);
	struct private_context *ctx = ctx_lookup(grant->owner, grant->context);

	assert(bo != NULL && ctx != NULL && bo->pending != 0U && ctx->pending != 0U);
	bo->pending--;
	ctx->pending--;
	memset(grant, 0, sizeof(*grant));
}

static bool range_valid(unsigned long base, size_t count)
{
	return count != 0U && count <= GPU_PRIVATE_BATCH &&
	       (base & PAGE_MASK) == 0UL && base < ADDRESS_LIMIT &&
	       count <= (ADDRESS_LIMIT - base) / GPU_PRIVATE_PAGE_SIZE;
}

static struct backing_page *bo_page(struct private_bo *bo, unsigned int index)
{
	unsigned int block = bo->blocks[index / ENTRIES];

	return block == 0U ? NULL : &backing[block - 1U][index % ENTRIES];
}

static void bo_create(const void *owner, const void *service,
		unsigned long size, unsigned long access, bool control,
		struct gpu_private_result *result)
{
	result_init(result);
	if (owner == NULL || service == NULL || (owner == service) != control ||
	    size == 0UL || (size & PAGE_MASK) != 0UL ||
	    size / GPU_PRIVATE_PAGE_SIZE > GPU_PRIVATE_BO_BLOCKS * ENTRIES ||
	    (access & GPU_PRIVATE_READ) == 0UL ||
	    (access & ~GPU_PRIVATE_ACCESS) != 0UL)
		return;
	result->status = GPU_PRIVATE_FULL;
	if (control) {
		unsigned int count = 0U, pages = 0U;

		for (unsigned int i = 0U; i < GPU_PRIVATE_OBJECTS; i++) {
			if (objects[i].handle != 0UL && objects[i].control) {
				count++;
				pages += objects[i].pages;
			}
		}
		if (count >= GPU_PRIVATE_CONTROL_OBJECTS || pages > GPU_PRIVATE_CONTROL_PAGES ||
		    size / GPU_PRIVATE_PAGE_SIZE > GPU_PRIVATE_CONTROL_PAGES - pages)
			return;
	}
	for (unsigned int i = 0U; i < GPU_PRIVATE_OBJECTS; i++) {
		struct private_bo *bo = &objects[i];
		unsigned long handle;

		if (bo->handle != 0UL)
			continue;
		handle = new_handle(BO_PREFIX, i);
		if (handle == 0UL)
			return;
		{
			cache_metadata_invalidate();
			memset(bo, 0, sizeof(*bo));
		}
		{
			cache_metadata_invalidate();
			bo->owner = owner;
		}
		{
			cache_metadata_invalidate();
			bo->service = service;
		}
		{
			cache_metadata_invalidate();
			bo->handle = handle;
		}
		bo->access = access;
		{
			cache_metadata_invalidate();
			bo->control = control;
		}
		{
			cache_metadata_invalidate();
			bo->pages = (unsigned int)(size / GPU_PRIVATE_PAGE_SIZE);
		}
		bo->min_ipa = ULONG_MAX;
		result->status = GPU_PRIVATE_SUCCESS;
		result->value[0] = handle;
		return;
	}
}

void gpu_private_bo_create(const void *owner, const void *service,
		unsigned long size, unsigned long access, struct gpu_private_result *result)
{
	bo_create(owner, service, size, access, false, result);
}

void gpu_private_control_create(const void *service, unsigned long size,
		struct gpu_private_result *result)
{
	bo_create(service, service, size, GPU_PRIVATE_READ | GPU_PRIVATE_WRITE, true, result);
}

static void bo_append(const struct gpu_private_ops *ops, const void *owner,
		unsigned long handle, unsigned long offset,
		const unsigned long *ipas, size_t count, bool control,
		struct gpu_private_result *result)
{
	struct private_bo *bo = bo_lookup(owner, handle);
	unsigned int first, last;

	result_init(result);
	if (ops == NULL || ops->source_page == NULL || bo == NULL ||
	    bo->control != control || ipas == NULL || bo->closing || bo->resident || bo->uncached || count == 0U ||
	    count > GPU_PRIVATE_BATCH || (offset & PAGE_MASK) != 0UL ||
	    offset / GPU_PRIVATE_PAGE_SIZE != bo->registered ||
	    count > bo->pages - bo->registered ||
	    (control && (ops->hide_page == NULL || ops->restore_page == NULL || ops->clear_page == NULL)))
		return;
	first = bo->registered / ENTRIES;
	last = (bo->registered + (unsigned int)count - 1U) / ENTRIES;
	for (unsigned int index = first; index <= last; index++) {
		if (bo->blocks[index] != 0U)
			continue;
		for (unsigned int block = 0U; block < GPU_PRIVATE_BLOCKS; block++) {
			if (backing_owner[block] == 0UL) {
				backing_owner[block] = handle;
				bo->blocks[index] = (unsigned short)(block + 1U);
				break;
			}
		}
		if (bo->blocks[index] == 0U) {
			/* Empty reserved blocks are harmless and released by DESTROY. */
			result->status = GPU_PRIVATE_FULL;
			return;
		}
	}
	/* Stage only metadata in reserved RMM backing slots. registered is the
	 * publication point, so a failed batch leaves no live partial grant.
	 */
	for (size_t i = 0U; i < count; i++) {
		struct backing_page *page = bo_page(bo, bo->registered + (unsigned int)i);
		unsigned long pa;

		if ((ipas[i] & PAGE_MASK) != 0UL || ipas[i] >= (1UL << 44U) ||
		    !ops->source_page(owner, ipas[i], &pa) ||
		    (pa & PAGE_MASK) != 0UL || pa >= (1UL << 44U) ||
		    (control && (pa == 0UL || pa >= (1UL << 40U))))
			return;
		for (size_t j = 0U; j < i; j++) {
			struct backing_page *previous = bo_page(bo, bo->registered + (unsigned int)j);

			if (previous->ipa_page == ipas[i] >> 12U ||
			    previous->pa_page == pa >> 12U)
				return;
		}
		page->ipa_page = (uint32_t)(ipas[i] >> 12U);
		page->pa_page = (uint32_t)(pa >> 12U);
	}
	for (size_t i = 0U; i < count; i++) {
		if (ipas[i] < bo->min_ipa)
			bo->min_ipa = ipas[i];
		if (ipas[i] > bo->max_ipa)
			bo->max_ipa = ipas[i];
	}
	bo->registered += (unsigned int)count;
	if (control) {
		/* Publish the whole lifetime record before any CPU leaf is removed.
		 * A failed hide/clear retains both the sealed prefix and the unsealed
		 * suffix. DESTROY must safely restore the prefix before freeing any
		 * corresponding backing; a failed append can never be retried in place.
		 */
		result->status = GPU_PRIVATE_STATE;
		while (bo->hidden < bo->registered) {
			struct backing_page *page = bo_page(bo, bo->hidden);
			unsigned long pa = (unsigned long)page->pa_page << 12U;

			if (!ops->hide_page(owner, (unsigned long)page->ipa_page << 12U, pa)) {
				{
					cache_metadata_invalidate();
					bo->closing = true;
				}
				return;
			}
			{
				cache_metadata_invalidate();
				bo->hidden++;
			}
			if (!ops->clear_page(pa)) {
				{
					cache_metadata_invalidate();
					bo->closing = true;
				}
				return;
			}
		}
	}
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = bo->registered;
}

void gpu_private_bo_append(const struct gpu_private_ops *ops, const void *owner,
		unsigned long handle, unsigned long offset, const unsigned long *ipas,
		size_t count, struct gpu_private_result *result)
{
	bo_append(ops, owner, handle, offset, ipas, count, false, result);
}

void gpu_private_control_append(const struct gpu_private_ops *ops, const void *service,
		unsigned long handle, unsigned long offset, const unsigned long *ipas,
		size_t count, struct gpu_private_result *result)
{
	bo_append(ops, service, handle, offset, ipas, count, true, result);
}

void gpu_private_bo_seal(const struct gpu_private_ops *ops, const void *owner,
		unsigned long handle, struct gpu_private_result *result)
{
	struct private_bo *bo = bo_lookup(owner, handle);
	unsigned int budget = GPU_PRIVATE_BATCH;

	result_init(result);
	if (bo == NULL || bo->control || bo->uncached || ops == NULL || ops->hide_page == NULL ||
	    ops->sync_page_for_device == NULL || (bo->access & GPU_PRIVATE_EXEC) != 0UL)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (bo->closing || bo->registered != bo->pages)
		return;
	/* Completed replays are read-only, including after GPU mapping. */
	if (bo->resident && bo->hidden == bo->pages)
		goto complete;
	if (bo->mapped != 0U || bo->pending != 0U || bo->cache_context != 0UL)
		return;
	{
		cache_metadata_invalidate();
		bo->resident = true;
	}
	while (bo->hidden < bo->pages && budget-- != 0U) {
		struct backing_page *page = bo_page(bo, bo->hidden);
		unsigned long pa = (unsigned long)page->pa_page << 12U;

		/* Hide completes the Realm-wide CPU TLBI before maintenance. A
		 * concurrent vCPU can no longer dirty this page after its handoff.
		 * Publish hidden BEFORE a possibly failing flush so destroy retains
		 * and restores exactly the hidden prefix, including this last page.
		 */
		if (!ops->hide_page(owner, (unsigned long)page->ipa_page << 12U, pa)) {
			{
				cache_metadata_invalidate();
				bo->closing = true;
			}
			return;
		}
		{
			cache_metadata_invalidate();
			bo->hidden++;
		}
		if (!ops->sync_page_for_device(pa)) {
			{
				cache_metadata_invalidate();
				bo->closing = true;
			}
			return;
		}
	}
complete:
	result->value[0] = bo->hidden;
	result->status = bo->hidden == bo->pages ? GPU_PRIVATE_SUCCESS : GPU_PRIVATE_INCOMPLETE;
}

void gpu_private_bo_uncached(const struct gpu_private_ops *ops, const void *owner,
		unsigned long handle, struct gpu_private_result *result)
{
	struct private_bo *bo = bo_lookup(owner, handle);
	unsigned int budget = GPU_PRIVATE_BATCH;

	result_init(result);
	if (bo == NULL || bo->control || bo->resident || ops == NULL ||
	    ops->hide_page == NULL || ops->restore_page_uncached == NULL ||
	    ops->sync_page_for_device == NULL || ops->cache_barrier == NULL)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (bo->closing || bo->registered != bo->pages)
		return;
	/* Read-only completed replay is safe even after mapping/launch. */
	if (bo->uncached && bo->hidden == bo->pages)
		goto complete;
	if (bo->mapped != 0U || bo->pending != 0U || bo->cache_context != 0UL)
		return;
	{
		cache_metadata_invalidate();
		bo->uncached = true;
	}
	while (bo->hidden < bo->pages && budget-- != 0U) {
		unsigned int index = bo->hidden;
		struct backing_page *page = bo_page(bo, index);
		unsigned long pa = (unsigned long)page->pa_page << 12U;
		unsigned long ipa = (unsigned long)page->ipa_page << 12U;

		if (!ops->hide_page(owner, ipa, pa))
			goto failed;
		/* Record the hidden page before any fallible cache operation. Flush
		 * after global TLBI, then restore with NC forced by actual Stage-2.
		 * RMM temporary WB aliases are unmapped before restoring CPU access.
		 */
		{
			cache_metadata_invalidate();
			bo->hidden = NC_PENDING | index;
		}
		if (!ops->sync_page_for_device(pa) ||
		    !ops->restore_page_uncached(owner, ipa, pa))
			goto failed;
		{
			cache_metadata_invalidate();
			bo->hidden = index + 1U;
		}
	}
complete:
	result->value[0] = bo->hidden;
	result->status = bo->hidden == bo->pages ? GPU_PRIVATE_SUCCESS : GPU_PRIVATE_INCOMPLETE;
	return;
failed:
	{
		cache_metadata_invalidate();
		bo->closing = true;
	}
}

static void bo_destroy(const struct gpu_private_ops *ops, const void *owner,
		unsigned long handle, bool control,
		struct gpu_private_result *result)
{
	struct private_bo *bo = bo_lookup(owner, handle);
	unsigned int budget = GPU_PRIVATE_BATCH;

	result_init(result);
	if (bo == NULL || bo->control != control ||
	    ((control || bo->resident || bo->uncached) &&
	     (ops == NULL || ops->restore_page == NULL || ops->clear_page == NULL)))
		return;
	if (bo->uncached && ops->hide_page == NULL)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (bo->mapped != 0U || bo->pending != 0U || bo->control_gpu_refs != 0U)
		return;
	{
		cache_metadata_invalidate();
		bo->closing = true;
	}
	while (bo->registered != 0U && budget-- != 0U) {
		struct backing_page *page = bo_page(bo, bo->registered - 1U);

		if (bo->uncached) {
			unsigned int prefix = bo->hidden & NC_PREFIX;
			bool pending = (bo->hidden & NC_PENDING) != 0U;
			unsigned long pa = (unsigned long)page->pa_page << 12U;
			unsigned long ipa = (unsigned long)page->ipa_page << 12U;

			/* Discard untouched WB tail first. A pending page belongs just
			 * above the completed NC prefix and must stay hidden on failure.
			 */
			if (bo->registered == prefix && !pending) {
				if (!ops->hide_page(owner, ipa, pa))
					return;
				{
					cache_metadata_invalidate();
					bo->hidden = NC_PENDING | (prefix - 1U);
				}
				pending = true;
				prefix--;
			}
			if (pending && bo->registered == prefix + 1U) {
				if (!ops->clear_page(pa) || !ops->restore_page(owner, ipa, pa))
					return;
				{
					cache_metadata_invalidate();
					bo->hidden = prefix;
				}
			}
		}
		if ((control || bo->resident) && bo->registered == bo->hidden) {
			unsigned long pa = (unsigned long)page->pa_page << 12U;

			/* No firmware hold remains. Scrub before making the original
			 * CPU mapping valid, including after a failed/partial donation.
			 */
			if (!ops->clear_page(pa) || !ops->restore_page(owner,
					(unsigned long)page->ipa_page << 12U, pa))
				return;
			{
				cache_metadata_invalidate();
				bo->hidden--;
			}
		}
		bo->registered--;

		memset(page, 0, sizeof(*page));
	}
	result->value[0] = bo->registered;
	if (bo->registered != 0U) {
		result->status = GPU_PRIVATE_INCOMPLETE;
		return;
	}
	for (unsigned int i = 0U; i < GPU_PRIVATE_BO_BLOCKS; i++) {
		if (bo->blocks[i] != 0U)
			backing_owner[bo->blocks[i] - 1U] = 0UL;
	}
	{
		cache_metadata_invalidate();
		memset(bo, 0, sizeof(*bo));
	}
	result->status = GPU_PRIVATE_SUCCESS;
}

void gpu_private_bo_destroy(const void *owner, unsigned long handle,
		struct gpu_private_result *result)
{
	bo_destroy(NULL, owner, handle, false, result);
}

void gpu_private_bo_release(const struct gpu_private_ops *ops, const void *owner,
		unsigned long handle, struct gpu_private_result *result)
{
	bo_destroy(ops, owner, handle, false, result);
}

void gpu_private_control_destroy(const struct gpu_private_ops *ops, const void *service,
		unsigned long handle, struct gpu_private_result *result)
{
	bo_destroy(ops, service, handle, true, result);
}

bool gpu_private_control_acquire(const struct gpu_private_ops *ops, const void *service,
		unsigned long handle, unsigned int *pages)
{
	struct private_bo *bo = bo_lookup(service, handle);

	if (ops == NULL || ops->clear_page == NULL || pages == NULL || bo == NULL ||
	    !bo->control || bo->closing || bo->registered != bo->pages ||
	    bo->hidden != bo->pages || bo->mapped != 0U || bo->control_gpu_refs != 0U)
		return false;
	/* The old arena may contain another Client's suspended state after
	 * reset. Every new firmware binding starts with zeroed private backing.
	 */
	for (unsigned int i = 0U; i < bo->pages; i++)
		if (!ops->clear_page((unsigned long)bo_page(bo, i)->pa_page << 12U))
			return false;
	{
		cache_metadata_invalidate();
		bo->mapped = 1U;
	}
	*pages = bo->pages;
	return true;
}

bool gpu_private_control_page(const void *service, unsigned long handle,
		unsigned int index, unsigned long *pa)
{
	struct private_bo *bo = bo_lookup(service, handle);

	if (bo == NULL || !bo->control || bo->mapped != 1U || pa == NULL ||
	    bo->hidden != bo->pages || index >= bo->pages)
		return false;
	*pa = (unsigned long)bo_page(bo, index)->pa_page << 12U;
	return true;
}

void gpu_private_control_release(const void *service, unsigned long handle)
{
	struct private_bo *bo = bo_lookup(service, handle);

	assert(bo != NULL && bo->control && bo->mapped == 1U && bo->control_gpu_refs == 0U);
	{
		cache_metadata_invalidate();
		bo->mapped = 0U;
	}
}

static unsigned int alloc_table(const struct gpu_private_ops *ops,
		unsigned long context)
{
	for (unsigned int i = 0U; i < GPU_PRIVATE_TABLES; i++) {
		unsigned long pa;

		if (table_owner[i] != 0UL)
			continue;
		pa = ops->table_pa(tables[i]);
		if ((pa & ~ADDRESS_MASK) != 0UL)
			return GPU_PRIVATE_TABLES;
		table_owner[i] = context;
		memset(tables[i], 0, sizeof(tables[i]));
		memset(leaf_object[i], 0, sizeof(leaf_object[i]));
		leaf_groups[i] = 0U;
		ops->clean(tables[i], sizeof(tables[i]));
		return i;
	}
	return GPU_PRIVATE_TABLES;
}

static unsigned int table_index(const struct gpu_private_ops *ops,
		unsigned long context, uint64_t descriptor)
{
	unsigned long pa = (unsigned long)descriptor & ADDRESS_MASK;
	unsigned long first = ops->table_pa(tables[0]);
	unsigned long index;

	if ((descriptor & 3UL) != PTE_TABLE || pa < first)
		return GPU_PRIVATE_TABLES;
	index = (pa - first) / GPU_PRIVATE_PAGE_SIZE;
	if (index >= GPU_PRIVATE_TABLES || table_owner[index] != context ||
	    ops->table_pa(tables[index]) != pa)
		return GPU_PRIVATE_TABLES;
	return (unsigned int)index;
}

static void forget_leaf(unsigned int table, unsigned int index)
{
	unsigned int first = index & ~31U;

	leaf_object[table][index] = 0U;
	for (unsigned int i = first; i < first + 32U; i++)
		if (leaf_object[table][i] != 0U)
			return;
	leaf_groups[table] &= (uint16_t)~(1U << (index / 32U));
}

static unsigned int walk(const struct gpu_private_ops *ops,
		struct private_context *ctx, unsigned long iova,
		struct table_transaction *transaction)
{
	unsigned int table = ctx->root;

	for (unsigned int level = 0U; level < 3U; level++) {
		unsigned int index = (unsigned int)((iova >> (39U - level * 9U)) & 511UL);
		uint64_t pte = tables[table][index];
		unsigned int child;

		if (pte != 0UL) {
			table = table_index(ops, ctx->handle, pte);
			if (table == GPU_PRIVATE_TABLES)
				return table;
			continue;
		}
		if (transaction == NULL || transaction->count >= 6U)
			return GPU_PRIVATE_TABLES;
		child = alloc_table(ops, ctx->handle);
		if (child == GPU_PRIVATE_TABLES)
			return child;
		transaction->parent[transaction->count] = (unsigned short)table;
		transaction->entry[transaction->count] = (unsigned short)index;
		transaction->child[transaction->count++] = (unsigned short)child;
		tables[table][index] = ops->table_pa(tables[child]) | PTE_TABLE;
		ops->clean(&tables[table][index], sizeof(uint64_t));
		table = child;
	}
	return table;
}

static void rollback_tables(const struct gpu_private_ops *ops,
		struct private_context *ctx, struct table_transaction *transaction)
{
	/* No GPU has seen an inactive context, so these empty preflight tables
	 * can be returned immediately. Active PTW requires trusted invalidation
	 * before reclaim; retain such tables until stop/detach instead.
	 */
	if (ctx->activated)
		return;
	while (transaction->count != 0U) {
		unsigned int index = --transaction->count;
		uint64_t *entry = &tables[transaction->parent[index]][transaction->entry[index]];

		*entry = 0UL;
		ops->clean(entry, sizeof(*entry));
		table_owner[transaction->child[index]] = 0UL;
	}
}

void gpu_private_context_create(const struct gpu_private_ops *ops,
		const void *owner, const void *service, struct gpu_private_result *result)
{
	result_init(result);
	if (owner == NULL || service == NULL || owner == service)
		return;
	result->status = GPU_PRIVATE_FULL;
	for (unsigned int i = 0U; i < GPU_PRIVATE_CONTEXTS; i++) {
		struct private_context *ctx = &contexts[i];
		unsigned long handle;
		unsigned int root;

		if (ctx->handle != 0UL)
			continue;
		handle = new_handle(CTX_PREFIX, i);
		if (handle == 0UL)
			return;
		root = alloc_table(ops, handle);
		if (root == GPU_PRIVATE_TABLES)
			return;
		memset(ctx, 0, sizeof(*ctx));
		ctx->owner = owner;
		ctx->service = service;
		ctx->handle = handle;
		ctx->root = root;
		result->status = GPU_PRIVATE_SUCCESS;
		result->value[0] = handle;
		return;
	}
}

static bool synchronize(const struct gpu_private_ops *ops, struct private_context *ctx)
{
	if (!ctx->activated)
		return true;
	if (ops->synchronize == NULL ||
	    !ops->synchronize(ctx->handle, ops->table_pa(tables[ctx->root]))) {
		ctx->quarantined = true;
		return false;
	}
	return true;
}

void gpu_private_context_destroy(const struct gpu_private_ops *ops,
		const void *owner, unsigned long context, struct gpu_private_result *result)
{
	struct private_context *ctx = ctx_lookup(owner, context);

	result_init(result);
	if (ctx == NULL)
		return;
	result->status = GPU_PRIVATE_STATE;
	/* An activated root needs a trusted stop/detach operation before destroy.
	 * This core deliberately does not accept a service's "GPU idle" claim.
	 */
	if (ctx->mapped != 0U || ctx->pending != 0U || ctx->group_refs != 0U || ctx->task_refs != 0U ||
	    ctx->activated || ctx->quarantined)
		return;
	for (unsigned int i = 0U; i < GPU_PRIVATE_TABLES; i++) {
		if (table_owner[i] == context) {
			memset(tables[i], 0, sizeof(tables[i]));
			ops->clean(tables[i], sizeof(tables[i]));
			table_owner[i] = 0UL;
			leaf_groups[i] = 0U;
		}
	}
	memset(ctx, 0, sizeof(*ctx));
	result->status = GPU_PRIVATE_SUCCESS;
}

bool gpu_private_context_hold(const void *service, const void *owner,
		unsigned long context)
{
	struct private_context *ctx = ctx_lookup(owner, context);

	if (service == NULL || owner == service || ctx == NULL ||
	    ctx->service != service || ctx->quarantined || ctx->revoked ||
	    ctx->group_refs == UINT_MAX)
		return false;
	ctx->group_refs++;
	return true;
}

void gpu_private_context_put(const void *owner, unsigned long context)
{
	struct private_context *ctx = ctx_lookup(owner, context);

	assert(ctx != NULL && ctx->group_refs != 0U);
	ctx->group_refs--;
}

static bool task_hold_batch(const struct gpu_private_ops *ops, const void *service,
		const void *owner, unsigned long context,
		const struct gpu_private_command_range *ranges, unsigned int count,
		unsigned long live_task)
{
	struct private_context *ctx = ctx_lookup(owner, context);
	unsigned int remaining = GPU_PRIVATE_BATCH;

	if (ops == NULL || ops->table_pa == NULL || service == NULL || owner == service ||
	    ctx == NULL || ctx->service != service || ctx->group_refs == 0U ||
	    ctx->quarantined || ctx->revoked || ctx->task_refs == UINT_MAX ||
	    ranges == NULL || count == 0U || count > GPU_PRIVATE_TASK_BATCH)
		return false;
	if (live_task != 0UL ?
	    (!ctx->drained || !gpu_private_task_live_eligible(ops, service, owner, context, live_task)) :
	    ctx->activated)
		return false;
	for (unsigned int member = 0U; member < count; member++) {
		unsigned long start = ranges[member].start, bytes = ranges[member].bytes;
		unsigned long first = start & ~PAGE_MASK, last;

		if (bytes == 0UL) {
			if (start != 0UL)
				return false;
			continue;
		}
		if (((start | bytes) & 7UL) != 0UL || start >= GPU_PRIVATE_CONTROL_GPU_VA ||
		    bytes > GPU_PRIVATE_CONTROL_GPU_VA - start)
			return false;
		last = (start + bytes - 1UL) & ~PAGE_MASK;
		if ((last - first) / GPU_PRIVATE_PAGE_SIZE >= remaining)
			return false;
		remaining -= (unsigned int)((last - first) / GPU_PRIVATE_PAGE_SIZE) + 1U;
		for (unsigned long va = first; va <= last; va += GPU_PRIVATE_PAGE_SIZE) {
			unsigned int table = walk(ops, ctx, va, NULL);
			unsigned int index = (unsigned int)((va >> 12U) & 511UL), tag;
			struct private_bo *bo;

			if (table == GPU_PRIVATE_TABLES ||
			    (tables[table][index] & (PTE_TABLE | PTE_AF | PTE_USER)) !=
				(PTE_TABLE | PTE_AF | PTE_USER))
				return false;
			tag = leaf_object[table][index];
			if (tag == 0U || tag > GPU_PRIVATE_OBJECTS)
				return false;
			bo = &objects[tag - 1U];
			if (bo->owner != owner || bo->service != service || bo->control || bo->closing)
				return false;
		}
	}
	ctx->task_refs++;
	return true;
}

bool gpu_private_task_hold_batch(const struct gpu_private_ops *ops, const void *service,
		const void *owner, unsigned long context,
		const struct gpu_private_command_range *ranges, unsigned int count)
{
	return task_hold_batch(ops, service, owner, context, ranges, count, 0UL);
}

bool gpu_private_task_hold_live(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long task, const struct gpu_private_command_range *ranges, unsigned int count)
{
	return task != 0UL && task_hold_batch(ops, service, owner, context, ranges, count, task);
}

bool gpu_private_task_hold(const struct gpu_private_ops *ops, const void *service,
		const void *owner, unsigned long context, unsigned long start,
		unsigned long bytes)
{
	const struct gpu_private_command_range range = { .start = start, .bytes = bytes };

	return bytes != 0UL && gpu_private_task_hold_batch(ops, service, owner, context, &range, 1U);
}

bool gpu_private_task_put(const void *owner, unsigned long context)
{
	struct private_context *ctx = ctx_lookup(owner, context);

	if (ctx == NULL || ctx->task_refs == 0U || ctx->activated || ctx->quarantined || ctx->revoked)
		return false;
	ctx->task_refs--;
	return true;
}

void gpu_private_context_prepare(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long firmware_root, struct gpu_private_result *result)
{
	struct private_context *ctx = ctx_lookup(owner, context);
	unsigned int slot;

	result_init(result);
	if (service == NULL || owner == service || ctx == NULL || ctx->service != service ||
	    ops == NULL || ops->prepare_as == NULL || ops->table_pa == NULL || firmware_root == 0UL)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (ctx->quarantined || ctx->revoked || ctx->quiesced || ctx->task_refs == 0U || ctx->pending != 0U ||
	    (ctx->activated && !ctx->live_prepared))
		return;
	if (ctx->live_prepared) {
		slot = ctx->slot;
		if (slot == 0U || slot >= GPU_PRIVATE_AS_SLOTS || slot_owner[slot] != context)
			return;
	} else {
		for (slot = 1U; slot < GPU_PRIVATE_AS_SLOTS; slot++)
			if (slot_owner[slot] == 0UL)
				break;
		result->status = GPU_PRIVATE_FULL;
		if (slot == GPU_PRIVATE_AS_SLOTS)
			return;
		/* Retain slot/root/backing before a possibly partial hardware write. */
		ctx->activated = true;
		ctx->slot = slot;
		slot_owner[slot] = context;
	}
	result->status = GPU_PRIVATE_STATE;
	if (!ops->prepare_as(ops->table_pa(tables[ctx->root]), slot, firmware_root, ctx->live_prepared)) {
		ctx->quarantined = true;
		return;
	}
	ctx->live_prepared = true;
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = slot; /* Trusted internal result, not an RSI address/root. */
}

void gpu_private_context_check_running(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long firmware_root, struct gpu_firmware_config *config,
		struct gpu_private_result *result)
{
	struct private_context *ctx = ctx_lookup(owner, context);
	unsigned int slot;

	result_init(result);
	if (service == NULL || owner == service || ctx == NULL || ctx->service != service ||
	    config == NULL || ops == NULL || ops->check_running_as == NULL ||
	    ops->table_pa == NULL || firmware_root == 0UL)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (ctx->quarantined || ctx->revoked || ctx->quiesced || ctx->task_refs == 0U ||
	    ctx->pending != 0U || !ctx->activated || !ctx->live_prepared)
		return;
	slot = ctx->slot;
	if (slot == 0U || slot >= GPU_PRIVATE_AS_SLOTS || slot_owner[slot] != context)
		return;
	if (!ops->check_running_as(ops->table_pa(tables[ctx->root]), slot, firmware_root, config)) {
		ctx->quarantined = true;
		return;
	}
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = slot;
}

void gpu_private_context_quiesce(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long task, unsigned long firmware_root, struct gpu_private_result *result)
{
	struct private_context *ctx = ctx_lookup(owner, context);

	result_init(result);
	if (service == NULL || service == owner || ctx == NULL || ctx->service != service ||
	    task == 0UL || ops == NULL || ops->table_pa == NULL || ops->detach_as == NULL ||
	    firmware_root == 0UL)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (ctx->quarantined || ctx->revoked || !ctx->activated ||
	    (!ctx->live_prepared && !ctx->quiesced) || ctx->task_refs == 0U ||
	    ctx->pending != 0U || ctx->extension_object != 0UL || ctx->cache_task != task ||
	    ctx->cache_cursor != GPU_PRIVATE_TABLES * ENTRIES || ctx->slot == 0U ||
	    ctx->slot >= GPU_PRIVATE_AS_SLOTS || slot_owner[ctx->slot] != context)
		return;
	/* A partial flush/UPDATE may already have disabled translation. Never
	 * try to repair/reinstall the root or release backing on that ambiguity.
	 */
	ctx->quarantined = true;
	if (!ops->detach_as(ops->table_pa(tables[ctx->root]), ctx->slot,
			firmware_root, ctx->quiesced))
		return;
	ctx->quarantined = false;
	ctx->quiesced = true;
	ctx->live_prepared = false;
	ctx->drained = false;
	result->status = GPU_PRIVATE_SUCCESS;
}

/* A protected unchanged PT cannot acquire a new leaf without an epoch change.
 * Recheck every referenced BO before acquiring any lease. Alias exclusion is
 * per task, never cached across retirement or another context's execution.
 * The bitmap includes donated control BOs too, but gives them no data lease.
 */
static bool cache_set_check(struct private_cache_set *set,
		struct private_context *ctx, const void *service, const void *owner,
		bool for_cpu, bool acquire, bool *uncached_seen)
{
	for (unsigned int word = 0U; word < CACHE_SET_WORDS; word++) {
		uint64_t bits = set->objects[word];

		while (bits != 0U) {
			unsigned int bit = (unsigned int)__builtin_ctzll(bits);
			unsigned int index = word * 64U + bit;
			struct private_bo *bo;

			bits &= bits - 1U;
			if (index >= GPU_PRIVATE_OBJECTS)
				return false;
			bo = &objects[index];
			if (bo->service != service || bo->closing || bo->handle == 0UL)
				return false;
			if (bo->control) {
				if (bo->owner != service || bo->control_gpu_refs == 0U)
					return false;
				continue;
			}
			if (bo->owner != owner || (!bo->resident && !bo->uncached) ||
			    bo->hidden != bo->pages || bo->mapped == 0U ||
			    (for_cpu ? bo->cache_context != ctx->handle :
				(bo->cache_context != 0UL && bo->cache_context != ctx->handle)))
				return false;
			*uncached_seen |= bo->uncached;
			if (acquire)
				cache_lease_acquire(ctx, bo);
		}
	}
	return true;
}

bool gpu_private_task_live_eligible(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context, unsigned long task)
{
	struct private_context *ctx = ctx_lookup(owner, context);
	struct private_cache_set *set;
	bool uncached = false;

	if (ops == NULL || !ops->protected_mapping_summary || service == NULL || service == owner ||
	    ctx == NULL || ctx->service != service || task == 0UL || ctx->cache_task != task ||
	    !ctx->activated || !ctx->live_prepared || ctx->quiesced || ctx->quarantined || ctx->revoked ||
	    ctx->task_refs == 0U || ctx->group_refs == 0U || ctx->pending != 0U ||
	    ctx->extension_object != 0UL || ctx->cache_cursor != GPU_PRIVATE_TABLES * ENTRIES ||
	    ctx->cache_pages != 0U || ctx->return_cursor != 0U || ctx->return_pages != 0U ||
	    ctx->slot == 0U || ctx->slot >= GPU_PRIVATE_AS_SLOTS || slot_owner[ctx->slot] != context)
		return false;
	set = cache_set_for(context);
	if (!set->valid || set->context != context || set->epoch != ctx->mapping_epoch)
		return false;
	/* Only the BO metadata predicates are reusable. All context/token,
	 * epoch, lifecycle and slot checks above still read fresh state; callers
	 * still perform real hardware/root/configuration/completion checks.
	 * No callback or unlock occurs while constructing this summary.
	 */
	if (cache_metadata_epoch != 0UL && set->live_epoch == cache_metadata_epoch)
		return !set->live_uncached || ops->cache_barrier != NULL;
	if (!cache_set_check(set, ctx, service, owner, true, false, &uncached))
		return false;
	set->live_uncached = uncached;
	set->live_epoch = cache_metadata_epoch;
	return !uncached || ops->cache_barrier != NULL;
}

bool gpu_private_task_flush_live(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long task, unsigned long firmware_root)
{
	struct private_context *ctx = ctx_lookup(owner, context);

	gpu_private_task_clear_drained(service, owner, context, task);
	if (!gpu_private_task_live_eligible(ops, service, owner, context, task) ||
	    firmware_root == 0UL || ops->table_pa == NULL || ops->flush_as == NULL)
		return false;
	/* A previous observation never survives a physical callback. A partial
	 * flush/barrier must not reopen staging or release any lease/backing.
	 */
	ctx->drained = false;
	ctx->quarantined = true;
	if (!ops->flush_as(ops->table_pa(tables[ctx->root]), ctx->slot, firmware_root) ||
	    (ops->cache_barrier != NULL && !ops->cache_barrier()))
		return false;
	ctx->quarantined = false;
	if (!gpu_private_task_live_eligible(ops, service, owner, context, task)) {
		ctx->quarantined = true;
		return false;
	}
	return true;
}

bool gpu_private_task_mark_drained(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context, unsigned long task)
{
	if (!gpu_private_task_live_eligible(ops, service, owner, context, task))
		return false;
	ctx_lookup(owner, context)->drained = true;
	return true;
}

void gpu_private_task_clear_drained(const void *service, const void *owner,
		unsigned long context, unsigned long task)
{
	struct private_context *ctx = ctx_lookup(owner, context);

	if (service != NULL && service != owner && ctx != NULL && ctx->service == service &&
	    task != 0UL && ctx->cache_task == task)
		ctx->drained = false;
}

bool gpu_private_task_is_drained(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context, unsigned long task)
{
	return gpu_private_task_live_eligible(ops, service, owner, context, task) &&
		ctx_lookup(owner, context)->drained;
}

bool gpu_private_task_put_live(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context, unsigned long task)
{
	struct private_context *ctx = ctx_lookup(owner, context);

	if (!gpu_private_task_live_eligible(ops, service, owner, context, task) ||
	    !ctx->drained || ctx->task_refs < 2U)
		return false;
	ctx->task_refs--;
	return true;
}

bool gpu_private_task_handoff_live(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long previous, unsigned long next)
{
	struct private_context *ctx = ctx_lookup(owner, context);

	if (next == 0UL || next == previous ||
	    !gpu_private_task_live_eligible(ops, service, owner, context, previous) ||
	    !ctx->drained || ctx->task_refs < 2U)
		return false;
	/* No callbacks or publication in this commit. Keep AS, frozen PTE epoch
	 * and every cache lease; only the staged successor's hold survives.
	 */
	ctx->task_refs--;
	ctx->cache_task = next;
	ctx->cache_cursor = ctx->cache_pages = 0U;
	ctx->return_cursor = ctx->return_pages = 0U;
	ctx->drained = false;
	return true;
}

static void task_cache(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long task, bool for_cpu, struct gpu_private_result *result)
{
	struct private_context *ctx = ctx_lookup(owner, context);
	struct private_cache_set *set;
	unsigned int scan_budget = CACHE_SCAN_BATCH;
	unsigned int sync_budget = GPU_PRIVATE_BATCH;
	unsigned int checked_nc_tag = 0U;
	uint64_t checked_nc_tags = 0U;
	unsigned int *cursor, *pages;
	bool uncached_seen = false;

	result_init(result);
	if (service == NULL || owner == service || ctx == NULL || ctx->service != service ||
	    task == 0UL || ops == NULL ||
	    (for_cpu ? ops->sync_page_for_cpu == NULL : ops->sync_page_for_device == NULL))
		return;
	result->status = GPU_PRIVATE_STATE;
	if (!ctx->activated || ctx->quarantined || ctx->revoked || ctx->extension_object != 0UL ||
	    ctx->task_refs == 0U || ctx->pending != 0U ||
	    (ctx->cache_task != 0UL && ctx->cache_task != task))
		return;
	if (for_cpu) {
		if (!ctx->quiesced || ctx->live_prepared || ctx->cache_task != task ||
		    ctx->cache_cursor != GPU_PRIVATE_TABLES * ENTRIES)
			return;
	} else if (!ctx->live_prepared || ctx->quiesced) {
		return;
	}
	cursor = for_cpu ? &ctx->return_cursor : &ctx->cache_cursor;
	pages = for_cpu ? &ctx->return_pages : &ctx->cache_pages;
	ctx->cache_task = task;
	set = cache_set_for(context);
	if (ops->protected_mapping_summary && set->valid &&
	    set->context == context && set->epoch == ctx->mapping_epoch &&
	    (*cursor == 0U || *cursor == GPU_PRIVATE_TABLES * ENTRIES)) {
		/* No physical callback or unlock between preflight and acquisition.
		 * RETURN still follows real SUSPEND/flush/AS disable in the consumer.
		 */
		if (*pages != 0U || ctx->cache_pages != 0U ||
		    !cache_set_check(set, ctx, service, owner, for_cpu, false, &uncached_seen) ||
		    !cache_set_check(set, ctx, service, owner, for_cpu, true, &uncached_seen))
			goto failed;
		*cursor = GPU_PRIVATE_TABLES * ENTRIES;
		goto barrier;
	}
	if (ops->protected_mapping_summary && !for_cpu && *cursor == 0U) {
		memset(set, 0, sizeof(*set));
		set->context = context;
		set->epoch = ctx->mapping_epoch;
		set->eligible = true;
	}
	/* Table ownership and leaf tags are private, frozen RMM metadata. Skip
	 * unrelated tables wholesale, never follow Proxy-selected pointers or
	 * synchronize another Client's pages. A trusted empty table/group takes
	 * one scan unit; every entry of an occupied group still takes one.
	 * Independently cap expensive physical cache operations. Both cursors and
	 * leases survive continuation; no tagged leaf is skipped by either limit.
	 */
	while (*cursor < GPU_PRIVATE_TABLES * ENTRIES && scan_budget != 0U &&
	       sync_budget != 0U) {
		unsigned int table = *cursor / ENTRIES;
		unsigned int index = *cursor % ENTRIES;
		unsigned int end = (index | 31U) + 1U;

		if (table_owner[table] != context) {
			*cursor = (table + 1U) * ENTRIES;
			continue;
		}
		if (leaf_groups[table] == 0U) {
			scan_budget--;
			*cursor = (table + 1U) * ENTRIES;
			continue;
		}
		if ((leaf_groups[table] & (1U << (index / 32U))) == 0U) {
			scan_budget--;
			*cursor = table * ENTRIES + (index | 31U) + 1U;
			continue;
		}
		/* The policy lock freezes this table/group while no physical
		 * callback runs. Walk its leaves directly, retaining the per-leaf
		 * budget, tag and actual PTE checks. A physical callback exits this
		 * inner walk so the next entry rechecks the table/group boundary.
		 */
		for (; index < end && scan_budget != 0U && sync_budget != 0U; index++) {
			unsigned int tag;
			struct private_bo *bo;
			uint64_t pte;

			/* A checked NC/resident BO has no per-page callback. Inspect four
			 * consecutive real leaves together while the same policy lock
			 * freezes their tags, ownership and lifecycle. Do not cross this
			 * 32-entry group or the metadata budget. On any mismatch, fall
			 * through to the scalar walk so its first-failure cursor and all
			 * control/WB handling remain exact. No proof crosses a callback.
			 */
			if (checked_nc_tag != 0U && (index & 3U) == 0U &&
			    end - index >= 4U && scan_budget >= 4U) {
				uint64_t tags;

				/* Read all four real tags as one naturally aligned word.
				 * memcpy avoids aliasing through a uint64_t pointer; the
				 * alignment follows from the array and four-entry boundary.
				 * The repeated tag word is invariant only within this call's
				 * callback-free checked BO span, exactly like checked_nc_tag.
				 */
				__builtin_memcpy(&tags, __builtin_assume_aligned(
					&leaf_object[table][index], 8), sizeof(tags));
				uint64_t present = tables[table][index] & tables[table][index + 1U] &
					tables[table][index + 2U] & tables[table][index + 3U];

				if (tags == checked_nc_tags &&
				    (present & (PTE_TABLE | PTE_AF | PTE_USER)) ==
				    (PTE_TABLE | PTE_AF | PTE_USER)) {
					scan_budget -= 4U;
					*cursor += 4U;
					index += 3U;
					continue;
				}
			}
			scan_budget--;
			tag = leaf_object[table][index];
			if (tag == 0U) {
				(*cursor)++;
				continue;
			}
			if (tag > GPU_PRIVATE_OBJECTS)
				goto failed;
			pte = tables[table][index];
			if ((pte & (PTE_TABLE | PTE_AF | PTE_USER)) !=
			    (PTE_TABLE | PTE_AF | PTE_USER))
				goto failed;
			/* The policy lock freezes BO ownership/lifecycle and PT mutation for
			 * this entire call. Reuse only the last fully checked NC/resident BO:
			 * those leaves have no physical callback between checks. Each leaf's
			 * actual tag and hardware PTE is still read above. Never retain this
			 * proof over a continuation, cache operation or final NC barrier.
			 */
			if (tag == checked_nc_tag) {
				(*cursor)++;
				continue;
			}
			checked_nc_tag = 0U;
			bo = &objects[tag - 1U];
			if (bo->service != service || bo->closing)
				goto failed;
			if (ops->protected_mapping_summary && !for_cpu) {
				set->objects[(tag - 1U) / 64U] |= UINT64_C(1) << ((tag - 1U) % 64U);
				if (!bo->control && !bo->resident && !bo->uncached)
					set->eligible = false;
			}
			if (bo->control) {
				if (bo->owner != service)
					goto failed;
			} else {
				if (bo->owner != owner ||
				    (for_cpu ? bo->cache_context != context :
					(bo->cache_context != 0UL && bo->cache_context != context)))
					goto failed;
				/* Do not perform CPU cache maintenance over backing already handed
				 * to another context, even within this Client. Holds are retained
				 * across partial failure until trusted device reset.
				 */
				cache_lease_acquire(ctx, bo);
				/* Only a completed RMM donation proves absence of CPU writers.
				 * Keep owner/context/leaf checks and leases even when no cache
				 * ownership is returned to the CPU between GPU tasks.
				 */
				if (bo->resident || bo->uncached) {
					if (bo->hidden != bo->pages)
						goto failed;
					uncached_seen |= bo->uncached;
					checked_nc_tag = tag;
					checked_nc_tags = UINT64_C(0x0001000100010001) * tag;
					(*cursor)++;
					continue;
				}
				if (!(for_cpu ? ops->sync_page_for_cpu((unsigned long)(pte & ADDRESS_MASK)) :
					ops->sync_page_for_device((unsigned long)(pte & ADDRESS_MASK))))
					goto failed;
				sync_budget--;
				(*pages)++;
				(*cursor)++;
				break;
			}
			(*cursor)++;
		}
	}
barrier:
	if (uncached_seen && (ops->cache_barrier == NULL || !ops->cache_barrier()))
		goto failed;
	if (for_cpu && *cursor == GPU_PRIVATE_TABLES * ENTRIES && *pages != ctx->cache_pages)
		goto failed;
	if (ops->protected_mapping_summary && !for_cpu &&
	    *cursor == GPU_PRIVATE_TABLES * ENTRIES && set->context == context &&
	    set->epoch == ctx->mapping_epoch && set->eligible && *pages == 0U)
		set->valid = true;
	result->value[0] = *pages;
	result->status = *cursor == GPU_PRIVATE_TABLES * ENTRIES ?
		GPU_PRIVATE_SUCCESS : GPU_PRIVATE_INCOMPLETE;
	return;
failed:
	set->valid = false;
	ctx->quarantined = true;
}

void gpu_private_task_cache(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long task, struct gpu_private_result *result)
{
	task_cache(ops, service, owner, context, task, false, result);
}

void gpu_private_task_return(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long task, struct gpu_private_result *result)
{
	task_cache(ops, service, owner, context, task, true, result);
}

void gpu_private_task_returned(const void *service, const void *owner,
		unsigned long context, unsigned long task, struct gpu_private_result *result)
{
	struct private_context *ctx = ctx_lookup(owner, context);

	result_init(result);
	if (service == NULL || owner == service || ctx == NULL || ctx->service != service ||
	    task == 0UL)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (ctx->quarantined || ctx->revoked || !ctx->activated || !ctx->quiesced ||
	    ctx->live_prepared || ctx->pending != 0U || ctx->extension_object != 0UL ||
	    ctx->task_refs == 0U || ctx->cache_task != task ||
	    ctx->cache_cursor != GPU_PRIVATE_TABLES * ENTRIES ||
	    ctx->return_cursor != GPU_PRIVATE_TABLES * ENTRIES || ctx->return_pages != ctx->cache_pages ||
	    ctx->slot == 0U || ctx->slot >= GPU_PRIVATE_AS_SLOTS || slot_owner[ctx->slot] != context)
		return;
	/* Completion cursors and the lease are private RMM state under the
	 * policy lock. No PTE scan, physical cache callback or hardware write
	 * occurs here, so this check needs only one real quiescence boundary.
	 */
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = ctx->return_pages;
}

bool gpu_private_task_retire(const void *service, const void *owner,
		unsigned long context, unsigned long task)
{
	struct private_context *ctx = ctx_lookup(owner, context);

	if (service == NULL || owner == service || ctx == NULL || ctx->service != service ||
	    ctx->quarantined || ctx->revoked || !ctx->activated || !ctx->quiesced ||
	    ctx->live_prepared || ctx->pending != 0U || ctx->extension_object != 0UL || ctx->task_refs == 0U ||
	    task == 0UL || ctx->cache_task != task ||
	    ctx->cache_cursor != GPU_PRIVATE_TABLES * ENTRIES ||
	    ctx->return_cursor != GPU_PRIVATE_TABLES * ENTRIES || ctx->return_pages != ctx->cache_pages ||
	    ctx->slot == 0U || ctx->slot >= GPU_PRIVATE_AS_SLOTS || slot_owner[ctx->slot] != context)
		return false;
	/* Preflight all metadata before releasing anything. BO backing/mapping
	 * refs remain; only this context's completed cache lease is retired.
	 */
	for (unsigned int group = 0U; group < CACHE_LEASE_GROUPS; group++) {
		if ((ctx->cache_groups & (1U << group)) == 0U)
			continue;
		unsigned int end = (group + 1U) * CACHE_LEASE_GROUP_SIZE;

		if (end > GPU_PRIVATE_OBJECTS)
			end = GPU_PRIVATE_OBJECTS;
		for (unsigned int i = group * CACHE_LEASE_GROUP_SIZE; i < end; i++)
			if (objects[i].cache_context == context &&
			    (objects[i].owner != owner || objects[i].service != service || objects[i].control))
				return false;
	}
	for (unsigned int group = 0U; group < CACHE_LEASE_GROUPS; group++) {
		if ((ctx->cache_groups & (1U << group)) == 0U)
			continue;
		unsigned int end = (group + 1U) * CACHE_LEASE_GROUP_SIZE;

		if (end > GPU_PRIVATE_OBJECTS)
			end = GPU_PRIVATE_OBJECTS;
		for (unsigned int i = group * CACHE_LEASE_GROUP_SIZE; i < end; i++)
			if (objects[i].cache_context == context)
				{
					cache_metadata_invalidate();
					objects[i].cache_context = 0UL;
				}
	}
	ctx->cache_groups = 0U;
	slot_owner[ctx->slot] = 0UL;
	ctx->slot = 0U;
	ctx->activated = ctx->quiesced = false;
	ctx->cache_task = 0UL;
	ctx->cache_cursor = ctx->cache_pages = ctx->return_cursor = ctx->return_pages = 0U;
	ctx->task_refs--;
	return true;
}

static void stage_object_mapping(const struct gpu_private_ops *ops, struct private_context *ctx,
		struct private_bo *bo, unsigned long offset, unsigned long iova,
		size_t count, unsigned long prot, struct gpu_private_result *result)
{
	struct table_transaction transaction = { 0 };
	unsigned int first;

	result_init(result);
	result->status = GPU_PRIVATE_STATE;
	if (ctx->mapping_epoch == ULONG_MAX ||
	    ((bo->resident || bo->uncached) && bo->hidden != bo->pages))
		return;
	first = (unsigned int)(offset / GPU_PRIVATE_PAGE_SIZE);
	/* Preflight every leaf before publishing any data mapping. */
	for (size_t i = 0U; i < count; i++) {
		unsigned long va = iova + i * GPU_PRIVATE_PAGE_SIZE;
		unsigned int table = walk(ops, ctx, va, &transaction);

		if (table == GPU_PRIVATE_TABLES) {
			result->status = GPU_PRIVATE_FULL;
			rollback_tables(ops, ctx, &transaction);
			return;
		}
		if (tables[table][(va >> 12U) & 511UL] != 0UL) {
			rollback_tables(ops, ctx, &transaction);
			return;
		}
	}
	/* An attempted leaf mutation gets a fresh, non-wrapping snapshot epoch.
	 * Partial invalidation failures quarantine the context as before.
	 */
	ctx->mapping_epoch++;
	for (size_t i = 0U; i < count; i++) {
		unsigned long va = iova + i * GPU_PRIVATE_PAGE_SIZE;
		unsigned int table = walk(ops, ctx, va, NULL);
		unsigned int index = (unsigned int)((va >> 12U) & 511UL);
		unsigned long pte = ((unsigned long)bo_page(bo, first + (unsigned int)i)->pa_page << 12U) |
			PTE_TABLE | PTE_AF | PTE_NG | PTE_USER;

		if ((prot & GPU_PRIVATE_WRITE) == 0UL)
			pte |= PTE_RO;
		if ((prot & GPU_PRIVATE_EXEC) == 0UL)
			pte |= PTE_XN;
		pte |= (prot & GPU_PRIVATE_CACHE) != 0UL ? (3UL << 8U) | (1UL << 2U) : 2UL << 8U;
		leaf_object[table][index] = (unsigned short)(bo - objects + 1);
		leaf_groups[table] |= (uint16_t)(1U << (index / 32U));
		tables[table][index] = pte;
		ops->clean(&tables[table][index], sizeof(uint64_t));
		if (bo->control)
			{
				cache_metadata_invalidate();
				bo->control_gpu_refs++;
			}
		else
			{
				cache_metadata_invalidate();
				bo->mapped++;
			}
		ctx->mapped++;
	}
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = count * GPU_PRIVATE_PAGE_SIZE;
}

static void map_object(const struct gpu_private_ops *ops, struct private_context *ctx,
		struct private_bo *bo, unsigned long offset, unsigned long iova,
		size_t count, unsigned long prot, struct gpu_private_result *result)
{
	stage_object_mapping(ops, ctx, bo, offset, iova, count, prot, result);
	if (result->status != GPU_PRIVATE_SUCCESS)
		return;
	result->status = GPU_PRIVATE_STATE;
	result->value[0] = 0UL;
	if (!synchronize(ops, ctx))
		return;
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = count * GPU_PRIVATE_PAGE_SIZE;
}

void gpu_private_task_extend(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long task, unsigned long object, unsigned long iova,
		unsigned long firmware_root, struct gpu_private_result *result)
{
	struct private_context *ctx = ctx_lookup(owner, context);
	struct private_bo *bo = bo_lookup(owner, object);
	struct gpu_private_result checked;
	unsigned int first, count;

	result_init(result);
	if (service == NULL || service == owner || ctx == NULL || bo == NULL ||
	    ctx->service != service || bo->service != service || bo->control || bo->closing ||
	    bo->registered != bo->pages || bo->pages < 32U || bo->pages > 2048U ||
	    (bo->access & (GPU_PRIVATE_READ | GPU_PRIVATE_WRITE)) != (GPU_PRIVATE_READ | GPU_PRIVATE_WRITE) ||
	    (iova & PAGE_MASK) != 0UL || iova >= GPU_PRIVATE_CONTROL_GPU_VA ||
	    bo->pages > (GPU_PRIVATE_CONTROL_GPU_VA - iova) / GPU_PRIVATE_PAGE_SIZE ||
	    task == 0UL || firmware_root == 0UL || ops == NULL || ops->table_pa == NULL ||
	    ops->clean == NULL || ops->prepare_as == NULL || ops->extend_as == NULL ||
	    ops->sync_page_for_device == NULL)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (ctx->quarantined || ctx->revoked || !ctx->activated || !ctx->live_prepared ||
	    ctx->quiesced || ctx->task_refs == 0U || ctx->pending != 0U || ctx->cache_task != task ||
	    ctx->cache_cursor != GPU_PRIVATE_TABLES * ENTRIES || ctx->return_cursor != 0U ||
	    ctx->return_pages != 0U || ctx->slot == 0U || ctx->slot >= GPU_PRIVATE_AS_SLOTS ||
	    slot_owner[ctx->slot] != context || ctx->mapping_epoch == ULONG_MAX)
		return;
	if (ctx->extension_object != 0UL) {
		if (ctx->extension_object != object || ctx->extension_va != iova ||
		    bo->cache_context != context || bo->pending == 0U ||
		    ctx->extension_cursor >= bo->pages)
			return;
	} else {
		/* A fresh object cannot alias backing already owned by any GPUVM.
		 * Check the ENTIRE destination before synchronizing a single page;
		 * an occupied later batch must not leave an authorized prefix.
		 */
		if (bo->mapped != 0U || bo->pending != 0U || bo->cache_context != 0UL)
			return;
		for (unsigned int i = 0U; i < bo->pages; i++) {
			unsigned long va = iova + i * GPU_PRIVATE_PAGE_SIZE;
			unsigned int table = walk(ops, ctx, va, NULL);

			if (table != GPU_PRIVATE_TABLES && tables[table][(va >> 12U) & 511UL] != 0UL)
				return;
		}
	}
	/* Existing-root preparation is a read-only check. No Client or Proxy can
	 * select another AS or repair changed hardware while growing a task.
	 */
	gpu_private_context_prepare(ops, service, owner, context, firmware_root, &checked);
	if (checked.status != GPU_PRIVATE_SUCCESS)
		return;
	if (ctx->extension_object == 0UL) {
		ctx->extension_object = object;
		ctx->extension_va = iova;
		ctx->extension_cursor = 0U;
		bo->pending++;
		cache_lease_acquire(ctx, bo);
	}
	first = ctx->extension_cursor;
	count = bo->pages - first;
	if (count > GPU_PRIVATE_BATCH)
		count = GPU_PRIVATE_BATCH;
	if (!bo->resident && !bo->uncached && ctx->cache_pages > UINT_MAX - count)
		goto failed;
	if ((bo->resident || bo->uncached) && bo->hidden != bo->pages)
		goto failed;
	for (unsigned int i = 0U; i < count; i++) {
		struct backing_page *page = bo_page(bo, first + i);

		if (page == NULL || (!bo->resident && !bo->uncached &&
		    !ops->sync_page_for_device((unsigned long)page->pa_page << 12U)))
			goto failed;
	}
	if (bo->uncached && (ops->cache_barrier == NULL || !ops->cache_barrier()))
		goto failed;
	stage_object_mapping(ops, ctx, bo, (unsigned long)first * GPU_PRIVATE_PAGE_SIZE,
		iova + (unsigned long)first * GPU_PRIVATE_PAGE_SIZE, count,
		GPU_PRIVATE_READ | GPU_PRIVATE_WRITE | GPU_PRIVATE_CACHE, &checked);
	if (checked.status != GPU_PRIVATE_SUCCESS)
		goto failed;
	/* Account for published leaves BEFORE any uncertain hardware operation.
	 * A later trusted reset can then retire every exact mapping/backing hold.
	 */
	ctx->extension_cursor += count;
	if (!bo->resident && !bo->uncached)
		ctx->cache_pages += count;
	if (!ops->extend_as(ops->table_pa(tables[ctx->root]), ctx->slot, firmware_root))
		goto failed;
	result->value[0] = ctx->extension_cursor;
	result->status = ctx->extension_cursor == bo->pages ? GPU_PRIVATE_SUCCESS : GPU_PRIVATE_INCOMPLETE;
	if (result->status == GPU_PRIVATE_SUCCESS) {
		assert(bo->pending != 0U);
		bo->pending--;
		ctx->extension_object = ctx->extension_va = 0UL;
		ctx->extension_cursor = 0U;
	}
	return;
failed:
	ctx->quarantined = true;
}

void gpu_private_map(const struct gpu_private_ops *ops, const void *owner,
		unsigned long context, unsigned long object, unsigned long offset,
		unsigned long iova, size_t count, unsigned long prot,
		struct gpu_private_result *result)
{
	struct private_context *ctx = ctx_lookup(owner, context);
	struct private_bo *bo = bo_lookup(owner, object);

	result_init(result);
	if (ctx == NULL || bo == NULL || bo->control || bo->service != ctx->service || bo->closing ||
	    bo->registered != bo->pages || !range_valid(iova, count) ||
	    iova >= GPU_PRIVATE_CONTROL_GPU_VA ||
	    count > (GPU_PRIVATE_CONTROL_GPU_VA - iova) / GPU_PRIVATE_PAGE_SIZE ||
	    (offset & PAGE_MASK) != 0UL || offset / GPU_PRIVATE_PAGE_SIZE >= bo->pages ||
	    count > bo->pages - offset / GPU_PRIVATE_PAGE_SIZE ||
	    (prot & GPU_PRIVATE_READ) == 0UL ||
	    (prot & ~(GPU_PRIVATE_ACCESS | GPU_PRIVATE_CACHE)) != 0UL ||
	    (prot & GPU_PRIVATE_ACCESS & ~bo->access) != 0UL)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (ctx->quarantined || ctx->revoked || ctx->task_refs != 0U)
		return;
	map_object(ops, ctx, bo, offset, iova, count, prot, result);
}

static void unmap_object(const struct gpu_private_ops *ops, const void *owner,
		unsigned long context, unsigned long iova, size_t count, unsigned long control,
		struct gpu_private_result *result)
{
	struct private_context *ctx = ctx_lookup(owner, context);

	result_init(result);
	if (ctx == NULL || !range_valid(iova, count))
		return;
	result->status = GPU_PRIVATE_STATE;
	if (ctx->quarantined || ctx->task_refs != 0U || ctx->mapping_epoch == ULONG_MAX)
		return;
	/* Activated contexts require a trusted stop/detach before any backing
	 * references can be released. Merely invalidating TLBs is insufficient
	 * to cancel in-flight memory transactions.
	 */
	if (ctx->activated)
		return;
	/* Reject a mixed public/internal range before modifying ANY leaf. */
	ctx->mapping_epoch++;
	for (size_t i = 0U; i < count; i++) {
		unsigned long va = iova + i * GPU_PRIVATE_PAGE_SIZE;
		unsigned int table = walk(ops, ctx, va, NULL);
		unsigned int index = (unsigned int)((va >> 12U) & 511UL);
		unsigned int object;

		if (table == GPU_PRIVATE_TABLES || tables[table][index] == 0UL)
			continue;
		object = leaf_object[table][index];
		if (object == 0U || object > GPU_PRIVATE_OBJECTS ||
		    objects[object - 1U].control != (control != 0UL) ||
		    (control != 0UL && objects[object - 1U].handle != control))
			return;
	}
	for (size_t i = 0U; i < count; i++) {
		unsigned long va = iova + i * GPU_PRIVATE_PAGE_SIZE;
		unsigned int table = walk(ops, ctx, va, NULL);
		unsigned int index = (unsigned int)((va >> 12U) & 511UL);
		unsigned int object;

		if (table == GPU_PRIVATE_TABLES || tables[table][index] == 0UL)
			continue;
		object = leaf_object[table][index];
		if (object == 0U || object > GPU_PRIVATE_OBJECTS)
			return;
		tables[table][index] = 0UL;
		ops->clean(&tables[table][index], sizeof(uint64_t));
		forget_leaf(table, index);
		if (control != 0UL)
			{
				cache_metadata_invalidate();
				objects[object - 1U].control_gpu_refs--;
			}
		else
			{
				cache_metadata_invalidate();
				objects[object - 1U].mapped--;
			}
		ctx->mapped--;
	}
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = count * GPU_PRIVATE_PAGE_SIZE;
}

void gpu_private_unmap(const struct gpu_private_ops *ops, const void *owner,
		unsigned long context, unsigned long iova, size_t count,
		struct gpu_private_result *result)
{
	result_init(result);
	if (!range_valid(iova, count) || iova >= GPU_PRIVATE_CONTROL_GPU_VA ||
	    count > (GPU_PRIVATE_CONTROL_GPU_VA - iova) / GPU_PRIVATE_PAGE_SIZE)
		return;
	unmap_object(ops, owner, context, iova, count, 0UL, result);
}

void gpu_private_unmap_bo(const struct gpu_private_ops *ops, const void *owner,
		unsigned long context, unsigned long object, unsigned long offset,
		unsigned long iova, size_t count, struct gpu_private_result *result)
{
	struct private_context *ctx = ctx_lookup(owner, context);
	struct private_bo *bo = bo_lookup(owner, object);
	unsigned short selected[GPU_PRIVATE_BATCH];
	unsigned int matched = 0U;

	result_init(result);
	if (ops == NULL || ops->table_pa == NULL || ops->clean == NULL ||
	    ctx == NULL || bo == NULL || bo->control || bo->service != ctx->service ||
	    bo->registered != bo->pages || !range_valid(iova, count) ||
	    iova >= GPU_PRIVATE_CONTROL_GPU_VA ||
	    count > (GPU_PRIVATE_CONTROL_GPU_VA - iova) / GPU_PRIVATE_PAGE_SIZE ||
	    (offset & PAGE_MASK) != 0UL || offset / GPU_PRIVATE_PAGE_SIZE >= bo->pages ||
	    count > bo->pages - offset / GPU_PRIVATE_PAGE_SIZE)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (ctx->quarantined || ctx->revoked || ctx->activated || ctx->task_refs != 0U ||
	    ctx->mapping_epoch == ULONG_MAX || table_owner[ctx->root] != context)
		return;
	/* Under the policy lock, snapshot exactly the leaves owned by this BO.
	 * Do not turn a failed MAP collision into a range-wide UNMAP. An invalid
	 * non-leaf is an error, never evidence of an empty range.
	 */
	for (size_t i = 0U; i < count; i++) {
		unsigned long va = iova + i * GPU_PRIVATE_PAGE_SIZE;
		unsigned int table = ctx->root;
		unsigned int index = (unsigned int)((va >> 12U) & 511UL);
		uint64_t pte;
		unsigned int tag;

		selected[i] = GPU_PRIVATE_TABLES;
		for (unsigned int level = 0U; level < 3U; level++) {
			pte = tables[table][(va >> (39U - level * 9U)) & 511UL];
			if (pte == 0UL) {
				table = GPU_PRIVATE_TABLES;
				break;
			}
			table = table_index(ops, context, pte);
			if (table == GPU_PRIVATE_TABLES)
				return;
		}
		if (table == GPU_PRIVATE_TABLES)
			continue;
		pte = tables[table][index];
		tag = leaf_object[table][index];
		if (pte == 0UL) {
			if (tag != 0U)
				return;
			continue;
		}
		if (tag == 0U || tag > GPU_PRIVATE_OBJECTS)
			return;
		if (tag != (unsigned int)(bo - objects + 1))
			continue;
		if ((pte & 3UL) != PTE_TABLE || (pte & ADDRESS_MASK) !=
		    ((uint64_t)bo_page(bo, offset / GPU_PRIVATE_PAGE_SIZE + i)->pa_page << 12U))
			return;
		selected[i] = (unsigned short)table;
		matched++;
	}
	if (bo->mapped < matched || ctx->mapped < matched)
		return;
	/* One epoch covers the whole atomic batch, including an idempotent retry.
	 * No allocation, external callback that drops the lock, or untrusted
	 * service operation can replace these leaves between check and removal.
	 */
	ctx->mapping_epoch++;
	for (size_t i = 0U; i < count; i++) {
		unsigned int table = selected[i];
		unsigned int index = (unsigned int)(((iova >> 12U) + i) & 511UL);

		if (table == GPU_PRIVATE_TABLES)
			continue;
		tables[table][index] = 0UL;
		ops->clean(&tables[table][index], sizeof(uint64_t));
		forget_leaf(table, index);
	}
	{
		cache_metadata_invalidate();
		bo->mapped -= matched;
	}
	ctx->mapped -= matched;
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = count * GPU_PRIVATE_PAGE_SIZE;
}

void gpu_private_control_mapping(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long object, unsigned int first, unsigned int count,
		bool writable, bool install, struct gpu_private_result *result)
{
	struct private_context *ctx = ctx_lookup(owner, context);
	struct private_bo *bo = bo_lookup(service, object);
	unsigned long va = GPU_PRIVATE_CONTROL_GPU_VA + (unsigned long)first * 4096UL;

	result_init(result);
	if (ops == NULL || ops->table_pa == NULL || ops->clean == NULL ||
	    service == NULL || owner == service || ctx == NULL || ctx->service != service ||
	    bo == NULL || !bo->control || bo->closing || bo->mapped != 1U ||
	    bo->registered != bo->pages || bo->hidden != bo->pages ||
	    first >= bo->pages || count == 0U || count > bo->pages - first ||
	    !range_valid(va, count))
		return;
	result->status = GPU_PRIVATE_STATE;
	if (ctx->group_refs == 0U || ctx->task_refs != 0U ||
	    ctx->activated || ctx->quarantined || ctx->revoked)
		return;
	if (install)
		map_object(ops, ctx, bo, (unsigned long)first * 4096UL, va, count,
			GPU_PRIVATE_READ | (writable ? GPU_PRIVATE_WRITE : 0UL), result);
	else
		unmap_object(ops, owner, context, va, count, object, result);
}

void gpu_private_context_activate(const struct gpu_private_ops *ops,
		const void *service, unsigned long context, unsigned long hardware_slot,
		struct gpu_private_result *result)
{
	unsigned long slot = context & 0xffffUL;
	struct private_context *ctx;

	result_init(result);
	if (service == NULL || slot == 0UL || slot > GPU_PRIVATE_CONTEXTS ||
	    hardware_slot >= GPU_PRIVATE_AS_SLOTS)
		return;
	ctx = &contexts[slot - 1UL];
	if (ctx->handle != context || ctx->service != service)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (ctx->quarantined || ctx->revoked || ctx->quiesced || ops->activate == NULL || ops->synchronize == NULL ||
	    (slot_owner[hardware_slot] != 0UL && slot_owner[hardware_slot] != context) ||
	    (ctx->activated && ctx->slot != hardware_slot))
		return;
	ctx->activated = true;
	ctx->slot = (unsigned int)hardware_slot;
	slot_owner[hardware_slot] = context;
	if (!ops->activate(context, ops->table_pa(tables[ctx->root]), ctx->slot)) {
		ctx->quarantined = true;
		return;
	}
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = context;
	result->value[1] = hardware_slot;
}

void gpu_private_query(const void *owner, unsigned long context,
		unsigned long iova, struct gpu_private_result *result)
{
	struct private_context *ctx = ctx_lookup(owner, context);

	result_init(result);
	if (ctx == NULL || iova >= ADDRESS_LIMIT)
		return;
	/* No page address disclosure, no data read, and no service-side lookup
	 * based on a guessed owner. Hardware-format walks are tested separately.
	 */
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = ctx->mapped;
	result->value[1] = ctx->quarantined ? 1UL : 0UL;
	result->value[2] = ctx->activated ? 1UL : 0UL;
	result->value[3] = ctx->revoked ? 1UL : 0UL;
}

void gpu_private_mapping_check(const struct gpu_private_ops *ops, const void *owner,
		unsigned long context, unsigned long object, unsigned long offset,
		unsigned long iova, size_t count, unsigned long prot,
		struct gpu_private_result *result)
{
	struct private_context *ctx = ctx_lookup(owner, context);
	struct private_bo *bo = object != 0UL ? bo_lookup(owner, object) : NULL;

	result_init(result);
	if (ops == NULL || ops->table_pa == NULL || ctx == NULL ||
	    !range_valid(iova, count) || iova >= GPU_PRIVATE_CONTROL_GPU_VA ||
	    count > (GPU_PRIVATE_CONTROL_GPU_VA - iova) / GPU_PRIVATE_PAGE_SIZE)
		return;
	if (object == 0UL) {
		if ((offset | prot) != 0UL)
			return;
	} else if (bo == NULL || bo->control || bo->closing || bo->service != ctx->service ||
		bo->registered != bo->pages || (offset & PAGE_MASK) != 0UL ||
		offset / GPU_PRIVATE_PAGE_SIZE >= bo->pages ||
		count > bo->pages - offset / GPU_PRIVATE_PAGE_SIZE ||
		(prot & GPU_PRIVATE_READ) == 0UL ||
		(prot & ~(GPU_PRIVATE_ACCESS | GPU_PRIVATE_CACHE)) != 0UL ||
		(prot & GPU_PRIVATE_ACCESS & ~bo->access) != 0UL) {
		return;
	}
	result->status = GPU_PRIVATE_STATE;
	if (ctx->quarantined || ctx->revoked || table_owner[ctx->root] != context)
		return;
	for (size_t i = 0U; i < count; i++) {
		unsigned long va = iova + i * GPU_PRIVATE_PAGE_SIZE;
		unsigned int table = ctx->root;
		uint64_t pte = 0UL, expected;
		unsigned int tag = 0U;

		/* Unlike a failed allocation walk, an invalid non-leaf descriptor
		 * must not be mistaken for proof that a range is unmapped.
		 */
		for (unsigned int level = 0U; level < 3U; level++) {
			pte = tables[table][(va >> (39U - level * 9U)) & 511UL];
			if (pte == 0UL)
				break;
			table = table_index(ops, context, pte);
			if (table == GPU_PRIVATE_TABLES)
				return;
			if (level == 2U) {
				pte = tables[table][(va >> 12U) & 511UL];
				tag = leaf_object[table][(va >> 12U) & 511UL];
			}
		}
		if (object == 0UL) {
			if (pte != 0UL || tag != 0U)
				return;
			continue;
		}
		expected = ((uint64_t)bo_page(bo, offset / GPU_PRIVATE_PAGE_SIZE + i)->pa_page << 12U) |
			PTE_TABLE | PTE_AF | PTE_NG | PTE_USER;
		if ((prot & GPU_PRIVATE_WRITE) == 0UL)
			expected |= PTE_RO;
		if ((prot & GPU_PRIVATE_EXEC) == 0UL)
			expected |= PTE_XN;
		expected |= (prot & GPU_PRIVATE_CACHE) != 0UL ? (3UL << 8U) | (1UL << 2U) : 2UL << 8U;
		if (pte != expected || tag != (unsigned int)(bo - objects + 1))
			return;
	}
	/* Metadata only: no page-table address or Client data leaves the RMM.
	 * The caller compares epochs across batches to reject torn observations.
	 * This proves a mapping snapshot, never a GPU task's completion.
	 */
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = count * GPU_PRIVATE_PAGE_SIZE;
	result->value[1] = ctx->mapping_epoch;
}

/* A hint is writable data, never an executable Client trampoline or a hidden
 * firmware/control page. Validate the actual leaf and physical backing as
 * well as both endpoint identities. The caller holds the common policy gate;
 * original-command staging then freezes this context before publication.
 */
bool gpu_private_task_hint_check(const struct gpu_private_ops *ops, const void *service,
		const void *owner, unsigned long context, unsigned long iova)
{
	struct private_context *ctx = ctx_lookup(owner, context);
	struct gpu_private_result checked;
	unsigned int table, tag;
	struct private_bo *bo;

	if (ops == NULL || ops->table_pa == NULL || service == NULL || owner == service ||
	    ctx == NULL || ctx->service != service || ctx->quarantined || ctx->revoked ||
	    ctx->group_refs == 0U || (iova & PAGE_MASK) != 0UL || iova == 0UL ||
	    iova >= GPU_PRIVATE_CONTROL_GPU_VA)
		return false;
	table = walk(ops, ctx, iova, NULL);
	if (table == GPU_PRIVATE_TABLES)
		return false;
	tag = leaf_object[table][(iova >> 12U) & 511UL];
	if (tag == 0U || tag > GPU_PRIVATE_OBJECTS)
		return false;
	bo = &objects[tag - 1U];
	if (bo->owner != owner || bo->service != service || bo->control || bo->resident ||
	    bo->closing || !bo->uncached || bo->pages != 1U || bo->registered != 1U ||
	    bo->hidden != 1U || bo->pending != 0U)
		return false;
	gpu_private_mapping_check(ops, owner, context, bo->handle, 0UL, iova, 1U,
		GPU_PRIVATE_READ | GPU_PRIVATE_WRITE, &checked);
	return checked.status == GPU_PRIVATE_SUCCESS;
}

void gpu_private_device_revoked(const struct gpu_private_ops *ops)
{
	/* Reset completion alone is insufficient: an untrusted service with
	 * writable roots/doorbells could reinstall an old root immediately.
	 * The adapter calls this only after the RELEASE path has revoked MMIO
	 * and verified reset while holding the common ownership policy gate.
	 */
	memset(cache_sets, 0, sizeof(cache_sets));
	for (unsigned int i = 0U; i < GPU_PRIVATE_MAP_GRANTS; i++)
		if (map_grants[i].handle != 0UL)
			grant_forget(&map_grants[i]);
	for (unsigned int i = 0U; i < GPU_PRIVATE_TABLES; i++) {
		unsigned long handle = table_owner[i];
		struct private_context *ctx;

		if (handle == 0UL)
			continue;
		ctx = &contexts[(handle & 0xffffUL) - 1UL];
		assert(ctx->handle == handle);
		for (unsigned int j = 0U; j < ENTRIES; j++) {
			unsigned int object = leaf_object[i][j];
			struct private_bo *bo;

			if (object == 0U)
				continue;
			assert(object <= GPU_PRIVATE_OBJECTS);
			bo = &objects[object - 1U];
			assert(ctx->mapped != 0U);
			if (bo->control) {
				assert(bo->owner == ctx->service && bo->control_gpu_refs != 0U);
				{
					cache_metadata_invalidate();
					bo->control_gpu_refs--;
				}
			} else {
				assert(bo->owner == ctx->owner && bo->mapped != 0U);
				{
					cache_metadata_invalidate();
					bo->mapped--;
				}
			}
			ctx->mapped--;
		}
		memset(leaf_object[i], 0, sizeof(leaf_object[i]));
		leaf_groups[i] = 0U;
		memset(tables[i], 0, sizeof(tables[i]));
		ops->clean(tables[i], sizeof(tables[i]));
	}
	for (unsigned int i = 0U; i < GPU_PRIVATE_CONTEXTS; i++) {
		struct private_context *ctx = &contexts[i];

		if (ctx->handle == 0UL)
			continue;
		assert(ctx->mapped == 0U);
		ctx->activated = false;
		ctx->quarantined = false;
		ctx->revoked = true;
		ctx->group_refs = 0U;
		ctx->task_refs = 0U;
		ctx->live_prepared = false;
		ctx->quiesced = false;
		ctx->drained = false;
		ctx->cache_task = 0UL;
		ctx->cache_groups = 0U;
		ctx->cache_cursor = ctx->cache_pages = 0U;
		ctx->return_cursor = ctx->return_pages = 0U;
		if (ctx->extension_object != 0UL) {
			struct private_bo *bo = bo_lookup(ctx->owner, ctx->extension_object);

			assert(bo != NULL && bo->pending != 0U);
			bo->pending--;
			ctx->extension_object = ctx->extension_va = 0UL;
			ctx->extension_cursor = 0U;
		}
	}
	memset(slot_owner, 0, sizeof(slot_owner));
	/* Trusted whole-device reset also retires AS0's donated arena. CPU
	 * mappings remain hidden until CONTROL_DESTROY scrubs and restores them.
	 */
	for (unsigned int i = 0U; i < GPU_PRIVATE_OBJECTS; i++) {
		{
			cache_metadata_invalidate();
			objects[i].cache_context = 0UL;
		}
		if (objects[i].control) {
			assert(objects[i].control_gpu_refs == 0U);
			{
				cache_metadata_invalidate();
				objects[i].mapped = 0U;
			}
		}
	}
}

void gpu_private_bo_inspect(const void *service, const void *owner,
		unsigned long object, struct gpu_private_result *result)
{
	struct private_bo *bo = bo_lookup(owner, object);

	result_init(result);
	if (service == NULL || bo == NULL || bo->control || bo->service != service)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (bo->closing || bo->registered != bo->pages)
		return;
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = (unsigned long)bo->pages * GPU_PRIVATE_PAGE_SIZE;
	result->value[1] = bo->access;
	result->value[2] = bo->registered;
	result->value[3] = bo->mapped;
}

void gpu_private_context_inspect(const void *service, const void *owner,
		unsigned long context, struct gpu_private_result *result)
{
	struct private_context *ctx = ctx_lookup(owner, context);

	result_init(result);
	if (service == NULL || ctx == NULL || ctx->service != service)
		return;
	gpu_private_query(owner, context, 0UL, result);
}

void gpu_private_service_map(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long authorization, unsigned long offset, unsigned long iova,
		size_t count, unsigned long prot, struct gpu_private_result *result)
{
	struct private_context *ctx = ctx_lookup(owner, context);
	struct private_map_grant *grant = grant_lookup(owner, authorization);

	result_init(result);
	if (service == NULL || ctx == NULL || ctx->service != service || grant == NULL ||
	    grant->context != context || count == 0U || count > GPU_PRIVATE_BATCH ||
	    count > grant->count - grant->progress || grant->prot != prot ||
	    offset != grant->offset + grant->progress * GPU_PRIVATE_PAGE_SIZE ||
	    iova != grant->iova + grant->progress * GPU_PRIVATE_PAGE_SIZE)
		return;
	gpu_private_map(ops, owner, context, grant->object, offset, iova, count, prot, result);
	if (result->status == GPU_PRIVATE_SUCCESS) {
		grant->progress += count;
		if (grant->progress == grant->count)
			grant_forget(grant);
	}
}

void gpu_private_map_authorize(const void *owner, unsigned long context,
		unsigned long object, unsigned long offset, unsigned long iova,
		size_t count, unsigned long prot, struct gpu_private_result *result)
{
	struct private_context *ctx = ctx_lookup(owner, context);
	struct private_bo *bo = bo_lookup(owner, object);

	result_init(result);
	if (ctx == NULL || bo == NULL || bo->control || ctx->service != bo->service || bo->closing ||
	    bo->registered != bo->pages || count == 0U ||
	    ((bo->resident || bo->uncached) && bo->hidden != bo->pages) ||
	    ((offset | iova) & PAGE_MASK) != 0UL || iova >= ADDRESS_LIMIT ||
	    count > (ADDRESS_LIMIT - iova) / GPU_PRIVATE_PAGE_SIZE ||
	    iova >= GPU_PRIVATE_CONTROL_GPU_VA ||
	    count > (GPU_PRIVATE_CONTROL_GPU_VA - iova) / GPU_PRIVATE_PAGE_SIZE ||
	    offset / GPU_PRIVATE_PAGE_SIZE >= bo->pages ||
	    count > bo->pages - offset / GPU_PRIVATE_PAGE_SIZE ||
	    (prot & GPU_PRIVATE_READ) == 0UL ||
	    (prot & ~(GPU_PRIVATE_ACCESS | GPU_PRIVATE_CACHE)) != 0UL ||
	    (prot & GPU_PRIVATE_ACCESS & ~bo->access) != 0UL)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (ctx->quarantined || ctx->revoked)
		return;
	result->status = GPU_PRIVATE_FULL;
	if (ctx->pending >= GPU_PRIVATE_CONTEXT_GRANTS)
		return;
	for (unsigned int i = 0U; i < GPU_PRIVATE_MAP_GRANTS; i++) {
		struct private_map_grant *grant = &map_grants[i];
		unsigned long handle;

		if (grant->handle != 0UL)
			continue;
		handle = new_handle(MAP_PREFIX, i);
		if (handle == 0UL)
			return;
		*grant = (struct private_map_grant) {
			.owner = owner, .handle = handle, .context = context, .object = object,
			.offset = offset, .iova = iova, .prot = prot, .count = count
		};
		bo->pending++;
		ctx->pending++;
		result->status = GPU_PRIVATE_SUCCESS;
		result->value[0] = handle;
		return;
	}
}

void gpu_private_map_cancel(const void *owner, unsigned long authorization,
		struct gpu_private_result *result)
{
	struct private_map_grant *grant = grant_lookup(owner, authorization);

	result_init(result);
	if (grant == NULL)
		return;
	grant_forget(grant);
	result->status = GPU_PRIVATE_SUCCESS;
}

void gpu_private_service_map_release(const void *service, const void *owner,
		unsigned long context, unsigned long authorization,
		struct gpu_private_result *result)
{
	struct private_context *ctx = ctx_lookup(owner, context);
	struct private_map_grant *grant = grant_lookup(owner, authorization);

	result_init(result);
	if (service == NULL || ctx == NULL || ctx->service != service || grant == NULL ||
	    grant->context != context)
		return;
	grant_forget(grant);
	result->status = GPU_PRIVATE_SUCCESS;
}

void gpu_private_service_unmap(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long iova, size_t count, struct gpu_private_result *result)
{
	struct private_context *ctx = ctx_lookup(owner, context);

	result_init(result);
	if (service == NULL || ctx == NULL || ctx->service != service)
		return;
	gpu_private_unmap(ops, owner, context, iova, count, result);
}

void gpu_private_owner_reclaim(const struct gpu_private_ops *ops,
		const void *owner, struct gpu_private_result *result)
{
	result_init(result);
	if (owner == NULL || ops == NULL || ops->clean == NULL ||
	    ops->clear_page == NULL || ops->restore_page == NULL)
		return;
	result->status = GPU_PRIVATE_STATE;
	/* Refuse the entire request before mutating anything unless all related
	 * contexts have been retired by the trusted device-revocation path.
	 */
	for (unsigned int i = 0U; i < GPU_PRIVATE_CONTEXTS; i++) {
		struct private_context *ctx = &contexts[i];

		if (ctx->handle != 0UL && (ctx->owner == owner || ctx->service == owner) &&
		    (!ctx->revoked || ctx->activated || ctx->quarantined ||
		     ctx->mapped != 0U || ctx->pending != 0U || ctx->group_refs != 0U ||
		     ctx->task_refs != 0U || ctx->cache_task != 0UL))
			return;
	}
	for (unsigned int i = 0U; i < GPU_PRIVATE_OBJECTS; i++) {
		struct private_bo *bo = &objects[i];

		if (bo->handle != 0UL && (bo->owner == owner || bo->service == owner) &&
		    (bo->mapped != 0U || bo->pending != 0U ||
		     bo->control_gpu_refs != 0U || bo->cache_context != 0UL))
			return;
	}
	for (unsigned int i = 0U; i < GPU_PRIVATE_CONTEXTS; i++) {
		struct private_context *ctx = &contexts[i];

		if (ctx->handle == 0UL)
			continue;
		if (ctx->owner == owner) {
			gpu_private_context_destroy(ops, owner, ctx->handle, result);
			if (result->status != GPU_PRIVATE_SUCCESS)
				return;
		} else if (ctx->service == owner) {
			/* Preserve living Clients' revoked contexts, but do not leave an
			 * RD pointer that could authenticate a later Realm at this address.
			 */
			ctx->service = NULL;
		}
	}
	for (unsigned int i = 0U; i < GPU_PRIVATE_OBJECTS; i++) {
		if (objects[i].handle != 0UL && objects[i].owner != owner &&
		    objects[i].service == owner)
			{
				cache_metadata_invalidate();
				objects[i].service = NULL;
			}
	}
	for (unsigned int i = 0U; i < GPU_PRIVATE_OBJECTS; i++) {
		struct private_bo *bo = &objects[i];

		if (bo->handle == 0UL || bo->owner != owner)
			continue;
		/* bo_destroy keeps registration on scrub/RTT-restore failure and
		 * clears donated pages before restoring their original CPU mapping.
		 * Ordinary dead-Client data stays delegated until RMI_DATA_DESTROY.
		 */
		bo_destroy(ops, owner, bo->handle, bo->control, result);
		if (result->status != GPU_PRIVATE_SUCCESS)
			return;
		break;
	}
	result_init(result);
	result->status = gpu_private_owner_busy(owner) ?
		GPU_PRIVATE_INCOMPLETE : GPU_PRIVATE_SUCCESS;
}

bool gpu_private_raw_access_blocked(void)
{
	/* A replacement raw service must not DMA through orphaned Client
	 * registrations after its former service RD has been safely detached.
	 */
	for (unsigned int i = 0U; i < GPU_PRIVATE_OBJECTS; i++)
		if (objects[i].handle != 0UL)
			return true;
	for (unsigned int i = 0U; i < GPU_PRIVATE_CONTEXTS; i++)
		if (contexts[i].handle != 0UL)
			return true;
	return false;
}

bool gpu_private_owner_busy(const void *owner)
{
	if (owner == NULL)
		return false;
	for (unsigned int i = 0U; i < GPU_PRIVATE_OBJECTS; i++) {
		if (objects[i].handle != 0UL &&
		    (objects[i].owner == owner || objects[i].service == owner))
			return true;
	}
	for (unsigned int i = 0U; i < GPU_PRIVATE_CONTEXTS; i++) {
		if (contexts[i].handle != 0UL &&
		    (contexts[i].owner == owner || contexts[i].service == owner))
			return true;
	}
	return false;
}

bool gpu_private_range_busy(const void *owner, unsigned long ipa, unsigned long size)
{
	if (owner == NULL || size == 0UL)
		return false;
	for (unsigned int i = 0U; i < GPU_PRIVATE_OBJECTS; i++) {
		struct private_bo *bo = &objects[i];

		if (bo->handle == 0UL || bo->owner != owner || bo->registered == 0U)
			continue;
		if (ipa > bo->max_ipa && ipa - bo->max_ipa >= GPU_PRIVATE_PAGE_SIZE)
			continue;
		if (ipa <= bo->min_ipa && bo->min_ipa - ipa >= size)
			continue;
		for (unsigned int index = 0U; index < bo->registered; index++) {
			unsigned long page = (unsigned long)bo_page(bo, index)->ipa_page << 12U;

			if (page >= ipa ? page - ipa < size : ipa - page < GPU_PRIVATE_PAGE_SIZE)
				return true;
		}
	}
	return false;
}
