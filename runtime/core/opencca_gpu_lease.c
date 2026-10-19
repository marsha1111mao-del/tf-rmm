/* SPDX-License-Identifier: BSD-3-Clause */
#include <limits.h>
#include <opencca_gpu_lease.h>
#include <stdint.h>

#define BUCKET_BITS 15U
#define BUCKET_COUNT (1U << BUCKET_BITS)
#define PAGE_MASK 4095UL

struct gpu_lease {
	const void *owner;
	unsigned long hpa;
	unsigned int next;
	unsigned short refs;
};

/* Links are index + 1, with zero denoting an empty bucket/free list. */
static struct gpu_lease leases[OPENCCA_GPU_LEASE_CAPACITY];
static unsigned int buckets[BUCKET_COUNT];
static unsigned int free_head;
static unsigned int active;
static bool initialized;

struct dma_mapping {
	unsigned long domain;
	unsigned long iova;
	unsigned long pa;
	unsigned long size;
};

static struct dma_mapping dma_maps[OPENCCA_DMA_MAP_CAPACITY];
static unsigned int dma_active;
static bool valid_range(unsigned long base, unsigned long size)
{
	return size != 0UL && ((base | size) & PAGE_MASK) == 0UL &&
	       size <= ULONG_MAX - base;
}

static bool overlaps(unsigned long a, unsigned long asize,
		     unsigned long b, unsigned long bsize)
{
	return a < b + bsize && b < a + asize;
}

bool opencca_dma_map_overlaps(unsigned long pa, unsigned long size)
{
	if (!valid_range(pa, size))
		return true;
	if (dma_active == 0U)
		return false;
	for (unsigned int i = 0U; i < OPENCCA_DMA_MAP_CAPACITY; i++) {
		const struct dma_mapping *map = &dma_maps[i];

		if (map->size != 0UL && overlaps(pa, size, map->pa, map->size))
			return true;
	}
	return false;
}

static unsigned int bucket_for(unsigned long hpa)
{
	uint64_t key = (uint64_t)(hpa >> 12U) * UINT64_C(0x9e3779b97f4a7c15);

	return (unsigned int)(key >> (64U - BUCKET_BITS));
}

static void init(void)
{
	if (initialized)
		return;
	for (unsigned int i = 0U; i < OPENCCA_GPU_LEASE_CAPACITY; i++)
		leases[i].next = i + 2U;
	leases[OPENCCA_GPU_LEASE_CAPACITY - 1U].next = 0U;
	free_head = 1U;
	initialized = true;
}

static bool acquire_one(const void *owner, unsigned long hpa)
{
	unsigned int bucket = bucket_for(hpa);
	struct gpu_lease *lease;
	unsigned int slot;

	if (!valid_range(hpa, PAGE_MASK + 1UL) ||
	    opencca_dma_map_overlaps(hpa, PAGE_MASK + 1UL))
		return false;
	for (slot = buckets[bucket]; slot != 0U; slot = lease->next) {
		lease = &leases[slot - 1U];
		if (lease->hpa != hpa)
			continue;
		if (lease->owner != owner || lease->refs == USHRT_MAX)
			return false;
		lease->refs++;
		return true;
	}
	if (free_head == 0U)
		return false;
	slot = free_head;
	lease = &leases[slot - 1U];
	free_head = lease->next;
	lease->owner = owner;
	lease->hpa = hpa;
	lease->refs = 1U;
	lease->next = buckets[bucket];
	buckets[bucket] = slot;
	active++;
	return true;
}

static void clear(unsigned int *link)
{
	unsigned int slot = *link;
	struct gpu_lease *lease = &leases[slot - 1U];

	*link = lease->next;
	lease->owner = NULL;
	lease->hpa = 0UL;
	lease->refs = 0U;
	lease->next = free_head;
	free_head = slot;
	active--;
}

static void release_one(const void *owner, unsigned long hpa)
{
	unsigned int *link = &buckets[bucket_for(hpa)];

	while (*link != 0U) {
		struct gpu_lease *lease = &leases[*link - 1U];

		if (lease->hpa == hpa && lease->owner == owner) {
			if (--lease->refs == 0U)
				clear(link);
			return;
		}
		link = &lease->next;
	}
}

bool opencca_gpu_lease_acquire(const void *owner, const unsigned long *hpas,
			       size_t count)
{
	size_t i;

	if (owner == NULL || hpas == NULL || count == 0U ||
	    count > OPENCCA_GPU_LEASE_BATCH)
		return false;
	init();
	if (!opencca_gpu_mmio_running(owner))
		return false;
	for (i = 0U; i < count; i++) {
		if (!acquire_one(owner, hpas[i])) {
			/* Includes references added to already-present pages. */
			while (i != 0U)
				release_one(owner, hpas[--i]);
			return false;
		}
	}
	return true;
}

void opencca_gpu_lease_release(const void *owner, const unsigned long *hpas,
			      size_t count)
{
	if (owner == NULL || hpas == NULL || count > OPENCCA_GPU_LEASE_BATCH)
		return;
	for (size_t i = 0U; i < count; i++)
		release_one(owner, hpas[i]);
}

unsigned int opencca_gpu_lease_release_owner(const void *owner)
{
	unsigned int released = 0U;

	if (active == 0U)
		return 0U;
	for (unsigned int i = 0U; i < BUCKET_COUNT; i++) {
		unsigned int *link = &buckets[i];

		while (*link != 0U) {
			struct gpu_lease *lease = &leases[*link - 1U];

			if (lease->owner == owner) {
				clear(link);
				released++;
			} else {
				link = &lease->next;
			}
		}
		if (active == 0U)
			break;
	}
	return released;
}

unsigned int opencca_gpu_lease_active(void)
{
	return active;
}

bool opencca_gpu_lease_page_busy(unsigned long hpa)
{
	if (!valid_range(hpa, PAGE_MASK + 1UL))
		return true;
	for (unsigned int slot = buckets[bucket_for(hpa)]; slot != 0U;
	     slot = leases[slot - 1U].next) {
		if (leases[slot - 1U].hpa == hpa)
			return true;
	}
	return false;
}

unsigned long opencca_gpu_lease_first(void)
{
	for (unsigned int i = 0U; i < OPENCCA_GPU_LEASE_CAPACITY; i++) {
		if (leases[i].refs != 0U)
			return leases[i].hpa;
	}
	return 0UL;
}

bool opencca_dma_map_acquire(unsigned long domain, unsigned long iova,
			    unsigned long pa, unsigned long size)
{
	unsigned int free_slot = OPENCCA_DMA_MAP_CAPACITY;

	if (domain == 0UL || size > OPENCCA_DMA_MAP_MAX_SIZE ||
	    !valid_range(iova, size) || !valid_range(pa, size))
		return false;
	for (unsigned int i = 0U; i < OPENCCA_DMA_MAP_CAPACITY; i++) {
		const struct dma_mapping *map = &dma_maps[i];

		if (map->size == 0UL) {
			free_slot = i;
			continue;
		}
		if (map->domain == domain &&
		    overlaps(iova, size, map->iova, map->size))
			return false;
	}
	if (free_slot == OPENCCA_DMA_MAP_CAPACITY)
		return false;
	for (unsigned long offset = 0UL; offset < size; offset += 4096UL) {
		if (opencca_gpu_lease_page_busy(pa + offset))
			return false;
	}
	dma_maps[free_slot] = (struct dma_mapping){domain, iova, pa, size};
	dma_active++;
	return true;
}

bool opencca_dma_map_release(unsigned long domain, unsigned long iova,
			    unsigned long size)
{
	unsigned long end, cursor;
	unsigned int free_slot = OPENCCA_DMA_MAP_CAPACITY;
	bool split = false;

	if (domain == 0UL || !valid_range(iova, size))
		return false;
	end = iova + size;
	/* Validate complete coverage before changing anything. Partial unmaps
	 * may cross multiple registrations or split a larger registration.
	 */
	for (cursor = iova; cursor < end;) {
		bool found = false;

		for (unsigned int i = 0U; i < OPENCCA_DMA_MAP_CAPACITY; i++) {
			const struct dma_mapping *map = &dma_maps[i];
			unsigned long map_end = map->iova + map->size;

			if (map->size == 0UL || map->domain != domain ||
			    cursor < map->iova || cursor >= map_end)
				continue;
			split = split || (iova > map->iova && end < map_end);
			cursor = map_end < end ? map_end : end;
			found = true;
			break;
		}
		if (!found)
			return false;
	}
	if (split) {
		for (unsigned int i = 0U; i < OPENCCA_DMA_MAP_CAPACITY; i++) {
			if (dma_maps[i].size == 0UL) {
				free_slot = i;
				break;
			}
		}
		if (free_slot == OPENCCA_DMA_MAP_CAPACITY)
			return false;
	}
	for (unsigned int i = 0U; i < OPENCCA_DMA_MAP_CAPACITY; i++) {
		struct dma_mapping *map = &dma_maps[i];
		unsigned long map_end = map->iova + map->size;

		if (map->size == 0UL || map->domain != domain ||
		    !overlaps(iova, size, map->iova, map->size))
			continue;
		if (iova <= map->iova && end >= map_end) {
			map->size = 0UL;
			dma_active--;
		} else if (iova <= map->iova) {
			map->pa += end - map->iova;
			map->iova = end;
			map->size = map_end - end;
		} else {
			if (end < map_end) {
				dma_maps[free_slot] = (struct dma_mapping){domain,
					end, map->pa + end - map->iova, map_end - end};
				dma_active++;
			}
			map->size = iova - map->iova;
		}
	}
	return true;
}

unsigned int opencca_dma_map_active(void)
{
	return dma_active;
}
