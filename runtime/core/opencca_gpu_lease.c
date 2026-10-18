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

	if ((hpa & PAGE_MASK) != 0UL)
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
	}
	return released;
}

unsigned int opencca_gpu_lease_active(void)
{
	return active;
}
