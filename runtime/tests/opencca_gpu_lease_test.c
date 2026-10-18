/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <limits.h>
#include <opencca_gpu_lease.h>
#include <stdio.h>

static const unsigned char owner_a, owner_b;
static unsigned long batch[OPENCCA_GPU_LEASE_BATCH];

int main(void)
{
	unsigned long page = 0x80000000UL;
	unsigned long other = page + 4096UL;
	unsigned long mixed[] = { page, other };

	assert(!opencca_gpu_lease_acquire(NULL, &page, 1U));
	assert(!opencca_gpu_lease_acquire(&owner_a, &page, 0U));
	assert(opencca_gpu_lease_acquire(&owner_b, &other, 1U));
	/* Failure on the second entry rolls back a newly acquired first. */
	assert(!opencca_gpu_lease_acquire(&owner_a, mixed, 2U));
	assert(opencca_gpu_lease_active() == 1U);
	assert(opencca_gpu_lease_acquire(&owner_a, &page, 1U));
	assert(!opencca_gpu_lease_acquire(&owner_b, &page, 1U));
	opencca_gpu_lease_release(&owner_b, &page, 1U);
	/* Same failure must also roll back a reference to an existing page. */
	assert(!opencca_gpu_lease_acquire(&owner_a, mixed, 2U));
	opencca_gpu_lease_release(&owner_a, &page, 1U);
	assert(opencca_gpu_lease_active() == 1U);
	assert(opencca_gpu_lease_release_owner(&owner_b) == 1U);

	for (unsigned int n = 0U; n < USHRT_MAX; n++)
		assert(opencca_gpu_lease_acquire(&owner_a, &page, 1U));
	assert(!opencca_gpu_lease_acquire(&owner_a, &page, 1U));
	opencca_gpu_lease_release(&owner_a, &page, 1U);
	mixed[0] = page;
	mixed[1] = page;
	assert(!opencca_gpu_lease_acquire(&owner_a, mixed, 2U));
	for (unsigned int n = 0U; n < USHRT_MAX - 1U; n++)
		opencca_gpu_lease_release(&owner_a, &page, 1U);
	assert(opencca_gpu_lease_active() == 0U);

	/* Exercise 16 times the old 8192-entry ceiling and every hash chain. */
	for (unsigned int start = 0U; start < OPENCCA_GPU_LEASE_CAPACITY;
	     start += OPENCCA_GPU_LEASE_BATCH) {
		for (unsigned int i = 0U; i < OPENCCA_GPU_LEASE_BATCH; i++)
			batch[i] = page + (unsigned long)(start + i) * 4096UL;
		assert(opencca_gpu_lease_acquire(&owner_a, batch,
					       OPENCCA_GPU_LEASE_BATCH));
	}
	assert(opencca_gpu_lease_active() == OPENCCA_GPU_LEASE_CAPACITY);
	other = page + (unsigned long)OPENCCA_GPU_LEASE_CAPACITY * 4096UL;
	mixed[0] = page;
	mixed[1] = other;
	assert(!opencca_gpu_lease_acquire(&owner_a, mixed, 2U));
	opencca_gpu_lease_release(&owner_a, &page, 1U);
	assert(opencca_gpu_lease_active() == OPENCCA_GPU_LEASE_CAPACITY - 1U);
	assert(opencca_gpu_lease_acquire(&owner_b, &other, 1U));
	assert(opencca_gpu_lease_release_owner(&owner_a) ==
	       OPENCCA_GPU_LEASE_CAPACITY - 1U);
	assert(opencca_gpu_lease_active() == 1U);
	assert(!opencca_gpu_lease_acquire(&owner_a, &other, 1U));
	assert(opencca_gpu_lease_release_owner(&owner_b) == 1U);
	/* Recycled slots/bucket links remain usable after full teardown. */
	assert(opencca_gpu_lease_acquire(&owner_a, &page, 1U));
	assert(opencca_gpu_lease_release_owner(&owner_a) == 1U);
	assert(opencca_gpu_lease_active() == 0U);
	puts("GPU lease index: capacity, ownership, refcount, rollback, reuse PASS");
	return 0;
}
