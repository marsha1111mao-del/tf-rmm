/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <limits.h>
#include <opencca_gpu_lease.h>
#include <stdio.h>

#define PAGE 4096UL
static const unsigned char owner;

int main(void)
{
	unsigned long pa = 0x80000000UL, page, mixed[2];

	assert(opencca_gpu_control(NULL, NULL, OPENCCA_GPU_POWER_ON, 0UL, 0UL));
	assert(opencca_gpu_mmio_grant(&owner));
	assert(opencca_gpu_claim(&owner));
	/* Neither an already active GPU page nor a larger covering DMA mapping
	 * may be admitted. Failed admission must not leave a reservation.
	 */
	page = pa + PAGE;
	assert(opencca_gpu_lease_acquire(&owner, &page, 1U));
	assert(!opencca_dma_map_acquire(1UL, PAGE, page, PAGE));
	assert(!opencca_dma_map_acquire(2UL, 0UL, pa, 2UL * PAGE));
	assert(opencca_dma_map_active() == 0U);
	assert(opencca_gpu_lease_release_owner(&owner) == 1U);

	/* Admission is bidirectional, including rollback of a GPU batch whose
	 * first page is free but second page is reserved for another device.
	 */
	assert(opencca_dma_map_acquire(1UL, 0UL, pa + PAGE, 3UL * PAGE));
	mixed[0] = pa;
	mixed[1] = pa + PAGE;
	assert(!opencca_gpu_lease_acquire(&owner, mixed, 2U));
	assert(opencca_gpu_lease_active() == 0U);
	assert(!opencca_dma_map_acquire(1UL, PAGE, pa + 10UL * PAGE, PAGE));
	assert(!opencca_dma_map_release(2UL, 0UL, 3UL * PAGE));

	/* A middle unmap splits the physical reservation. The still-mapped
	 * edges remain protected against GPU admission.
	 */
	assert(opencca_dma_map_release(1UL, PAGE, PAGE));
	page = pa + 2UL * PAGE;
	assert(opencca_gpu_lease_acquire(&owner, &page, 1U));
	page = pa + PAGE;
	assert(!opencca_gpu_lease_acquire(&owner, &page, 1U));
	page = pa + 3UL * PAGE;
	assert(!opencca_gpu_lease_acquire(&owner, &page, 1U));
	assert(opencca_dma_map_active() == 2U);
	/* An unmap containing a hole must fail atomically. */
	assert(!opencca_dma_map_release(1UL, 0UL, 3UL * PAGE));
	assert(opencca_dma_map_active() == 2U);
	assert(opencca_dma_map_release(1UL, 0UL, PAGE));
	assert(opencca_dma_map_release(1UL, 2UL * PAGE, PAGE));
	assert(opencca_gpu_lease_release_owner(&owner) == 1U);

	/* Aliases across devices require independent retirement. */
	assert(opencca_dma_map_acquire(1UL, 0UL, pa, PAGE));
	assert(opencca_dma_map_acquire(2UL, PAGE, pa, PAGE));
	assert(opencca_dma_map_release(1UL, 0UL, PAGE));
	assert(!opencca_gpu_lease_acquire(&owner, &pa, 1U));
	assert(opencca_dma_map_release(2UL, PAGE, PAGE));
	assert(opencca_gpu_lease_acquire(&owner, &pa, 1U));
	assert(opencca_gpu_lease_release_owner(&owner) == 1U);

	assert(!opencca_dma_map_acquire(0UL, 0UL, pa, PAGE));
	assert(!opencca_dma_map_acquire(1UL, 1UL, pa, PAGE));
	assert(!opencca_dma_map_acquire(1UL, 0UL, pa + 1UL, PAGE));
	assert(!opencca_dma_map_acquire(1UL, 0UL, pa, 0UL));
	assert(!opencca_dma_map_acquire(1UL, 0UL, pa, PAGE + 1UL));
	assert(!opencca_dma_map_acquire(1UL, ULONG_MAX - PAGE + 1UL, pa, PAGE));
	assert(!opencca_dma_map_acquire(1UL, 0UL, ULONG_MAX - PAGE + 1UL, PAGE));
	assert(!opencca_dma_map_release(1UL, 0UL, 0UL));
	assert(opencca_dma_map_overlaps(ULONG_MAX - PAGE + 1UL, PAGE));

	/* Adjacent registrations can be retired by a single unmap. */
	for (unsigned long i = 0UL; i < 8UL; i++)
		assert(opencca_dma_map_acquire(1UL, i * PAGE, pa + i * PAGE, PAGE));
	assert(opencca_dma_map_release(1UL, 0UL, 8UL * PAGE));
	assert(opencca_dma_map_active() == 0U);

	/* Capacity exhaustion and split failure are fail-closed. */
	assert(opencca_dma_map_acquire(1UL, 0UL, pa, 3UL * PAGE));
	for (unsigned long i = 1UL; i < OPENCCA_DMA_MAP_CAPACITY; i++)
		assert(opencca_dma_map_acquire(i + 1UL, 0UL,
			pa + (i + 3UL) * PAGE, PAGE));
	assert(!opencca_dma_map_acquire(OPENCCA_DMA_MAP_CAPACITY + 1UL,
		0UL, pa + (OPENCCA_DMA_MAP_CAPACITY + 3UL) * PAGE, PAGE));
	assert(!opencca_dma_map_release(1UL, PAGE, PAGE));
	page = pa + PAGE;
	assert(!opencca_gpu_lease_acquire(&owner, &page, 1U));
	assert(opencca_dma_map_release(1UL, 0UL, 3UL * PAGE));
	for (unsigned long i = 1UL; i < OPENCCA_DMA_MAP_CAPACITY; i++)
		assert(opencca_dma_map_release(i + 1UL, 0UL, PAGE));
	assert(opencca_dma_map_active() == 0U);
	assert(opencca_gpu_lease_active() == 0U);
	puts("DMA guard: GPU/DMA exclusion, rollback, aliases, partial unmap, "
	     "range validation, capacity, reuse PASS");
	return 0;
}
