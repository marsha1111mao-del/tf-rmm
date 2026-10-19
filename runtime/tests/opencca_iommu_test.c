/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <opencca_gpu_lease.h>
#include <opencca_iommu.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PAGE 4096UL
#define TABLE_BASE 0x200000UL
#define DEVICE 0xfdb50800UL
static const unsigned char realm_a, realm_b;
static uintptr_t pool_va;
static unsigned long device_root;
static bool device_bound, invalidated, fail_device;
static bool check_retirement;
static unsigned int device_events, clean_events;
static unsigned int fault_events;
static bool fail_fault;
static unsigned long fault_flags = 1UL | OPENCCA_IOMMU_FAULT_WRITE;

static unsigned long table_pa(const void *table)
{
	if (pool_va == 0U)
		pool_va = (uintptr_t)table - PAGE; /* First allocation is page 1. */
	return TABLE_BASE + (unsigned long)((uintptr_t)table - pool_va);
}

static uint32_t *table_at(unsigned long pa)
{
	assert(pa >= TABLE_BASE && pa < TABLE_BASE + OPENCCA_IOMMU_TABLE_PAGES * PAGE);
	return (uint32_t *)(pool_va + pa - TABLE_BASE);
}

static void clean(const void *table, size_t bytes)
{
	(void)table;
	assert(bytes == PAGE);
	clean_events++;
}

static bool reserve(unsigned long handle, unsigned long iova,
		    unsigned long pa, unsigned long size)
{
	return opencca_dma_map_acquire(handle, iova, pa, size);
}

static bool retire(unsigned long handle, unsigned long iova, unsigned long size)
{
	if (check_retirement)
		assert(invalidated);
	return opencca_dma_map_release(handle, iova, size);
}

static bool valid_device(unsigned long device)
{
	return device == DEVICE;
}

static bool device(unsigned long id, unsigned long root,
		   enum opencca_iommu_device_command command)
{
	assert(id == DEVICE);
	device_events++;
	if (fail_device && command == OPENCCA_IOMMU_DEVICE_INVALIDATE)
		return false;
	switch (command) {
	case OPENCCA_IOMMU_DEVICE_BIND:
		device_root = root;
		device_bound = true;
		break;
	case OPENCCA_IOMMU_DEVICE_STALL:
		assert(root == device_root);
		invalidated = false;
		break;
	case OPENCCA_IOMMU_DEVICE_INVALIDATE:
		assert(root == device_root);
		invalidated = true;
		break;
	case OPENCCA_IOMMU_DEVICE_RESUME:
		assert(root == device_root);
		break;
	case OPENCCA_IOMMU_DEVICE_PARK:
		assert(table_at(root)[0] == 0U);
		device_bound = false;
		device_root = root;
		break;
	}
	return true;
}

static bool fault(unsigned long id, unsigned long root,
		  struct opencca_iommu_result *result)
{
	assert(id == DEVICE && root == device_root);
	fault_events++;
	if (fail_fault)
		return false;
	result->value[0] = fault_flags;
	result->value[1] = 0x12345000UL;
	return true;
}

static const struct opencca_iommu_ops ops = {
	.table_pa = table_pa,
	.clean = clean,
	.reserve = reserve,
	.retire = retire,
	.device_valid = valid_device,
	.device = device,
	.fault = fault
};

static struct opencca_iommu_result call(const void *owner, unsigned long op,
		unsigned long handle, unsigned long a, unsigned long b, unsigned long c)
{
	struct opencca_iommu_result result;

	opencca_iommu_call(&ops, owner, op, handle, a, b, c, &result);
	return result;
}

static unsigned long create(const void *owner)
{
	struct opencca_iommu_result result = call(owner, OPENCCA_IOMMU_CREATE, 0UL, 0UL, 0UL, 0UL);

	assert(result.status == OPENCCA_IOMMU_SUCCESS);
	assert(opencca_iommu_secure_handle(result.value[0]));
	assert((result.value[1] & 4095UL) == 0UL);
	return result.value[0];
}

static struct opencca_iommu_result map(const void *owner, unsigned long handle,
		unsigned long iova, const unsigned long *pages, size_t count,
		unsigned long prot, unsigned long ipa)
{
	struct opencca_iommu_result result;

	opencca_iommu_map(&ops, owner, handle, iova, pages, count, prot, ipa, &result);
	return result;
}

static void remove_all(const void *owner, unsigned long handle, unsigned long iova,
		       unsigned long size)
{
	struct opencca_iommu_result result = call(owner, OPENCCA_IOMMU_UNMAP,
						handle, iova, 0UL, size);

	assert(result.status == OPENCCA_IOMMU_SUCCESS && result.value[0] == size);
}

static void check_fault(const void *owner, unsigned long handle,
			unsigned long effective, bool guest)
{
	struct opencca_iommu_result result = call(owner, OPENCCA_IOMMU_FAULT,
						handle, DEVICE, 0UL, 0UL);

	assert(result.status == OPENCCA_IOMMU_SUCCESS);
	assert(result.value[0] == (fault_flags | (guest ? OPENCCA_IOMMU_FAULT_GUEST : 0UL)));
	assert(result.value[1] == 0x12345000UL && result.value[3] == effective);
}

int main(int argc, char **argv)
{
	unsigned long host = create(NULL), guest = create(&realm_a);
	unsigned long pa = 0x1287654000UL, ipa = 0x88000000UL;
	unsigned long pages[] = {pa, pa + PAGE, pa + 3UL * PAGE};
	struct opencca_iommu_result result;
	unsigned long stale;
	unsigned int before;
	bool guest_fault_failure = argc == 2 && strcmp(argv[1], "--guest-fault-failure") == 0;
	bool fault_failure = guest_fault_failure ||
		(argc == 2 && strcmp(argv[1], "--fault-failure") == 0);

	assert(argc == 1 || fault_failure);

	assert(opencca_gpu_control(NULL, NULL, OPENCCA_GPU_POWER_ON, 0UL, 0UL));
	assert(opencca_gpu_mmio_grant(&realm_a));
	assert(opencca_gpu_claim(&realm_a));
	result = call(NULL, OPENCCA_IOMMU_VERSION, 0UL, 0UL, 0UL, 0UL);
	assert(result.status == 0UL && result.value[0] == OPENCCA_IOMMU_ABI);
	assert(call(&realm_b, OPENCCA_IOMMU_QUERY, guest, 0UL, 0UL, 0UL).status != 0UL);
	assert(call(NULL, OPENCCA_IOMMU_DESTROY, guest, 0UL, 0UL, 0UL).status != 0UL);
	assert(map(NULL, guest, 0UL, pages, 1U, 3UL, 0UL).status != 0UL);
	before = device_events;
	assert(call(&realm_a, OPENCCA_IOMMU_BIND, guest, DEVICE, 0UL, 0UL).status == OPENCCA_IOMMU_STATE);
	assert(call(&realm_a, OPENCCA_IOMMU_GRANT, 0UL, DEVICE, guest, 0UL).status != 0UL);
	assert(call(NULL, OPENCCA_IOMMU_GRANT, 0UL, DEVICE, guest, 0UL).status == OPENCCA_IOMMU_STATE);
	assert(device_events == before);
	before = fault_events;
	assert(call(NULL, OPENCCA_IOMMU_FAULT, host, DEVICE, 0UL, 0UL).status != 0UL);
	assert(call(&realm_a, OPENCCA_IOMMU_FAULT, guest, DEVICE, 0UL, 0UL).status != 0UL);
	assert(fault_events == before);
	assert(map(&realm_a, guest, 0x3ff000UL, pages, 3U, 3UL, ipa).status == 0UL);
	result = call(&realm_a, OPENCCA_IOMMU_QUERY, guest, 0x400123UL, 0UL, 0UL);
	assert(result.value[0] == pa + PAGE + 0x123UL && result.value[1] == 3UL);
	assert(result.value[3] == 3UL);
	/* Read the actual hardware-format tables, including high PA bits and
	 * the 4 MiB directory boundary. The fake backend maps their PA only.
	 */
	assert(table_at(result.value[2])[0] != 0U && table_at(result.value[2])[1] != 0U);
	{
		unsigned long leaf = table_at(result.value[2])[0] & 0xfffff000U;

		/* Independent RK v2 descriptor check: PA 0x1287654000 has
		 * low bits 0x87654000, PA[35:32]=2 and PA[39:36]=1.
		 */
		assert(table_at(leaf)[1023] == 0x87654217U);
	}
	assert(opencca_iommu_owner_busy(&realm_a));
	assert(opencca_iommu_range_busy(&realm_a, ipa, 3UL * PAGE));
	assert(!opencca_iommu_range_busy(&realm_b, ipa, PAGE));
	assert(!opencca_iommu_range_busy(&realm_a, ipa + 3UL * PAGE, PAGE));
	assert(!opencca_gpu_lease_acquire(&realm_b, &pa, 1U));
	assert(map(&realm_a, guest, 0x3ff000UL, pages, 1U, 1UL, ipa).status != 0UL);
	assert(map(&realm_a, guest, 0UL, pages, 1U, 4UL, ipa).status != 0UL);
	assert(map(&realm_a, guest, 1UL, pages, 1U, 1UL, ipa).status != 0UL);
	assert(map(&realm_a, guest, (1UL << 32U) - PAGE, pages, 2U, 1UL, ipa).status != 0UL);
	assert(call(&realm_a, OPENCCA_IOMMU_DESTROY, guest, 0UL, 0UL, 0UL).status != 0UL);
	remove_all(&realm_a, guest, 0x400000UL, PAGE);
	assert(!opencca_iommu_range_busy(&realm_a, ipa + PAGE, PAGE));
	assert(opencca_iommu_range_busy(&realm_a, ipa, PAGE));
	remove_all(&realm_a, guest, 0x3ff000UL, PAGE);
	remove_all(&realm_a, guest, 0x401000UL, PAGE);
	assert(!opencca_iommu_range_busy(&realm_a, ipa, 3UL * PAGE));
	assert(opencca_gpu_lease_acquire(&realm_a, &pa, 1U));
	assert(map(NULL, host, 0UL, pages, 3U, 1UL, 0UL).status != 0UL);
	assert(opencca_dma_map_active() == 0U);
	opencca_gpu_lease_release(&realm_a, &pa, 1U);

	/* A later forbidden page must roll back earlier physical reservations. */
	assert(opencca_gpu_lease_acquire(&realm_a, &pages[2], 1U));
	assert(map(NULL, host, 0UL, pages, 3U, 1UL, 0UL).status != 0UL);
	assert(opencca_dma_map_active() == 0U);
	assert(call(NULL, OPENCCA_IOMMU_QUERY, host, 0UL, 0UL, 0UL).value[1] == 0UL);
	opencca_gpu_lease_release(&realm_a, &pages[2], 1U);
	assert(map(NULL, host, 0UL, pages, 3U, 1UL, 0UL).status == 0UL);
	assert(call(NULL, OPENCCA_IOMMU_QUERY, host, 0UL, 0UL, 0UL).value[1] == 1UL);
	assert(call(NULL, OPENCCA_IOMMU_BIND, host, DEVICE + PAGE, 0UL, 0UL).status != 0UL);
	assert(call(NULL, OPENCCA_IOMMU_BIND, host, DEVICE, 0UL, 0UL).status == 0UL);
	before = fault_events;
	assert(call(&realm_b, OPENCCA_IOMMU_FAULT, host, DEVICE, 0UL, 0UL).status != 0UL);
	assert(call(&realm_a, OPENCCA_IOMMU_FAULT, guest, DEVICE, 0UL, 0UL).status != 0UL);
	assert(call(NULL, OPENCCA_IOMMU_FAULT, host, DEVICE + PAGE, 0UL, 0UL).status != 0UL);
	assert(call(NULL, OPENCCA_IOMMU_FAULT, host, DEVICE, 1UL, 0UL).status != 0UL);
	assert(call(NULL, OPENCCA_IOMMU_FAULT, host, DEVICE, 0UL, PAGE).status != 0UL);
	assert(fault_events == before);
	check_fault(NULL, host, host, false);
	fault_flags = 0UL;
	check_fault(NULL, host, host, false);
	fault_flags = 1UL | OPENCCA_IOMMU_FAULT_WRITE;
	assert(call(&realm_a, OPENCCA_IOMMU_BIND, guest, DEVICE, 0UL, 0UL).status != 0UL);
	before = device_events;
	check_retirement = true;
	remove_all(NULL, host, 0UL, 3UL * PAGE);
	check_retirement = false;
	assert(device_events == before + 3U && invalidated);
	assert(call(NULL, OPENCCA_IOMMU_DESTROY, host, 0UL, 0UL, 0UL).status != 0UL);
	assert(call(NULL, OPENCCA_IOMMU_QUIESCE, host, 0UL, 0UL, 0UL).status == 0UL);
	assert(call(NULL, OPENCCA_IOMMU_BIND, host, DEVICE, 0UL, 0UL).status == 0UL);
	assert(call(NULL, OPENCCA_IOMMU_QUIESCE, host, 0UL, 0UL, 0UL).status == 0UL);
	assert(call(NULL, OPENCCA_IOMMU_UNBIND, host, DEVICE, 0UL, 0UL).status == 0UL);
	assert(!device_bound);
	before = fault_events;
	assert(call(NULL, OPENCCA_IOMMU_FAULT, host, DEVICE, 0UL, 0UL).status != 0UL);
	assert(fault_events == before);
	assert(call(NULL, OPENCCA_IOMMU_DESTROY, host, 0UL, 0UL, 0UL).status == 0UL);
	stale = host;
	host = create(NULL);
	assert(host != stale && call(NULL, OPENCCA_IOMMU_QUERY, stale, 0UL, 0UL, 0UL).status != 0UL);
	before = fault_events;
	assert(call(NULL, OPENCCA_IOMMU_FAULT, stale, DEVICE, 0UL, 0UL).status != 0UL);
	assert(fault_events == before);
	{
		unsigned long temporary = create(&realm_b);

		assert(map(&realm_b, temporary, PAGE, pages, 1U, 3UL, ipa).status == 0UL);
		assert(opencca_iommu_owner_busy(&realm_b));
		remove_all(&realm_b, temporary, PAGE, PAGE);
		assert(!opencca_iommu_range_busy(&realm_b, ipa, PAGE));
		assert(opencca_iommu_owner_busy(&realm_b));
		assert(call(&realm_b, OPENCCA_IOMMU_DESTROY, temporary, 0UL, 0UL, 0UL).status == 0UL);
		assert(!opencca_iommu_owner_busy(&realm_b));
	}

	assert(call(NULL, OPENCCA_IOMMU_BIND, host, DEVICE, 0UL, 0UL).status == 0UL);
	assert(map(NULL, host, 0UL, pages, 1U, 3UL, 0UL).status == 0UL);
	before = device_events;
	assert(call(NULL, OPENCCA_IOMMU_GRANT, 0UL, DEVICE, guest, 0UL).status == OPENCCA_IOMMU_STATE);
	assert(device_events == before);
	remove_all(NULL, host, 0UL, PAGE);
	assert(call(NULL, OPENCCA_IOMMU_GRANT, 0UL, DEVICE, stale, 0UL).status != 0UL);
	assert(call(NULL, OPENCCA_IOMMU_GRANT, 0UL, DEVICE, host, 0UL).status != 0UL);
	assert(call(NULL, OPENCCA_IOMMU_GRANT, 0UL, DEVICE, guest, 0UL).status == 0UL);
	assert(!device_bound);
	check_fault(NULL, host, guest, true);
	before = fault_events;
	assert(call(&realm_a, OPENCCA_IOMMU_FAULT, guest, DEVICE, 0UL, 0UL).status != 0UL);
	assert(fault_events == before);
	before = device_events;
	assert(call(NULL, OPENCCA_IOMMU_BIND, host, DEVICE, 0UL, 0UL).status == OPENCCA_IOMMU_STATE);
	assert(call(NULL, OPENCCA_IOMMU_UNBIND, host, DEVICE, 0UL, 0UL).status == OPENCCA_IOMMU_STATE);
	assert(map(NULL, host, 0UL, pages, 1U, 3UL, 0UL).status == OPENCCA_IOMMU_STATE);
	assert(call(&realm_a, OPENCCA_IOMMU_DESTROY, guest, 0UL, 0UL, 0UL).status == OPENCCA_IOMMU_STATE);
	assert(call(NULL, OPENCCA_IOMMU_GRANT, 0UL, DEVICE, guest, 0UL).status == OPENCCA_IOMMU_STATE);
	assert(device_events == before);
	assert(call(&realm_a, OPENCCA_IOMMU_BIND, guest, DEVICE, 0UL, 0UL).status == 0UL);
	assert(device_bound);
	check_fault(&realm_a, guest, guest, true);
	check_fault(NULL, host, guest, true);
	assert(map(&realm_a, guest, 0UL, pages, 1U, 3UL, ipa).status == 0UL);
	assert(call(&realm_a, OPENCCA_IOMMU_REVOKE, 0UL, DEVICE, 0UL, 0UL).status != 0UL);
	assert(call(NULL, OPENCCA_IOMMU_REVOKE, 0UL, DEVICE, 0UL, 0UL).status == 0UL);
	check_fault(NULL, host, host, false);
	before = fault_events;
	assert(call(&realm_a, OPENCCA_IOMMU_FAULT, guest, DEVICE, 0UL, 0UL).status != 0UL);
	assert(fault_events == before);
	assert(opencca_iommu_range_busy(&realm_a, ipa, PAGE));
	before = device_events;
	assert(call(&realm_a, OPENCCA_IOMMU_BIND, guest, DEVICE, 0UL, 0UL).status == OPENCCA_IOMMU_STATE);
	assert(device_events == before);
	remove_all(&realm_a, guest, 0UL, PAGE);
	assert(call(NULL, OPENCCA_IOMMU_UNBIND, host, DEVICE, 0UL, 0UL).status == 0UL);
	assert(call(NULL, OPENCCA_IOMMU_BIND, host, DEVICE, 0UL, 0UL).status == 0UL);
	assert(call(NULL, OPENCCA_IOMMU_GRANT, 0UL, DEVICE, guest, 0UL).status == 0UL);

	/* A real backend failure cannot be acknowledged away by Host. Existing
	 * mappings, Guest backing and table ownership survive quarantine.
	 */
	assert(map(&realm_a, guest, 0UL, pages, 1U, 2UL, ipa).status == 0UL);
	assert(call(&realm_a, OPENCCA_IOMMU_BIND, guest, DEVICE, 0UL, 0UL).status == 0UL);
	if (fault_failure) {
		unsigned int reservations = opencca_dma_map_active();

		before = fault_events;
		fail_fault = true;
		result = call(guest_fault_failure ? &realm_a : NULL, OPENCCA_IOMMU_FAULT,
			      guest_fault_failure ? guest : host, DEVICE, 0UL, 0UL);
		assert(result.status == OPENCCA_IOMMU_STATE);
		assert(fault_events == before + 1U);
		fail_fault = false;
		assert(call(NULL, OPENCCA_IOMMU_FAULT, host, DEVICE, 0UL, 0UL).status == OPENCCA_IOMMU_STATE);
		assert(call(&realm_a, OPENCCA_IOMMU_FAULT, guest, DEVICE, 0UL, 0UL).status == OPENCCA_IOMMU_STATE);
		assert(fault_events == before + 1U);
		result = call(&realm_a, OPENCCA_IOMMU_QUERY, guest, 0UL, 0UL, 0UL);
		assert(result.status == 0UL && result.value[0] == pa && result.value[1] == 2UL);
		assert(result.value[3] == 1UL && opencca_iommu_range_busy(&realm_a, ipa, PAGE));
		assert(call(&realm_a, OPENCCA_IOMMU_UNMAP, guest, 0UL, 0UL, PAGE).status == OPENCCA_IOMMU_STATE);
		assert(call(&realm_a, OPENCCA_IOMMU_DESTROY, guest, 0UL, 0UL, 0UL).status == OPENCCA_IOMMU_STATE);
		assert(opencca_dma_map_active() == reservations);
		assert(!opencca_gpu_lease_acquire(&realm_b, &pa, 1U));
		assert(call(NULL, OPENCCA_IOMMU_REVOKE, 0UL, DEVICE, 0UL, 0UL).status == 0UL);
		assert(opencca_iommu_range_busy(&realm_a, ipa, PAGE));
		puts("Managed IOMMU fault failure: Host/Guest quarantine and backing retention PASS");
		return 0;
	}
	fail_device = true;
	result = call(&realm_a, OPENCCA_IOMMU_UNMAP, guest, 0UL, 0UL, PAGE);
	assert(result.status == OPENCCA_IOMMU_STATE && result.value[0] == 0UL);
	result = call(&realm_a, OPENCCA_IOMMU_QUERY, guest, 0UL, 0UL, 0UL);
	assert(result.status == 0UL && result.value[1] == 0UL && result.value[3] == 1UL);
	assert(opencca_iommu_range_busy(&realm_a, ipa, PAGE));
	assert(!opencca_gpu_lease_acquire(&realm_b, &pa, 1U));
	assert(call(&realm_a, OPENCCA_IOMMU_DESTROY, guest, 0UL, 0UL, 0UL).status != 0UL);
	assert(call(NULL, OPENCCA_IOMMU_UNBIND, guest, DEVICE, 0UL, 0UL).status != 0UL);
	fail_device = false;
	assert(call(&realm_a, OPENCCA_IOMMU_QUIESCE, guest, 0UL, 0UL, 0UL).status != 0UL);
	assert(call(&realm_a, OPENCCA_IOMMU_DESTROY, guest, 0UL, 0UL, 0UL).status != 0UL);
	/* Exhaust the shared page-table pool across the entire 32-bit IOVA
	 * aperture. Failed allocation must not reserve data pages; destroying
	 * an unbound empty domain recovers all retained empty leaf tables.
	 */
	host = create(NULL);
	{
		unsigned int mapped = 0U, reservations;
		unsigned long ordinary;

		for (; mapped < 1024U; mapped++) {
			ordinary = 0x80000000UL + mapped * PAGE;
			result = map(NULL, host, mapped * 0x400000UL, &ordinary, 1U, 3UL, 0UL);
			if (result.status != 0UL)
				break;
		}
		assert(mapped > 1000U && mapped < 1024U && result.status == OPENCCA_IOMMU_FULL);
		reservations = opencca_dma_map_active();
		ordinary = 0x90000000UL;
		assert(map(NULL, host, mapped * 0x400000UL, &ordinary, 1U, 3UL, 0UL).status != 0UL);
		assert(opencca_dma_map_active() == reservations);
		for (unsigned int i = 0U; i < mapped; i++)
			remove_all(NULL, host, i * 0x400000UL, PAGE);
	}
	assert(clean_events > 0U);
	assert(call(NULL, OPENCCA_IOMMU_DESTROY, host, 0UL, 0UL, 0UL).status == 0UL);
	puts("Managed IOMMU: real RK tables, PA40/RW, owner/generation, GPU exclusion, "
	     "Guest device grants/revocation, backing lifetime, rollback, trusted invalidation and quarantine PASS");
	return 0;
}
