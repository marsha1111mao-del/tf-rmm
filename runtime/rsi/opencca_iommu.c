/* SPDX-License-Identifier: BSD-3-Clause */
#include <arch_helpers.h>
#include <cpuid.h>
#include <granule.h>
#include <limits.h>
#include <opencca_gpu_lease.h>
#include <opencca_iommu.h>
#include <realm.h>
#include <rec.h>
#include <rsi-handler.h>
#include <smc-handler.h>
#include <string.h>
#include <xshm_runtime.h>

static unsigned long map_pages[MAX_CPUS][OPENCCA_IOMMU_BATCH_PAGES];

static unsigned long table_pa(const void *table)
{
	/* RMM RW uses identity mappings; the relocated runtime address is PA. */
	return (unsigned long)table;
}

static void clean(const void *table, size_t bytes)
{
	clean_dcache_range((uintptr_t)table, bytes);
	dsb(sy);
}

static const struct opencca_iommu_ops operations = {
	.table_pa = table_pa,
	.clean = clean,
	.reserve = opencca_gpu_dma_reserve,
	.retire = opencca_gpu_dma_retire,
	.device_valid = plat_opencca_iommu_device_valid,
	.device = plat_opencca_iommu_device,
	.fault = plat_opencca_iommu_fault
};

static bool map_arguments(unsigned long iova, unsigned long address,
			  unsigned long size_prot, size_t *count,
			  unsigned long *prot)
{
	unsigned long size = size_prot & ~4095UL;

	*prot = size_prot & 4095UL;
	if (size == 0UL || size > OPENCCA_IOMMU_BATCH_PAGES * GRANULE_SIZE ||
	    *prot == 0UL || (*prot & ~3UL) != 0UL ||
	    ((iova | address) & (GRANULE_SIZE - 1UL)) != 0UL ||
	    size > ULONG_MAX - address || size > ULONG_MAX - iova)
		return false;
	*count = size / GRANULE_SIZE;
	return true;
}

static void copy_result(const struct opencca_iommu_result *input, struct smc_result *output)
{
	memset(output, 0, sizeof(*output));
	output->x[0] = input->status;
	for (unsigned int i = 0U; i < 4U; i++)
		output->x[i + 1U] = input->value[i];
}

void smc_opencca_iommu(unsigned long op, unsigned long handle,
		unsigned long arg1, unsigned long arg2, unsigned long arg3,
		struct smc_result *res)
{
	struct opencca_iommu_result result = {.status = OPENCCA_IOMMU_INPUT};
	unsigned int cpu = my_cpuid();
	size_t count;
	unsigned long prot;

	/* RMI dispatch owns xshm_policy_lock, including granule validation and
	 * table publication. Host cannot race a successful check with delegate.
	 */
	if (op != OPENCCA_IOMMU_MAP) {
		opencca_iommu_call(&operations, NULL, op, handle, arg1, arg2, arg3, &result);
	} else if (cpu < MAX_CPUS && map_arguments(arg1, arg2, arg3, &count, &prot)) {
		for (size_t i = 0U; i < count; i++) {
			struct granule *granule;
			unsigned long pa = arg2 + i * GRANULE_SIZE;

			granule = find_lock_granule(pa, GRANULE_STATE_NS);
			if (granule == NULL)
				goto out;
			granule_unlock(granule);
			map_pages[cpu][i] = pa;
		}
		opencca_iommu_map(&operations, NULL, handle, arg1, map_pages[cpu],
				 count, prot, 0UL, &result);
	}
out:
	copy_result(&result, res);
}

void handle_rsi_opencca_iommu(struct rec *rec, struct rsi_result *res)
{
	struct opencca_iommu_result result = {.status = OPENCCA_IOMMU_INPUT};
	unsigned long op = rec->regs[1], handle = rec->regs[2];
	unsigned long arg1 = rec->regs[3], arg2 = rec->regs[4], arg3 = rec->regs[5];
	unsigned int cpu = my_cpuid();
	size_t count;
	unsigned long prot;

	res->action = UPDATE_REC_RETURN_TO_REALM;
	if ((rec->regs[6] | rec->regs[7]) != 0UL) {
		copy_result(&result, &res->smc_res);
		return;
	}
	xshm_policy_lock();
	if (op != OPENCCA_IOMMU_MAP) {
		opencca_iommu_call(&operations, rec->realm_info.g_rd, op, handle,
				   arg1, arg2, arg3, &result);
	} else if (cpu < MAX_CPUS && map_arguments(arg1, arg2, arg3, &count, &prot)) {
		for (size_t i = 0U; i < count; i++) {
			struct s2_walk_result walk;
			enum s2_walk_status status;

			/* Protected assigned RAM only; no Guest-supplied HPA, NS/MMIO
			 * alias or other Realm's owner enters the authorization.
			 */
			status = realm_ipa_to_pa(rec, arg2 + i * GRANULE_SIZE, &walk);
			if (status != WALK_SUCCESS) {
				if (status == WALK_FAIL && walk.ripas_val != RIPAS_EMPTY) {
					res->action = STAGE_2_TRANSLATION_FAULT;
					res->rtt_level = walk.rtt_level;
				}
				goto out;
			}
			map_pages[cpu][i] = walk.pa;
			granule_unlock(walk.llt);
		}
		opencca_iommu_map(&operations, rec->realm_info.g_rd, handle, arg1,
				 map_pages[cpu], count, prot, arg2, &result);
	}
out:
	xshm_policy_unlock();
	copy_result(&result, &res->smc_res);
}
