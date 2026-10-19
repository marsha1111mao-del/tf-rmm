/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */
#include <arch_helpers.h>
#include <buffer.h>
#include <cpuid.h>
#include <debug.h>
#include <granule.h>
#include <limits.h>
#include <opencca_gpu_lease.h>
#include <opencca_iommu.h>
#include <realm.h>
#include <rsi-handler.h>
#include <smc-rsi.h>
#include <smc-rmi.h>
#include <smc-handler.h>
#include <spinlock.h>
#include <string.h>
#include <xshm_runtime.h>

#define OPENCCA_GPA_TO_HPA_MAX_ENTRIES (GRANULE_SIZE / sizeof(unsigned long))
_Static_assert(OPENCCA_GPA_TO_HPA_MAX_ENTRIES == OPENCCA_GPU_LEASE_BATCH,
	       "GPU batch must fit in one granule");

static spinlock_t opencca_gpu_mappings_lock;
/* A synchronous RSI cannot re-enter on the same CPU. Keep the bounded batch
 * private without consuming a granule-sized chunk of the RMM stack.
 */
static unsigned long gpu_batch[MAX_CPUS][OPENCCA_GPU_LEASE_BATCH];

unsigned long smc_opencca_dma_guard(unsigned long op, unsigned long domain,
				    unsigned long iova, unsigned long pa,
				    unsigned long size)
{
	bool accepted = false;

	/* The legacy Host-cookie ABI must never release registrations owned
	 * by the managed-table service, even if Host knows its public handle.
	 */
	if (opencca_iommu_secure_handle(domain))
		return RMI_ERROR_INPUT;

	/* RMI mutations are serialized by xshm_policy_lock. Keep all delegated
	 * Realm pages protected, including BOs not currently mapped by the GPU.
	 * MMIO/non-DRAM DMA mappings require a separately authorized interface.
	 */
	if (op == 1UL) {
		if (size == 0UL || size > OPENCCA_DMA_MAP_MAX_SIZE ||
		    ((pa | size) & (GRANULE_SIZE - 1UL)) != 0UL ||
		    size > ULONG_MAX - pa)
			return RMI_ERROR_INPUT;
		for (unsigned long offset = 0UL; offset < size; offset += GRANULE_SIZE) {
			struct granule *g = find_lock_granule(pa + offset, GRANULE_STATE_NS);

			if (g == NULL)
				return RMI_ERROR_INPUT;
			granule_unlock(g);
		}
	}
	spinlock_acquire(&opencca_gpu_mappings_lock);
	if (op == 1UL)
		accepted = opencca_dma_map_acquire(domain, iova, pa, size);
	else if (op == 2UL && pa == 0UL)
		accepted = opencca_dma_map_release(domain, iova, size);
	spinlock_release(&opencca_gpu_mappings_lock);
	return accepted ? RMI_SUCCESS : RMI_ERROR_INPUT;
}

bool opencca_gpu_dma_busy(unsigned long pa, unsigned long size)
{
	bool busy;

	spinlock_acquire(&opencca_gpu_mappings_lock);
	busy = opencca_dma_map_overlaps(pa, size);
	spinlock_release(&opencca_gpu_mappings_lock);
	return busy;
}

bool opencca_gpu_page_busy(unsigned long hpa)
{
	bool busy;

	spinlock_acquire(&opencca_gpu_mappings_lock);
	busy = opencca_gpu_lease_page_busy(hpa) ||
	       opencca_dma_map_overlaps(hpa, GRANULE_SIZE);
	spinlock_release(&opencca_gpu_mappings_lock);
	return busy;
}

bool opencca_gpu_dma_reserve(unsigned long domain, unsigned long iova,
			    unsigned long pa, unsigned long size)
{
	bool accepted;

	spinlock_acquire(&opencca_gpu_mappings_lock);
	accepted = opencca_dma_map_acquire(domain, iova, pa, size);
	spinlock_release(&opencca_gpu_mappings_lock);
	return accepted;
}

bool opencca_gpu_dma_retire(unsigned long domain, unsigned long iova,
			   unsigned long size)
{
	bool accepted;

	spinlock_acquire(&opencca_gpu_mappings_lock);
	accepted = opencca_dma_map_release(domain, iova, size);
	spinlock_release(&opencca_gpu_mappings_lock);
	return accepted;
}

void smc_opencca_dma_status(unsigned long selector, struct smc_result *res)
{
	res->x[0] = RMI_SUCCESS;
	res->x[1] = 0UL;
	res->x[2] = 0UL;
	spinlock_acquire(&opencca_gpu_mappings_lock);
	if (selector == 0UL) {
		res->x[1] = 1UL; /* ABI version */
		res->x[2] = 0UL; /* No claim of immutable hardware enforcement. */
	} else if (selector == 1UL) {
		res->x[1] = opencca_gpu_lease_active();
		res->x[2] = opencca_gpu_lease_first();
	} else if (selector == 2UL) {
		res->x[1] = opencca_dma_map_active();
		res->x[2] = OPENCCA_DMA_MAP_CAPACITY;
	} else {
		res->x[0] = RMI_ERROR_INPUT;
	}
	spinlock_release(&opencca_gpu_mappings_lock);
}

unsigned long smc_opencca_gpu_mmio_grant(unsigned long rd_addr)
{
	struct granule *g_rd;
	unsigned long status = RMI_ERROR_INPUT;

	g_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
	if (g_rd == NULL)
		return status;
	spinlock_acquire(&opencca_gpu_mappings_lock);
	if (opencca_gpu_mmio_grant(g_rd))
		status = RMI_SUCCESS;
	spinlock_release(&opencca_gpu_mappings_lock);
	granule_unlock(g_rd);
	return status;
}

bool opencca_gpu_authorize_mapping(const void *owner, unsigned long ipa,
		unsigned long pa, unsigned long size, unsigned long shared_base)
{
	bool allowed;

	spinlock_acquire(&opencca_gpu_mappings_lock);
	allowed = opencca_gpu_mapping_allowed(owner, ipa, pa, size, shared_base);
	spinlock_release(&opencca_gpu_mappings_lock);
	return allowed;
}

/* Implemented by the RTT service: revoke and invalidate the owner's alias. */
extern bool opencca_gpu_revoke_mmio(const void *owner);

static const struct opencca_gpu_ops gpu_ops = {
	.reset = plat_opencca_gpu_reset,
	.revoke_mmio = opencca_gpu_revoke_mmio,
	.opp_valid = plat_opencca_gpu_opp_valid
};

void smc_opencca_gpu_pm(unsigned long operation, unsigned long argument,
		       unsigned long error, struct smc_result *res)
{
	bool accepted;

	memset(res, 0, sizeof(*res));
	spinlock_acquire(&opencca_gpu_mappings_lock);
	accepted = opencca_gpu_control(&gpu_ops, NULL, operation, argument, error);
	res->x[0] = accepted ? RMI_SUCCESS : RMI_ERROR_INPUT;
	res->x[1] = opencca_gpu_state();
	if (accepted && operation == OPENCCA_GPU_STATUS) {
		res->x[2] = plat_opencca_gpu_pa_bits();
		res->x[3] = OPENCCA_GPU_MMIO_BASE;
		res->x[4] = OPENCCA_GPU_MMIO_SIZE;
	}
	spinlock_release(&opencca_gpu_mappings_lock);
}

void handle_rsi_opencca_gpu_control(struct rec *rec, struct rsi_result *res)
{
	unsigned long operation = rec->regs[1];
	bool accepted = false;

	res->action = UPDATE_REC_RETURN_TO_REALM;
	memset(&res->smc_res, 0, sizeof(res->smc_res));
	res->smc_res.x[0] = RSI_ERROR_INPUT;
	for (unsigned int i = 2U; i < 8U; i++) {
		if (rec->regs[i] != 0UL)
			return;
	}
	spinlock_acquire(&opencca_gpu_mappings_lock);
	if (operation == 0UL)
		accepted = opencca_gpu_claim(rec->realm_info.g_rd);
	else if (operation == 1UL)
		accepted = opencca_gpu_control(&gpu_ops, rec->realm_info.g_rd,
					      OPENCCA_GPU_RESET, 0UL, 0UL);
	res->smc_res.x[0] = accepted ? RSI_SUCCESS : RSI_ERROR_INPUT;
	spinlock_release(&opencca_gpu_mappings_lock);
}

bool opencca_gpu_pm_destroy_allowed(struct granule *g_rd)
{
	bool allowed;

	spinlock_acquire(&opencca_gpu_mappings_lock);
	allowed = opencca_gpu_pm_destroy_begin(g_rd);
	spinlock_release(&opencca_gpu_mappings_lock);
	return allowed;
}

static enum s2_walk_status opencca_gpu_ipa_to_pa(struct rec *rec,
		unsigned long ipa, unsigned long *pa, unsigned long *rtt_level,
		enum ripas *ripas)
{
	struct s2_walk_result walk;
	enum s2_walk_status status = realm_ipa_to_pa(rec, ipa, &walk);

	if (status == WALK_SUCCESS) {
		*pa = walk.pa;
		granule_unlock(walk.llt);
	} else if (status == WALK_FAIL) {
		*rtt_level = walk.rtt_level;
		*ripas = walk.ripas_val;
	}
	return status;
}

/* Snapshot inputs, or commit all outputs, under one array-page RTT lock.
 * No outputs are published before all translations/leases have succeeded.
 */
static bool access_array(struct rec *rec, unsigned long array_ipa,
		unsigned long *batch, unsigned long count, bool write,
		struct rsi_result *res)
{
	struct s2_walk_result walk;
	enum s2_walk_status status = realm_ipa_to_pa(rec, array_ipa, &walk);
	struct granule *gr;
	unsigned long *array;
	size_t bytes = count * sizeof(*array);

	if (status == WALK_FAIL) {
		if (walk.ripas_val == RIPAS_EMPTY)
			res->smc_res.x[0] = RSI_ERROR_INPUT;
		else {
			res->action = STAGE_2_TRANSLATION_FAULT;
			res->rtt_level = walk.rtt_level;
		}
		return false;
	}
	if (status != WALK_SUCCESS) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		return false;
	}
	gr = find_granule(walk.pa);
	assert(gr != NULL);
	array = buffer_granule_map(gr, SLOT_RSI_CALL);
	assert(array != NULL);
	if (write) {
		memcpy(array, batch, bytes);
		clean_dcache_range((uintptr_t)array, bytes);
	} else {
		inv_dcache_range((uintptr_t)array, bytes);
		memcpy(batch, array, bytes);
	}
	buffer_unmap(array);
	granule_unlock(walk.llt);
	return true;
}

static bool valid_array(struct rec *rec, unsigned long ipa, unsigned long count)
{
	return GRANULE_ALIGNED(ipa) && addr_in_rec_par(rec, ipa) &&
	       count != 0UL && count <= OPENCCA_GPA_TO_HPA_MAX_ENTRIES;
}

void opencca_gpu_release_realm_mappings(struct granule *g_rd)
{
	unsigned int released, active;

	spinlock_acquire(&opencca_gpu_mappings_lock);
	opencca_gpu_mmio_release(g_rd);
	released = opencca_gpu_lease_release_owner(g_rd);
	active = opencca_gpu_lease_active();
	spinlock_release(&opencca_gpu_mappings_lock);
	if (released != 0U)
		INFO("[MZH][OPENCCA_GPU_UNMAP_ALL] rd=0x%lx released=%u active=%u\n",
		     granule_addr(g_rd), released, active);
}

void handle_rsi_opencca_gpa_to_hpa(struct rec *rec, struct rsi_result *res)
{
	unsigned long array_ipa = rec->regs[1], count = rec->regs[2];
	unsigned int cpu = my_cpuid();
	unsigned long *batch;
	bool acquired;

	res->action = UPDATE_REC_RETURN_TO_REALM;
	if (!valid_array(rec, array_ipa, count)) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		return;
	}
	assert(cpu < MAX_CPUS);
	batch = gpu_batch[cpu];
	xshm_policy_lock();
	if (!access_array(rec, array_ipa, batch, count, false, res))
		goto out;
	for (unsigned long i = 0UL; i < count; i++) {
		unsigned long ipa = batch[i], level = 0UL;
		enum ripas ripas = RIPAS_EMPTY;
		enum s2_walk_status status;

		if (!GRANULE_ALIGNED(ipa) || !addr_in_rec_par(rec, ipa)) {
			res->smc_res.x[0] = RSI_ERROR_INPUT;
			goto out;
		}
		status = opencca_gpu_ipa_to_pa(rec, ipa, &batch[i], &level, &ripas);
		if (status == WALK_INVALID_PARAMS ||
		    (status == WALK_FAIL && ripas == RIPAS_EMPTY)) {
			res->smc_res.x[0] = RSI_ERROR_INPUT;
			goto out;
		}
		if (status == WALK_FAIL) {
			res->action = STAGE_2_TRANSLATION_FAULT;
			res->rtt_level = level;
			goto out;
		}
	}
	spinlock_acquire(&opencca_gpu_mappings_lock);
	acquired = opencca_gpu_lease_acquire(rec->realm_info.g_rd, batch, count);
	spinlock_release(&opencca_gpu_mappings_lock);
	if (!acquired) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		goto out;
	}
	if (!access_array(rec, array_ipa, batch, count, true, res)) {
		spinlock_acquire(&opencca_gpu_mappings_lock);
		opencca_gpu_lease_release(rec->realm_info.g_rd, batch, count);
		spinlock_release(&opencca_gpu_mappings_lock);
		goto out;
	}
	res->smc_res.x[0] = RSI_SUCCESS;
out:
	xshm_policy_unlock();
}

void handle_rsi_opencca_gpu_revoke(struct rec *rec, struct rsi_result *res)
{
	unsigned long array_ipa = rec->regs[1], count = rec->regs[2];
	unsigned int cpu = my_cpuid();
	unsigned long *batch;

	res->action = UPDATE_REC_RETURN_TO_REALM;
	if (!valid_array(rec, array_ipa, count)) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		return;
	}
	assert(cpu < MAX_CPUS);
	batch = gpu_batch[cpu];
	if (!access_array(rec, array_ipa, batch, count, false, res))
		return;
	for (unsigned long i = 0UL; i < count; i++) {
		if (!GRANULE_ALIGNED(batch[i])) {
			res->smc_res.x[0] = RSI_ERROR_INPUT;
			return;
		}
	}
	spinlock_acquire(&opencca_gpu_mappings_lock);
	opencca_gpu_lease_release(rec->realm_info.g_rd, batch, count);
	spinlock_release(&opencca_gpu_mappings_lock);
	res->smc_res.x[0] = RSI_SUCCESS;
}
