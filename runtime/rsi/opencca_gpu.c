/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */
#include <arch_helpers.h>
#include <buffer.h>
#include <cpuid.h>
#include <debug.h>
#include <granule.h>
#include <opencca_gpu_lease.h>
#include <realm.h>
#include <rsi-handler.h>
#include <smc-rsi.h>
#include <spinlock.h>
#include <string.h>

#define OPENCCA_GPA_TO_HPA_MAX_ENTRIES (GRANULE_SIZE / sizeof(unsigned long))
_Static_assert(OPENCCA_GPA_TO_HPA_MAX_ENTRIES == OPENCCA_GPU_LEASE_BATCH,
	       "GPU batch must fit in one granule");

static spinlock_t opencca_gpu_mappings_lock;
/* A synchronous RSI cannot re-enter on the same CPU. Keep the bounded batch
 * private without consuming a granule-sized chunk of the RMM stack.
 */
static unsigned long gpu_batch[MAX_CPUS][OPENCCA_GPU_LEASE_BATCH];

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
	if (!access_array(rec, array_ipa, batch, count, false, res))
		return;
	for (unsigned long i = 0UL; i < count; i++) {
		unsigned long ipa = batch[i], level = 0UL;
		enum ripas ripas = RIPAS_EMPTY;
		enum s2_walk_status status;

		if (!GRANULE_ALIGNED(ipa) || !addr_in_rec_par(rec, ipa)) {
			res->smc_res.x[0] = RSI_ERROR_INPUT;
			return;
		}
		status = opencca_gpu_ipa_to_pa(rec, ipa, &batch[i], &level, &ripas);
		if (status == WALK_INVALID_PARAMS ||
		    (status == WALK_FAIL && ripas == RIPAS_EMPTY)) {
			res->smc_res.x[0] = RSI_ERROR_INPUT;
			return;
		}
		if (status == WALK_FAIL) {
			res->action = STAGE_2_TRANSLATION_FAULT;
			res->rtt_level = level;
			return;
		}
	}
	spinlock_acquire(&opencca_gpu_mappings_lock);
	acquired = opencca_gpu_lease_acquire(rec->realm_info.g_rd, batch, count);
	spinlock_release(&opencca_gpu_mappings_lock);
	if (!acquired) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		return;
	}
	if (!access_array(rec, array_ipa, batch, count, true, res)) {
		spinlock_acquire(&opencca_gpu_mappings_lock);
		opencca_gpu_lease_release(rec->realm_info.g_rd, batch, count);
		spinlock_release(&opencca_gpu_mappings_lock);
		return;
	}
	res->smc_res.x[0] = RSI_SUCCESS;
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
