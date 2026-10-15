/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */

#include <buffer.h>
#include <arch_helpers.h>
#include <debug.h>
#include <granule.h>
#include <limits.h>
#include <realm.h>
#include <rsi-handler.h>
#include <smc-rsi.h>
#include <spinlock.h>

#define OPENCCA_GPA_TO_HPA_MAX_ENTRIES	(GRANULE_SIZE / sizeof(unsigned long))
#define OPENCCA_GPU_MAPPING_MAX		8192U

struct opencca_gpu_mapping {
	struct granule *rd;
	unsigned long hpa;
	unsigned short refcount;
	bool active;
};

static spinlock_t opencca_gpu_mappings_lock;
static struct opencca_gpu_mapping
	opencca_gpu_mappings[OPENCCA_GPU_MAPPING_MAX];
static unsigned int opencca_gpu_mappings_active;
static unsigned int opencca_gpu_map_log_budget = 32U;
static unsigned int opencca_gpu_unmap_log_budget = 32U;

static void opencca_gpu_clear_mapping_locked(unsigned int index)
{
	opencca_gpu_mappings[index].active = false;
	opencca_gpu_mappings[index].rd = NULL;
	opencca_gpu_mappings[index].hpa = 0UL;
	opencca_gpu_mappings[index].refcount = 0U;
	opencca_gpu_mappings_active--;
}

static enum s2_walk_status opencca_gpu_ipa_to_pa(struct rec *rec,
						 unsigned long ipa,
						 unsigned long *pa,
						 unsigned long *rtt_level,
						 enum ripas *ripas)
{
	struct s2_walk_result walk_res;
	enum s2_walk_status walk_status;

	walk_status = realm_ipa_to_pa(rec, ipa, &walk_res);
	if (walk_status == WALK_SUCCESS) {
		*pa = walk_res.pa;
		granule_unlock(walk_res.llt);
		return WALK_SUCCESS;
	}

	if (walk_status == WALK_FAIL) {
		*rtt_level = walk_res.rtt_level;
		*ripas = walk_res.ripas_val;
	}

	return walk_status;
}

static bool opencca_gpu_read_entry(struct rec *rec, unsigned long array_ipa,
				   unsigned long index, unsigned long *ipa,
				   struct rsi_result *res)
{
	enum s2_walk_status walk_status;
	struct s2_walk_result array_walk;
	struct granule *gr;
	unsigned long *array;

	walk_status = realm_ipa_to_pa(rec, array_ipa, &array_walk);
	switch (walk_status) {
	case WALK_SUCCESS:
		break;
	case WALK_FAIL:
		if (array_walk.ripas_val == RIPAS_EMPTY) {
			res->smc_res.x[0] = RSI_ERROR_INPUT;
		} else {
			res->action = STAGE_2_TRANSLATION_FAULT;
			res->rtt_level = array_walk.rtt_level;
		}
		return false;
	case WALK_INVALID_PARAMS:
	default:
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		return false;
	}

	gr = find_granule(array_walk.pa);
	assert(gr != NULL);
	array = (unsigned long *)buffer_granule_map(gr, SLOT_RSI_CALL);
	assert(array != NULL);
	inv_dcache_range((uintptr_t)&array[index], sizeof(array[index]));
	*ipa = array[index];
	buffer_unmap(array);
	granule_unlock(array_walk.llt);

	return true;
}

static bool opencca_gpu_write_entry(struct rec *rec, unsigned long array_ipa,
				    unsigned long index, unsigned long pa,
				    struct rsi_result *res)
{
	enum s2_walk_status walk_status;
	struct s2_walk_result array_walk;
	struct granule *gr;
	unsigned long *array;

	walk_status = realm_ipa_to_pa(rec, array_ipa, &array_walk);
	switch (walk_status) {
	case WALK_SUCCESS:
		break;
	case WALK_FAIL:
		if (array_walk.ripas_val == RIPAS_EMPTY) {
			res->smc_res.x[0] = RSI_ERROR_INPUT;
		} else {
			res->action = STAGE_2_TRANSLATION_FAULT;
			res->rtt_level = array_walk.rtt_level;
		}
		return false;
	case WALK_INVALID_PARAMS:
	default:
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		return false;
	}

	gr = find_granule(array_walk.pa);
	assert(gr != NULL);
	array = (unsigned long *)buffer_granule_map(gr, SLOT_RSI_CALL);
	assert(array != NULL);
	array[index] = pa;
	clean_dcache_range((uintptr_t)&array[index], sizeof(array[index]));
	buffer_unmap(array);
	granule_unlock(array_walk.llt);

	return true;
}

static bool opencca_gpu_track_mapping(struct rec *rec, unsigned long hpa,
				      struct rsi_result *res)
{
	int free_idx = -1;

	spinlock_acquire(&opencca_gpu_mappings_lock);
	for (unsigned int i = 0U; i < OPENCCA_GPU_MAPPING_MAX; i++) {
		if (opencca_gpu_mappings[i].active &&
		    (opencca_gpu_mappings[i].hpa == hpa)) {
			if ((opencca_gpu_mappings[i].rd != rec->realm_info.g_rd) ||
			    (opencca_gpu_mappings[i].refcount == USHRT_MAX)) {
				spinlock_release(&opencca_gpu_mappings_lock);
				res->smc_res.x[0] = RSI_ERROR_INPUT;
				return false;
			}
			opencca_gpu_mappings[i].refcount++;
			spinlock_release(&opencca_gpu_mappings_lock);
			return true;
		}

		if (!opencca_gpu_mappings[i].active && (free_idx < 0)) {
			free_idx = (int)i;
		}
	}

	if (free_idx < 0) {
		spinlock_release(&opencca_gpu_mappings_lock);
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		return false;
	}

	opencca_gpu_mappings[free_idx].rd = rec->realm_info.g_rd;
	opencca_gpu_mappings[free_idx].hpa = hpa;
	opencca_gpu_mappings[free_idx].refcount = 1U;
	opencca_gpu_mappings[free_idx].active = true;
	opencca_gpu_mappings_active++;
	if (opencca_gpu_map_log_budget > 0U) {
		INFO("[MZH][OPENCCA_GPU_MAP] rd=0x%lx hpa=0x%lx active=%u\n",
		     granule_addr(rec->realm_info.g_rd), hpa,
		     opencca_gpu_mappings_active);
		opencca_gpu_map_log_budget--;
	}
	spinlock_release(&opencca_gpu_mappings_lock);

	return true;
}

static void opencca_gpu_untrack_hpa(struct rec *rec, unsigned long hpa)
{
	unsigned int active_after = 0U;

	spinlock_acquire(&opencca_gpu_mappings_lock);
	for (unsigned int i = 0U; i < OPENCCA_GPU_MAPPING_MAX; i++) {
		if (!opencca_gpu_mappings[i].active ||
		    (opencca_gpu_mappings[i].rd != rec->realm_info.g_rd) ||
		    (opencca_gpu_mappings[i].hpa != hpa)) {
			continue;
		}

		if (opencca_gpu_mappings[i].refcount > 1U) {
			opencca_gpu_mappings[i].refcount--;
			spinlock_release(&opencca_gpu_mappings_lock);
			return;
		}

		opencca_gpu_clear_mapping_locked(i);
		active_after = opencca_gpu_mappings_active;
		spinlock_release(&opencca_gpu_mappings_lock);

		if (opencca_gpu_unmap_log_budget > 0U) {
			INFO("[MZH][OPENCCA_GPU_UNMAP] rd=0x%lx hpa=0x%lx active=%u\n",
			     granule_addr(rec->realm_info.g_rd), hpa,
			     active_after);
			opencca_gpu_unmap_log_budget--;
		}

		return;
	}
	spinlock_release(&opencca_gpu_mappings_lock);
}

void opencca_gpu_release_realm_mappings(struct granule *g_rd)
{
	unsigned int released = 0U;
	unsigned int active_after = 0U;

	spinlock_acquire(&opencca_gpu_mappings_lock);
	for (unsigned int i = 0U; i < OPENCCA_GPU_MAPPING_MAX; i++) {
		if (opencca_gpu_mappings[i].active &&
		    (opencca_gpu_mappings[i].rd == g_rd)) {
			opencca_gpu_clear_mapping_locked(i);
			released++;
		}
	}
	active_after = opencca_gpu_mappings_active;
	spinlock_release(&opencca_gpu_mappings_lock);

	if (released != 0U) {
		INFO("[MZH][OPENCCA_GPU_UNMAP_ALL] rd=0x%lx released=%u active=%u\n",
		     granule_addr(g_rd), released, active_after);
	}
}

void handle_rsi_opencca_gpa_to_hpa(struct rec *rec, struct rsi_result *res)
{
	unsigned long array_ipa = rec->regs[1];
	unsigned long count = rec->regs[2];
	unsigned long i;

	res->action = UPDATE_REC_RETURN_TO_REALM;

	if (!GRANULE_ALIGNED(array_ipa) ||
	    !addr_in_rec_par(rec, array_ipa) ||
	    (count == 0UL) ||
	    (count > OPENCCA_GPA_TO_HPA_MAX_ENTRIES)) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		return;
	}

	for (i = 0UL; i < count; i++) {
		enum s2_walk_status walk_status;
		unsigned long ipa;
		unsigned long pa;
		unsigned long rtt_level = 0UL;
		enum ripas ripas = RIPAS_EMPTY;

		if (!opencca_gpu_read_entry(rec, array_ipa, i, &ipa, res)) {
			return;
		}

		if (!GRANULE_ALIGNED(ipa) || !addr_in_rec_par(rec, ipa)) {
			res->smc_res.x[0] = RSI_ERROR_INPUT;
			return;
		}

		walk_status = opencca_gpu_ipa_to_pa(rec, ipa, &pa, &rtt_level,
						    &ripas);
		if (walk_status == WALK_INVALID_PARAMS ||
		    (walk_status == WALK_FAIL && ripas == RIPAS_EMPTY)) {
			res->smc_res.x[0] = RSI_ERROR_INPUT;
			return;
		}

		if (walk_status == WALK_FAIL) {
			res->action = STAGE_2_TRANSLATION_FAULT;
			res->rtt_level = rtt_level;
			return;
		}

		if (!opencca_gpu_track_mapping(rec, pa, res)) {
			return;
		}

		if (!opencca_gpu_write_entry(rec, array_ipa, i, pa, res)) {
			opencca_gpu_untrack_hpa(rec, pa);
			return;
		}
	}

	res->smc_res.x[0] = RSI_SUCCESS;
}

void handle_rsi_opencca_gpu_revoke(struct rec *rec, struct rsi_result *res)
{
	unsigned long array_ipa = rec->regs[1];
	unsigned long count = rec->regs[2];
	unsigned long i;

	res->action = UPDATE_REC_RETURN_TO_REALM;

	if (!GRANULE_ALIGNED(array_ipa) ||
	    !addr_in_rec_par(rec, array_ipa) ||
	    (count == 0UL) ||
	    (count > OPENCCA_GPA_TO_HPA_MAX_ENTRIES)) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		return;
	}

	for (i = 0UL; i < count; i++) {
		unsigned long hpa;

		if (!opencca_gpu_read_entry(rec, array_ipa, i, &hpa, res)) {
			return;
		}

		if (!GRANULE_ALIGNED(hpa)) {
			res->smc_res.x[0] = RSI_ERROR_INPUT;
			return;
		}

		opencca_gpu_untrack_hpa(rec, hpa);
	}

	res->smc_res.x[0] = RSI_SUCCESS;
}
