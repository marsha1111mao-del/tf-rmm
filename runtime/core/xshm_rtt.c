/* SPDX-License-Identifier: BSD-3-Clause */
#include <buffer.h>
#include <granule.h>
#include <realm.h>
#include <s2tt.h>
#include <xshm_runtime.h>

static bool valid_range(const void *owner, unsigned long ipa, unsigned long size)
{
	struct granule *g_rd = (struct granule *)owner;
	struct rd *rd;
	bool valid;

	granule_lock(g_rd, GRANULE_STATE_RD);
	rd = buffer_granule_map(g_rd, SLOT_RD);
	valid = size != 0UL && ipa + size > ipa &&
		addr_in_par(rd, ipa) && addr_in_par(rd, ipa + size - 1UL);
	buffer_unmap(rd);
	granule_unlock(g_rd);
	return valid;
}

/* All callers hold the policy gate, which pins RD lifetime and source PA
 * ownership. Ordinary REC table walks still serialize on the RTT locks. */
static bool page(const void *owner, unsigned long ipa, unsigned long *pa,
		unsigned int operation)
{
	struct granule *g_rd = (struct granule *)owner;
	struct s2tt_context ctx;
	struct s2tt_walk wi;
	struct rd *rd;
	unsigned long *table, pte;
	bool success = false;

	granule_lock(g_rd, GRANULE_STATE_RD);
	rd = buffer_granule_map(g_rd, SLOT_RD);
	if (!GRANULE_ALIGNED(ipa) || !addr_in_par(rd, ipa)) {
		buffer_unmap(rd);
		granule_unlock(g_rd);
		return false;
	}
	ctx = rd->s2_ctx;
	buffer_unmap(rd);
	granule_lock(ctx.g_rtt, GRANULE_STATE_RTT);
	granule_unlock(g_rd);
	s2tt_walk_lock_unlock(&ctx, ipa, S2TT_PAGE_LEVEL, &wi);
	table = buffer_granule_map(wi.g_llt, SLOT_RTT);
	pte = s2tte_read(&table[wi.index]);
	if (operation == 0U) {
		/* Reject MMIO/NS mappings: a shareable PA must be owned DATA. */
		if (s2tte_is_assigned_ram(&ctx, pte, wi.last_level)) {
			struct granule *data;

			*pa = s2tte_pa(&ctx, pte, wi.last_level) +
				(ipa & (s2tte_map_size(wi.last_level) - 1UL));
			data = find_lock_granule(*pa, GRANULE_STATE_DATA);
			if (data != NULL) {
				granule_unlock(data);
				success = true;
			}
		}
	} else if (wi.last_level == S2TT_PAGE_LEVEL) {
		if (operation == 1U) {
			success = s2tte_is_unassigned_ram(&ctx, pte);
		} else if (operation == 2U) {
			if (s2tte_is_unassigned_ram(&ctx, pte) &&
			    (ctx.enable_lpa2 || (*pa < (1UL << S2TT_MAX_PA_BITS)))) {
				s2tte_write(&table[wi.index], s2tte_create_assigned_ram(
					&ctx, *pa, S2TT_PAGE_LEVEL));
				atomic_granule_get(wi.g_llt);
				/* Also discard any prior cached fault/translation. */
				s2tt_invalidate_page(&ctx, ipa);
				success = true;
			}
		} else if (s2tte_is_assigned_ram(&ctx, pte, S2TT_PAGE_LEVEL) &&
			   s2tte_pa(&ctx, pte, S2TT_PAGE_LEVEL) == *pa) {
			s2tte_write(&table[wi.index], s2tte_create_unassigned_ram(&ctx));
			s2tt_invalidate_page(&ctx, ipa);
			atomic_granule_put(wi.g_llt);
			success = true;
		}
	}
	buffer_unmap(table);
	granule_unlock(wi.g_llt);
	return success;
}

static bool source_page(const void *owner, unsigned long ipa, unsigned long *pa)
{
	return page(owner, ipa, pa, 0U);
}

static bool target_page(const void *owner, unsigned long ipa)
{
	unsigned long unused = 0UL;

	return page(owner, ipa, &unused, 1U);
}

static bool install(const void *owner, unsigned long ipa, unsigned long pa)
{
	return page(owner, ipa, &pa, 2U);
}

static bool restore(const void *owner, unsigned long ipa, unsigned long pa)
{
	return page(owner, ipa, &pa, 3U);
}

const struct xshm_memory_ops xshm_rtt_ops = {
	.valid_range = valid_range,
	.source_page = source_page,
	.target_page = target_page,
	.install = install,
	.restore = restore,
};
