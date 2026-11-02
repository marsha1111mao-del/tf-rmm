/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <opencca_gpu_private.h>
#include <opencca_iommu.h>
#include <smc-rmi.h>
#include <stdio.h>
#include <string.h>
#include <xshm_runtime.h>
#include "rtt-stubs/control_rtt_model.h"

#define IPA 0x400000UL
#define PA 0x60000000UL
#define PAGES 4U

static unsigned long entries[512];
static unsigned char contents[PAGES][4096];
static struct granule rtt = { .state = GRANULE_STATE_RTT, .memory = entries, .refs = PAGES };
static struct rd rd = { .s2_ctx = { .g_rtt = &rtt } };
static struct granule owner = { .state = GRANULE_STATE_RD, .memory = &rd };
static struct granule data[PAGES];
static unsigned int writes, invalidations;
static int walk_level = 3;
static unsigned long ram_attrs = 0x3fUL; /* OpenCCA non-FWB RAM: MemAttr=1111. */

void granule_lock(struct granule *g, enum granule_state state)
{
	assert(g != NULL && !g->locked && g->state == state);
	g->locked = true;
}
void granule_unlock(struct granule *g) { assert(g->locked); g->locked = false; }
struct granule *find_granule(unsigned long pa)
{
	if (pa == (unsigned long)&owner)
		return &owner;
	for (unsigned int i = 0U; i < PAGES; i++)
		if (data[i].pa == pa)
			return &data[i];
	return NULL;
}
struct granule *find_lock_granule(unsigned long pa, enum granule_state state)
{
	struct granule *g = find_granule(pa);

	if (g == NULL || g->state != state)
		return NULL;
	granule_lock(g, state);
	return g;
}
void atomic_granule_get(struct granule *g) { g->refs++; }
void atomic_granule_put(struct granule *g) { assert(g->refs); g->refs--; }
void *buffer_granule_map(struct granule *g, unsigned int slot)
{
	assert(g->locked && ((g == &owner && slot == SLOT_RD) || (g == &rtt && slot == SLOT_RTT)));
	return g->memory;
}
void buffer_unmap(void *memory) { assert(memory == &rd || memory == entries); }
bool addr_in_par(const struct rd *desc, unsigned long ipa)
{
	assert(desc == &rd);
	return ipa >= IPA && ipa < IPA + PAGES * 4096UL;
}
void s2tt_walk_lock_unlock(const struct s2tt_context *ctx, unsigned long ipa,
		int level, struct s2tt_walk *wi)
{
	assert(ctx->g_rtt == &rtt && rtt.locked && level == 3);
	*wi = (struct s2tt_walk){ .g_llt = &rtt, .index = (ipa >> 12U) & 511UL, .last_level = walk_level };
}
unsigned long s2tte_read(const unsigned long *entry) { assert(rtt.locked); return *entry; }
void s2tte_write(unsigned long *entry, unsigned long value) { assert(rtt.locked); *entry = value; writes++; }
bool s2tte_is_assigned_ram(const struct s2tt_context *ctx, unsigned long entry, long level)
{ (void)ctx; (void)level; return (entry & 3UL) == 3UL; }
bool s2tte_is_assigned_empty(const struct s2tt_context *ctx, unsigned long entry, long level)
{ (void)ctx; (void)level; return (entry & 4095UL) == 16UL; }
bool s2tte_is_unassigned_ram(const struct s2tt_context *ctx, unsigned long entry)
{ (void)ctx; return entry == 32UL; }
unsigned long s2tte_pa(const struct s2tt_context *ctx, unsigned long entry, long level)
{ (void)ctx; (void)level; return entry & ~4095UL; }
unsigned long s2tte_create_assigned_ram(const struct s2tt_context *ctx, unsigned long pa, long level)
{ (void)ctx; (void)level; return pa | ram_attrs; }
unsigned long s2tte_create_assigned_empty(const struct s2tt_context *ctx, unsigned long pa, long level)
{ (void)ctx; (void)level; return pa | 16UL; }
unsigned long s2tte_create_unassigned_ram(const struct s2tt_context *ctx) { (void)ctx; return 32UL; }
void s2tt_invalidate_page(const struct s2tt_context *ctx, unsigned long ipa)
{
	assert(ctx->g_rtt == &rtt && rtt.locked && GRANULE_ALIGNED(ipa));
	assert(writes == invalidations + 1U);
	invalidations++;
}
bool xshm_memory_owner_busy(const void *o) { (void)o; return false; }
bool xshm_memory_range_busy(const void *o, unsigned long a, unsigned long b)
{ (void)o; (void)a; (void)b; return false; }
bool opencca_iommu_owner_busy(const void *o) { (void)o; return false; }
bool opencca_iommu_range_busy(const void *o, unsigned long a, unsigned long b)
{ (void)o; (void)a; (void)b; return false; }

static bool source(const void *o, unsigned long ipa, unsigned long *pa)
{
	return !gpu_private_range_busy(o, ipa, 4096UL) && xshm_rtt_ops.source_page(o, ipa, pa);
}
static bool clear(unsigned long pa)
{
	unsigned int index = (unsigned int)((pa - PA) / 4096UL);

	assert(index < PAGES && s2tte_is_assigned_empty(&rd.s2_ctx, entries[index], 3));
	assert(invalidations == writes); /* Hide completed its TLBI first. */
	memset(contents[index], 0, 4096U);
	return true;
}
static void clean(const void *memory, size_t bytes)
{
	assert(memory != NULL && bytes != 0U);
}
static bool sync_device(unsigned long pa)
{
    unsigned int index = (unsigned int)((pa - PA) / 4096UL);
    assert(index < PAGES && s2tte_is_assigned_empty(&rd.s2_ctx, entries[index], 3));
    assert(invalidations == writes && contents[index][0] == 0x7b);
    return true;
}
static bool barrier(void) { return true; }
static const struct gpu_private_ops ops = {
	.source_page = source, .hide_page = gpu_control_rtt_hide,
	.restore_page = gpu_control_rtt_restore, .clear_page = clear, .clean = clean,
    .sync_page_for_device = sync_device,
    .restore_page_uncached = gpu_private_rtt_restore_uncached, .cache_barrier = barrier
};

int main(void)
{
	struct gpu_private_result result;
	unsigned long ipas[PAGES], object, translated;

	for (unsigned int i = 0U; i < PAGES; i++) {
		data[i] = (struct granule){ .state = GRANULE_STATE_DATA, .pa = PA + i * 4096UL };
		entries[i] = data[i].pa | ram_attrs;
		ipas[i] = IPA + i * 4096UL;
	}
	memset(contents, 0xcc, sizeof(contents));
	assert(!gpu_control_rtt_hide(&owner, IPA + 1UL, PA));
	assert(!gpu_control_rtt_hide(&owner, IPA, PA + 4096UL));
	walk_level = 2;
	assert(!gpu_control_rtt_hide(&owner, IPA, PA));
	walk_level = 3;
	data[0].state = GRANULE_STATE_NS;
	assert(!gpu_control_rtt_hide(&owner, IPA, PA));
	data[0].state = GRANULE_STATE_DATA;
	assert(writes == 0U && invalidations == 0U && rtt.refs == PAGES);
	gpu_private_control_create(&owner, sizeof(contents), &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	object = result.value[0];
	gpu_private_control_append(&ops, &owner, object, 0UL, ipas, PAGES, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && invalidations == PAGES);
	for (unsigned int i = 0U; i < PAGES; i++) {
		assert(s2tte_is_assigned_empty(&rd.s2_ctx, entries[i], 3));
		assert((entries[i] & ~4095UL) == data[i].pa && data[i].state == GRANULE_STATE_DATA);
		assert(!xshm_rtt_ops.source_page(&owner, ipas[i], &translated));
		assert(!gpu_control_rtt_hide(&owner, ipas[i], data[i].pa));
	}
	assert(rtt.refs == PAGES && !owner.locked && !rtt.locked);
	assert(!xshm_rmi_allowed(SMC_RMI_RTT_SET_RIPAS, (unsigned long)&owner, 0UL, IPA, IPA + sizeof(contents)));
	assert(!xshm_rmi_allowed(SMC_RMI_DATA_DESTROY, (unsigned long)&owner, IPA, 0UL, 0UL));
	assert(!xshm_rmi_allowed(SMC_RMI_RTT_FOLD, (unsigned long)&owner, IPA, 3UL, 0UL));
	assert(!xshm_rmi_allowed(SMC_RMI_REALM_DESTROY, (unsigned long)&owner, 0UL, 0UL, 0UL));
	gpu_private_control_destroy(&ops, &owner, object, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && invalidations == 2U * PAGES);
	assert(rtt.refs == PAGES && !owner.locked && !rtt.locked);
	for (unsigned int i = 0U; i < PAGES; i++) {
		assert(xshm_rtt_ops.source_page(&owner, ipas[i], &translated) && translated == data[i].pa);
		assert(!gpu_control_rtt_restore(&owner, ipas[i], data[i].pa));
	}
	assert(xshm_rmi_allowed(SMC_RMI_RTT_SET_RIPAS, (unsigned long)&owner, 0UL, IPA, IPA + sizeof(contents)));
	assert(xshm_rmi_allowed(SMC_RMI_REALM_DESTROY, (unsigned long)&owner, 0UL, 0UL, 0UL));
	/* Dead-owner core cleanup uses the same actual RTT restore and policy
	 * gates as a living Guest's CONTROL_DESTROY. RD/REC eligibility is tested
	 * separately against the actual RSI/PM adapter and Host helper.
	 */
	gpu_private_control_create(&owner, sizeof(contents), &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	object = result.value[0];
	gpu_private_control_append(&ops, &owner, object, 0UL, ipas, PAGES, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	memset(contents, 0x5a, sizeof(contents));
	assert(!xshm_rmi_allowed(SMC_RMI_DATA_DESTROY, (unsigned long)&owner, IPA, 0UL, 0UL));
	gpu_private_device_revoked(&ops);
	gpu_private_owner_reclaim(&ops, &owner, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && rtt.refs == PAGES);
	assert(!owner.locked && !rtt.locked && writes == 4U * PAGES && invalidations == writes);
	assert(xshm_rmi_allowed(SMC_RMI_DATA_DESTROY, (unsigned long)&owner, IPA, 0UL, 0UL));
	assert(xshm_rmi_allowed(SMC_RMI_REALM_DESTROY, (unsigned long)&owner, 0UL, 0UL, 0UL));
	gpu_private_control_destroy(&ops, &owner, object, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
    /* Resident Client data preserves initialization, but has exactly the
     * same real assigned-empty RTT and RMI mutation gates as control pages. */
    int service;
    memset(contents, 0x7b, sizeof(contents));
    gpu_private_bo_create(&owner, &service, sizeof(contents), 3UL, &result);
    assert(result.status == GPU_PRIVATE_SUCCESS);object = result.value[0];
    gpu_private_bo_append(&ops, &owner, object, 0UL, ipas, PAGES, &result);
    assert(result.status == GPU_PRIVATE_SUCCESS);
    gpu_private_bo_seal(&ops, &owner, object, &result);
    assert(!result.status && result.value[0] == PAGES && writes == 5U * PAGES);
    for (unsigned int i = 0U; i < PAGES; i++) {
        assert(!xshm_rtt_ops.source_page(&owner, ipas[i], &translated));
        for (unsigned int j = 0U; j < 4096U; j++) assert(contents[i][j] == 0x7b);
    }
    assert(!xshm_rmi_allowed(SMC_RMI_RTT_SET_RIPAS, (unsigned long)&owner, 0UL, IPA, IPA + sizeof(contents)));
    assert(!xshm_rmi_allowed(SMC_RMI_DATA_DESTROY, (unsigned long)&owner, IPA, 0UL, 0UL));
    assert(!xshm_rmi_allowed(SMC_RMI_RTT_FOLD, (unsigned long)&owner, IPA, 3UL, 0UL));
    gpu_private_bo_destroy(&owner, object, &result);assert(result.status);
    gpu_private_bo_release(&ops, &owner, object, &result);
    assert(!result.status && writes == 6U * PAGES && invalidations == writes && rtt.refs == PAGES);
    for (unsigned int i = 0U; i < PAGES; i++) {
        assert(xshm_rtt_ops.source_page(&owner, ipas[i], &translated));
        for (unsigned int j = 0U; j < 4096U; j++) assert(!contents[i][j]);
    }
    assert(xshm_rmi_allowed(SMC_RMI_DATA_DESTROY, (unsigned long)&owner, IPA, 0UL, 0UL));
	/* Actual RTT NC restore path, both default WB encodings. No transition
	 * may overwrite a live RAM leaf, wrong PA or non-DATA page. The model
	 * checks attributes/refcounts/TLBI ordering, not hardware cache behavior.
	 */
	for (unsigned int mode = 0U; mode < 2U; mode++) {
		ram_attrs = mode == 0U ? 0x3fUL : 0x1bUL;
		for (unsigned int i = 0U; i < PAGES; i++) entries[i] = data[i].pa | ram_attrs;
		assert(!gpu_private_rtt_restore_uncached(&owner, IPA, PA));
		memset(contents, 0x7b, sizeof(contents));
		gpu_private_bo_create(&owner, &service, sizeof(contents), 7UL, &result);
		assert(!result.status);object = result.value[0];
		gpu_private_bo_append(&ops, &owner, object, 0UL, ipas, PAGES, &result);assert(!result.status);
		unsigned int before = writes;
		gpu_private_bo_uncached(&ops, &owner, object, &result);
		assert(!result.status && result.value[0] == PAGES && writes == before + 2U * PAGES);
		for (unsigned int i = 0U; i < PAGES; i++) {
			assert(((entries[i] >> 2U) & 0xfUL) == 0x5UL);
			assert(xshm_rtt_ops.source_page(&owner, ipas[i], &translated) && translated == data[i].pa);
			assert(contents[i][0] == 0x7b);
		}
		assert(!xshm_rmi_allowed(SMC_RMI_DATA_DESTROY, (unsigned long)&owner, IPA, 0UL, 0UL));
		assert(!xshm_rmi_allowed(SMC_RMI_RTT_SET_RIPAS, (unsigned long)&owner, 0UL, IPA, IPA + sizeof(contents)));
		assert(!xshm_rmi_allowed(SMC_RMI_RTT_FOLD, (unsigned long)&owner, IPA, 3UL, 0UL));
		assert(gpu_control_rtt_hide(&owner, IPA, PA));
		assert(!gpu_private_rtt_restore_uncached(&owner, IPA, PA + 4096UL));
		data[0].state = GRANULE_STATE_NS;
		assert(!gpu_private_rtt_restore_uncached(&owner, IPA, PA));data[0].state = GRANULE_STATE_DATA;
		assert(gpu_private_rtt_restore_uncached(&owner, IPA, PA));
		gpu_private_bo_destroy(&owner, object, &result);assert(result.status);
		gpu_private_bo_release(&ops, &owner, object, &result);assert(!result.status);
		for (unsigned int i = 0U; i < PAGES; i++) assert(entries[i] == (data[i].pa | ram_attrs) && !contents[i][0]);
		assert(invalidations == writes && rtt.refs == PAGES && !owner.locked && !rtt.locked);
		assert(xshm_rmi_allowed(SMC_RMI_DATA_DESTROY, (unsigned long)&owner, IPA, 0UL, 0UL));
	}
	puts("GPU_CONTROL_RTT=PASS actual RTT/policy source, RAM-to-assigned-empty/restoration, DATA/PA/refcounts retained, TLBI before clear, wrong PA/state/level rejected, RIPAS/fold/DATA/Realm teardown blocked until retirement; MODEL_ONLY");
	return 0;
}
