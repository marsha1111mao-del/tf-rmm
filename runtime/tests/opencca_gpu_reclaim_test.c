/* SPDX-License-Identifier: BSD-3-Clause */
/* Actual private/device core and RSI/PM functions; lifecycle/GPU doubles only. */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <opencca_gpu.h>
#include <opencca_gpu_private.h>
#include <stdio.h>
#include <string.h>

#define PAGE 4096UL
#define IPA 0x400000UL
#define PA 0x60000000UL
#define PAGES 513U
#define RMI_SUCCESS 0UL
#define RMI_ERROR_INPUT 1UL
#define REALM_NEW 0U
#define REALM_ACTIVE 1U
#define REALM_SYSTEM_OFF 2U
#define SLOT_RD 0U
#define GRANULE_STATE_RD 1U
struct rd { unsigned int state; };
struct granule { unsigned int state, refs; bool locked; struct rd rd; };
struct smc_result { unsigned long x[8]; };
static struct granule realms[3];
static unsigned char arena[PAGES][PAGE];
static bool visible[PAGES];
static unsigned int fail_clear = UINT_MAX, fail_restore = UINT_MAX;
static unsigned int clears, restores, resets, firmware_retires;
static bool reset_ok = true;
static unsigned int cases;
static int opencca_gpu_mappings_lock;
static const unsigned char *table_base;

static struct granule *find_lock_granule(unsigned long address, unsigned int state)
{
	for (unsigned int i = 0U; i < 3U; i++) {
		struct granule *g = &realms[i];

		if (address != (unsigned long)g || g->state != state)
			continue;
		assert(!g->locked);
		g->locked = true;
		return g;
	}
	return NULL;
}
static unsigned int granule_refcount_read(struct granule *g)
{ assert(g->locked); return g->refs; }
static void *buffer_granule_map(struct granule *g, unsigned int slot)
{ assert(g->locked && slot == SLOT_RD); return &g->rd; }
static unsigned int get_rd_state_locked(struct rd *rd) { return rd->state; }
static void buffer_unmap(void *p) { assert(p != NULL); }
static void granule_unlock(struct granule *g) { assert(g->locked); g->locked = false; }
static void spinlock_acquire(int *lock) { assert(!*lock); *lock = 1; }
static void spinlock_release(int *lock) { assert(*lock); *lock = 0; }
static bool reset(bool preserve)
{ assert(!preserve); resets++; return reset_ok; }
static bool revoke(const void *owner) { return owner == &realms[0]; }
static bool opp_valid(unsigned long frequency) { return frequency != 0UL; }
unsigned long plat_opencca_gpu_pa_bits(void) { return 40UL; }
static void gpu_firmware_device_revoked(void) { firmware_retires++; }
static const struct opencca_gpu_ops gpu_ops = {
	.reset = reset, .revoke_mmio = revoke, .opp_valid = opp_valid
};

static bool source(const void *owner, unsigned long ipa, unsigned long *pa)
{
	if (ipa < IPA || (ipa - IPA) % PAGE != 0UL ||
	    gpu_private_range_busy(owner, ipa, PAGE))
		return false;
	unsigned long index = (ipa - IPA) / PAGE;

	if (owner == &realms[0]) {
		if (index >= PAGES || !visible[index])
			return false;
		*pa = PA + index * PAGE;
		return true;
	}
	if ((owner == &realms[1] || owner == &realms[2]) && index < PAGES) {
		*pa = PA + (owner == &realms[1] ? 0x1000000UL : 0x2000000UL) + index * PAGE;
		return true;
	}
	return false;
}
static unsigned long table_pa(const void *table)
{
	if (table_base == NULL)
		table_base = table;
	return 0x70000000UL + (unsigned long)((const unsigned char *)table - table_base);
}
static void clean(const void *memory, size_t bytes) { assert(memory && bytes); }
static bool hide(const void *owner, unsigned long ipa, unsigned long pa)
{
	unsigned int i = (unsigned int)((pa - PA) / PAGE);

	assert(owner == &realms[0] && !realms[0].locked && i < PAGES);
	assert(visible[i] && ipa == IPA + i * PAGE);
	visible[i] = false;
	return true;
}
static bool clear(unsigned long pa)
{
	unsigned int i = (unsigned int)((pa - PA) / PAGE);

	assert(i < PAGES && !visible[i]);
	if (i == fail_clear)
		return false;
	memset(arena[i], 0, PAGE);
	clears++;
	return true;
}
static bool restore(const void *owner, unsigned long ipa, unsigned long pa)
{
	unsigned int i = (unsigned int)((pa - PA) / PAGE);

	assert(owner == &realms[0] && !realms[0].locked && i < PAGES);
	assert(!visible[i] && ipa == IPA + i * PAGE);
	assert(gpu_private_range_busy(owner, ipa, PAGE));
	for (unsigned int j = 0U; j < PAGE; j++)
		assert(arena[i][j] == 0U);
	if (i == fail_restore)
		return false;
	visible[i] = true;
	restores++;
	return true;
}
static const struct gpu_private_ops operations = {
	.source_page = source, .table_pa = table_pa, .clean = clean,
	.hide_page = hide, .clear_page = clear, .restore_page = restore
};
/* Host helper invokes the actual RMM PM function unless a malformed transport
 * reply is explicitly injected. No Host "stopped" argument bypasses RMM.
 */
#define SMC_RMI_OPENCCA_GPU_PM 0x016eUL
#define RMI_OPENCCA_GPU_PRIVATE_RECLAIM OPENCCA_GPU_PRIVATE_RECLAIM
#define RMI_OPENCCA_GPU_RELEASE OPENCCA_GPU_RELEASE
#define RMI_OPENCCA_GPU_PRIVATE_SUCCESS GPU_PRIVATE_SUCCESS
#define RMI_OPENCCA_GPU_PRIVATE_STATE GPU_PRIVATE_STATE
#define RMI_OPENCCA_GPU_PRIVATE_INCOMPLETE GPU_PRIVATE_INCOMPLETE
struct arm_smccc_res { unsigned long a0, a1, a2, a3; };
struct realm { void *rd; };
static unsigned int host_calls, reschedules, bad_transport;
static unsigned long virt_to_phys(const void *p) { return (unsigned long)p; }
static void cond_resched(void) { reschedules++; }
void smc_opencca_gpu_pm(unsigned long op, unsigned long arg,
		unsigned long error, struct smc_result *r);
static void arm_smccc_1_1_smc(unsigned long fid, unsigned long op,
		unsigned long arg, unsigned long error, unsigned long a4,
		unsigned long a5, unsigned long a6, unsigned long a7,
		struct arm_smccc_res *result)
{
	struct smc_result r;

	assert(fid == SMC_RMI_OPENCCA_GPU_PM && !(error | a4 | a5 | a6 | a7));
	host_calls++;
	if (bad_transport != 0U) {
		*result = (struct arm_smccc_res){ .a0 = RMI_SUCCESS,
			.a2 = bad_transport == 1U ? GPU_PRIVATE_INCOMPLETE : GPU_PRIVATE_FULL };
		return;
	}
	smc_opencca_gpu_pm(op, arg, error, &r);
	*result = (struct arm_smccc_res){r.x[0], r.x[1], r.x[2], r.x[3]};
}
#include "actual.inc"

static struct smc_result reclaim(unsigned int owner)
{
	struct smc_result r;

	smc_opencca_gpu_pm(OPENCCA_GPU_PRIVATE_RECLAIM, (unsigned long)&realms[owner], 0UL, &r);
	assert(!realms[owner].locked);
	return r;
}
static unsigned long object(unsigned int owner, unsigned int pages)
{
	struct gpu_private_result r;

	gpu_private_bo_create(&realms[owner], &realms[0], pages * PAGE,
		GPU_PRIVATE_READ | GPU_PRIVATE_WRITE, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	return r.value[0];
}
static unsigned long context(unsigned int owner)
{
	struct gpu_private_result r;

	gpu_private_context_create(&operations, &realms[owner], &realms[0], &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	return r.value[0];
}
static void append(unsigned int owner, unsigned long bo, unsigned int count, bool control)
{
	struct gpu_private_result r;
	unsigned long ipas[GPU_PRIVATE_BATCH];

	for (unsigned int first = 0U; first < count; first += GPU_PRIVATE_BATCH) {
		unsigned int n = count - first;
		if (n > GPU_PRIVATE_BATCH)
			n = GPU_PRIVATE_BATCH;
		for (unsigned int j = 0U; j < n; j++)
			ipas[j] = IPA + (first + j) * PAGE;
		if (control)
			gpu_private_control_append(&operations, &realms[owner], bo,
				first * PAGE, ipas, n, &r);
		else
			gpu_private_bo_append(&operations, &realms[owner], bo,
				first * PAGE, ipas, n, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS);
	}
}
static void expect(struct smc_result r, unsigned long transport, unsigned long status)
{ assert(r.x[0] == transport && r.x[2] == status); cases++; }

int main(void)
{
	struct gpu_private_result r;
	struct smc_result s;
	unsigned long bo1, bo2, ctx1, ctx2, control;
	unsigned int arena_pages;

	for (unsigned int i = 0U; i < 3U; i++) {
		realms[i].state = GRANULE_STATE_RD;
		realms[i].rd.state = REALM_ACTIVE;
		realms[i].refs = 1U;
	}
	for (unsigned int i = 0U; i < PAGES; i++)
		visible[i] = true;
	smc_opencca_gpu_pm(OPENCCA_GPU_PRIVATE_RECLAIM, 1UL, 0UL, &s);
	expect(s, RMI_ERROR_INPUT, GPU_PRIVATE_INPUT);
	smc_opencca_gpu_pm(OPENCCA_GPU_PRIVATE_RECLAIM, (unsigned long)&realms[0], 1UL, &s);
	assert(s.x[0] == RMI_ERROR_INPUT && resets == 0U); cases++;
	/* No owned registrations: ordinary Realms need no GPU release. */
	expect(reclaim(1U), RMI_SUCCESS, GPU_PRIVATE_SUCCESS);
	bo1 = object(1U, PAGES); append(1U, bo1, PAGES, false);
	bo2 = object(2U, 1U); append(2U, bo2, 1U, false);
	ctx1 = context(1U); ctx2 = context(2U);
	gpu_private_map(&operations, &realms[1], ctx1, bo1, 0UL, 0x800000UL, 1U,
		GPU_PRIVATE_READ, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	gpu_private_map_authorize(&realms[2], ctx2, bo2, 0UL, 0x900000UL, 1U,
		GPU_PRIVATE_READ, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	/* Both a stopped REC and an ACTIVE context prevent cleanup. */
	expect(reclaim(1U), RMI_ERROR_INPUT, GPU_PRIVATE_INPUT);
	realms[1].refs = 0U;
	expect(reclaim(1U), RMI_ERROR_INPUT, GPU_PRIVATE_STATE);
	assert(gpu_private_range_busy(&realms[1], IPA, PAGE));
	smc_opencca_gpu_pm(OPENCCA_GPU_POWER_ON, 0UL, 0UL, &s);
	assert(s.x[0] == RMI_SUCCESS);
	assert(opencca_gpu_mmio_grant(&realms[0]) && opencca_gpu_claim(&realms[0]));
	expect(reclaim(1U), RMI_ERROR_INPUT, GPU_PRIVATE_STATE);
	reset_ok = false;
	smc_opencca_gpu_pm(OPENCCA_GPU_RELEASE, 0UL, 0UL, &s);
	assert(s.x[0] != RMI_SUCCESS && firmware_retires == 0U);
	expect(reclaim(1U), RMI_ERROR_INPUT, GPU_PRIVATE_STATE);
	reset_ok = true;
	smc_opencca_gpu_pm(OPENCCA_GPU_RELEASE, 0UL, 0UL, &s);
	assert(s.x[0] == RMI_SUCCESS && firmware_retires == 1U);
	/* No live REC, but NEW permits future REC creation and is rejected. */
	realms[1].rd.state = REALM_NEW;
	expect(reclaim(1U), RMI_ERROR_INPUT, GPU_PRIVATE_INPUT);
	realms[1].rd.state = REALM_ACTIVE;
	expect(reclaim(1U), RMI_SUCCESS, GPU_PRIVATE_INCOMPLETE);
	assert(gpu_private_range_busy(&realms[1], IPA, PAGE));
	assert(!gpu_private_range_busy(&realms[1], IPA + PAGE, PAGE));
	assert(gpu_private_range_busy(&realms[2], IPA, PAGE));
	expect(reclaim(1U), RMI_SUCCESS, GPU_PRIVATE_SUCCESS);
	assert(!gpu_private_owner_busy(&realms[1]) && gpu_private_owner_busy(&realms[2]));
	gpu_private_bo_destroy(&realms[1], bo1, &r);
	assert(r.status == GPU_PRIVATE_INPUT); cases++;
	gpu_private_context_destroy(&operations, &realms[1], ctx1, &r);
	assert(r.status == GPU_PRIVATE_INPUT); cases++;
	expect(reclaim(1U), RMI_SUCCESS, GPU_PRIVATE_SUCCESS);
	/* Donate an arena; a dead service cannot use Client liveness as proof. */
	gpu_private_control_create(&realms[0], PAGES * PAGE, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS); control = r.value[0];
	append(0U, control, PAGES, true);
	assert(gpu_private_control_acquire(&operations, &realms[0], control, &arena_pages));
	memset(arena, 0xcc, sizeof(arena)); clears = restores = 0U;
	expect(reclaim(0U), RMI_ERROR_INPUT, GPU_PRIVATE_INPUT);
	realms[0].refs = 0U;
	/* Reacquired GPU references after reset are also checked by the core. */
	expect(reclaim(0U), RMI_ERROR_INPUT, GPU_PRIVATE_STATE);
	gpu_private_control_release(&realms[0], control);
	fail_clear = PAGES - 1U;
	expect(reclaim(0U), RMI_ERROR_INPUT, GPU_PRIVATE_STATE);
	assert(!visible[PAGES - 1U] && restores == 0U && clears == 0U);
	assert(gpu_private_range_busy(&realms[2], IPA, PAGE));
	fail_clear = UINT_MAX; fail_restore = PAGES - 1U;
	expect(reclaim(0U), RMI_ERROR_INPUT, GPU_PRIVATE_STATE);
	assert(!visible[PAGES - 1U] && restores == 0U && clears == 1U);
	fail_restore = UINT_MAX;
	expect(reclaim(0U), RMI_SUCCESS, GPU_PRIVATE_INCOMPLETE);
	assert(restores == GPU_PRIVATE_BATCH && !visible[0] && visible[1]);
	assert(gpu_private_owner_busy(&realms[0]) && gpu_private_owner_busy(&realms[2]));
	expect(reclaim(0U), RMI_SUCCESS, GPU_PRIVATE_SUCCESS);
	assert(restores == PAGES && !gpu_private_owner_busy(&realms[0]));
	assert(gpu_private_range_busy(&realms[2], IPA, PAGE));
	/* Dead service pointers were detached; even the same RD address cannot
	 * import the living Client's old BO/context after its RD is recycled.
	 */
	gpu_private_bo_inspect(&realms[0], &realms[2], bo2, &r);
	assert(r.status != GPU_PRIVATE_SUCCESS); cases++;
	assert(!gpu_private_context_hold(&realms[0], &realms[2], ctx2)); cases++;
	/* Service RD can retire before another Client; cleanup also works after
	 * the device becomes UNOWNED and then OFF, without trusting a Host flag.
	 */
	assert(opencca_gpu_pm_destroy_begin(&realms[0]));
	opencca_gpu_mmio_release(&realms[0]);
	assert(gpu_private_raw_access_blocked());
	assert(smc_opencca_gpu_mmio_grant((unsigned long)&realms[0]) == RMI_ERROR_INPUT); cases++;
	assert(opencca_gpu_state() == OPENCCA_GPU_UNOWNED);
	expect(reclaim(2U), RMI_ERROR_INPUT, GPU_PRIVATE_INPUT);
	smc_opencca_gpu_pm(OPENCCA_GPU_POWER_OFF, 0UL, 0UL, &s);
	assert(s.x[0] == RMI_SUCCESS);
	realms[2].refs = 0U; realms[2].rd.state = REALM_SYSTEM_OFF;
	expect(reclaim(2U), RMI_SUCCESS, GPU_PRIVATE_SUCCESS);
	assert(!gpu_private_owner_busy(&realms[2]));
	assert(!gpu_private_raw_access_blocked());
	/* Exercise the real Host helper against the real RMM entry/core. */
	struct realm host_realm = { .rd = &realms[1] };

	smc_opencca_gpu_pm(OPENCCA_GPU_POWER_ON, 0UL, 0UL, &s);
	assert(s.x[0] == RMI_SUCCESS);
	assert(smc_opencca_gpu_mmio_grant((unsigned long)&realms[0]) == RMI_SUCCESS);
	assert(opencca_gpu_claim(&realms[0])); cases++;
	bo1 = object(1U, PAGES); append(1U, bo1, PAGES, false);
	ctx1 = context(1U); (void)ctx1;
	bo2 = object(2U, 1U); append(2U, bo2, 1U, false);
	ctx2 = context(2U);
	realms[1].refs = 1U;
	host_calls = 0U;
	unsigned int old_resets = resets;

	assert(realm_reclaim_private_gpu(&host_realm) == -EIO && host_calls == 1U);
	assert(resets == old_resets && gpu_private_owner_busy(&realms[1])); cases++;
	realms[1].refs = 0U;
	reset_ok = false;
	assert(realm_reclaim_private_gpu(&host_realm) == -EIO);
	assert(resets == old_resets + 1U && gpu_private_owner_busy(&realms[1])); cases++;
	reset_ok = true; host_calls = reschedules = 0U;
	assert(realm_reclaim_private_gpu(&host_realm) == 0 && host_calls == 4U);
	assert(reschedules == 2U && !gpu_private_owner_busy(&realms[1]));
	assert(gpu_private_range_busy(&realms[2], IPA, PAGE)); cases++;
	/* A fabricated unexpected success is rejected; perpetual INCOMPLETE
	 * cannot monopolize the Host thread or authorize DATA/RD release.
	 */
	bad_transport = 1U; host_calls = reschedules = 0U;
	assert(realm_reclaim_private_gpu(&host_realm) == -ETIMEDOUT);
	assert(host_calls == 2049U && reschedules == 2049U); cases++;
	bad_transport = 2U; host_calls = 0U;
	assert(realm_reclaim_private_gpu(&host_realm) == -EIO && host_calls == 1U); cases++;
	bad_transport = 0U;
	gpu_private_context_destroy(&operations, &realms[2], ctx2, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	gpu_private_bo_destroy(&realms[2], bo2, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	printf("GPU_PRIVATE_RECLAIM=PASS cases=%u actual-core/RSI/PM/Host-helper; HOST_DOUBLES_ONLY\n", cases);
	return 0;
}
