/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <limits.h>
#include <opencca_gpu_lease.h>
#include <stdio.h>
#include <string.h>

static const unsigned char owner_a, owner_b;
static bool reset_ok = true;
static bool revoke_ok = true;
static unsigned int resets;
static unsigned int revokes;
static bool expect_revoke;
static bool revoked;
static bool isolating;

static bool reset(bool preserve_irqs)
{
	if (expect_revoke)
		assert(revoked && !preserve_irqs);
	if (isolating) {
		assert(!preserve_irqs);
		assert(!opencca_gpu_mmio_allowed(&owner_a));
		assert(!opencca_gpu_service_running(&owner_a));
		assert(opencca_gpu_lease_active() == 1U);
	}
	resets++;
	return reset_ok;
}

static bool revoke(const void *owner)
{
	assert(owner != NULL);
	if (isolating) {
		assert(owner == &owner_a);
		assert(!opencca_gpu_mmio_allowed(owner));
		assert(!opencca_gpu_mmio_grant(owner));
		assert(!opencca_gpu_claim(owner));
		assert(!opencca_gpu_service_running(owner));
		assert(opencca_gpu_lease_active() == 1U);
	}
	revokes++;
	revoked = revoke_ok;
	return revoke_ok;
}

static bool valid_opp(unsigned long frequency)
{
	return frequency == 600000000UL;
}

static const struct opencca_gpu_ops ops = { reset, revoke, valid_opp };

static bool control(unsigned long op, unsigned long argument, unsigned long error)
{
	return opencca_gpu_control(&ops, NULL, op, argument, error);
}

static unsigned long batch[OPENCCA_GPU_LEASE_BATCH];

static int service_isolation(void)
{
	unsigned long page = 0x80000000UL;
	unsigned int old_resets, old_revokes;

	assert(control(OPENCCA_GPU_POWER_ON, 0UL, 0UL));
	assert(!opencca_gpu_service_isolate(&ops, NULL));
	assert(!opencca_gpu_service_isolate(&ops, &owner_a));
	assert(opencca_gpu_mmio_grant(&owner_a));
	assert(!opencca_gpu_service_isolate(&ops, &owner_a)); /* not claimed */
	assert(opencca_gpu_claim(&owner_a));
	assert(opencca_gpu_service_running(&owner_a));
	assert(!opencca_gpu_service_isolated(&owner_a));
	assert(!opencca_gpu_service_running(&owner_b));
	assert(!opencca_gpu_service_isolate(&ops, &owner_b));
	assert(!opencca_gpu_service_isolate(NULL, &owner_a));
	assert(opencca_gpu_lease_acquire(&owner_a, &page, 1U));
	old_resets = resets;
	old_revokes = revokes;
	/* No reset or reclaim may precede a successful MMIO revocation. */
	isolating = true;
	revoke_ok = false;
	assert(!opencca_gpu_service_isolate(&ops, &owner_a));
	assert(resets == old_resets && revokes == old_revokes + 1U);
	assert(opencca_gpu_state() == OPENCCA_GPU_QUARANTINED);
	assert(opencca_gpu_lease_active() == 1U);
	assert(!opencca_gpu_service_isolated(&owner_a));
	assert(!opencca_gpu_mmio_allowed(&owner_a));
	/* Host RESET cannot turn a failed handoff into a direct-access owner. */
	isolating = false;
	assert(control(OPENCCA_GPU_RESET, 0UL, 0UL));
	assert(opencca_gpu_state() == OPENCCA_GPU_QUARANTINED);
	assert(!opencca_gpu_claim(&owner_a));
	assert(!opencca_gpu_mmio_grant(&owner_a));
	assert(!opencca_gpu_service_running(&owner_a));
	assert(opencca_gpu_lease_active() == 1U);

	isolating = true;
	revoke_ok = true;
	reset_ok = false;
	expect_revoke = true;
	assert(!opencca_gpu_service_isolate(&ops, &owner_a));
	assert(opencca_gpu_state() == OPENCCA_GPU_QUARANTINED);
	assert(opencca_gpu_lease_page_busy(page));
	assert(!opencca_gpu_service_running(&owner_a));
	reset_ok = true;
	assert(opencca_gpu_service_isolate(&ops, &owner_a));
	isolating = false;
	expect_revoke = false;
	assert(opencca_gpu_state() == OPENCCA_GPU_MEDIATED);
	assert(opencca_gpu_service_running(&owner_a));
	assert(opencca_gpu_service_isolated(&owner_a));
	assert(!opencca_gpu_mmio_running(&owner_a));
	assert(!opencca_gpu_mmio_allowed(&owner_a));
	assert(!opencca_gpu_claim(&owner_a));
	assert(!opencca_gpu_mmio_grant(&owner_a));
	assert(!opencca_gpu_mapping_allowed(&owner_a, 0x80fb000000UL,
		0xfb000000UL, 0x200000UL, 0x8000000000UL));
	assert(!opencca_gpu_mapping_allowed(&owner_b, 0x80fb000000UL,
		0xfb000000UL, 0x200000UL, 0x8000000000UL));
	assert(!opencca_gpu_mapping_allowed(&owner_a, 0x80fb001000UL,
		0xfb001000UL, 4096UL, 0x8000000000UL));
	assert(!opencca_gpu_lease_acquire(&owner_a, &page, 1U));
	assert(opencca_gpu_lease_active() == 0U);
	assert(!opencca_gpu_lease_page_busy(page));
	assert(opencca_gpu_pm_destroy_blocked(&owner_a));
	old_resets = resets;
	old_revokes = revokes;
	assert(opencca_gpu_service_isolate(&ops, &owner_a));
	assert(!opencca_gpu_service_isolate(&ops, &owner_b));
	assert(resets == old_resets && revokes == old_revokes);
	assert(!opencca_gpu_control(&ops, &owner_a, OPENCCA_GPU_RESET, 0UL, 0UL));
	assert(!control(OPENCCA_GPU_OPP_BEGIN, 600000000UL, 0UL));
	assert(control(OPENCCA_GPU_RESET, 0UL, 0UL));
	assert(opencca_gpu_service_isolated(&owner_a));
	assert(!opencca_gpu_claim(&owner_a));
	assert(control(OPENCCA_GPU_RELEASE, 0UL, 0UL));
	assert(!opencca_gpu_service_running(&owner_a));
	assert(!opencca_gpu_service_isolated(&owner_a));
	assert(control(OPENCCA_GPU_RESET, 0UL, 0UL));
	assert(!opencca_gpu_claim(&owner_a));
	assert(!opencca_gpu_mmio_grant(&owner_a));
	assert(opencca_gpu_pm_destroy_begin(&owner_a));
	opencca_gpu_mmio_release(&owner_a);
	/* Only a complete owner teardown permits a new, independent raw owner. */
	assert(opencca_gpu_mmio_grant(&owner_b));
	assert(opencca_gpu_claim(&owner_b));
	assert(!opencca_gpu_service_isolated(&owner_b));
	assert(control(OPENCCA_GPU_RELEASE, 0UL, 0UL));
	assert(opencca_gpu_pm_destroy_begin(&owner_b));
	opencca_gpu_mmio_release(&owner_b);
	assert(control(OPENCCA_GPU_POWER_OFF, 0UL, 0UL));
	puts("GPU_SERVICE_ISOLATION=PASS actual owner, revoke-before-reset, sticky failures, retained/released DMA refs, service identity without MMIO, no regrant/claim, idempotence and teardown");
	return 0;
}

int main(int argc, char **argv)
{
	unsigned long page = 0x80000000UL;
	unsigned long other = page + 4096UL;
	unsigned long mixed[] = { page, other };

	if (argc == 2 && strcmp(argv[1], "--service-isolation") == 0)
		return service_isolation();
	assert(argc == 1);

	assert(!control(OPENCCA_GPU_RESET, 0UL, 0UL));
	assert(control(OPENCCA_GPU_POWER_ON, 0UL, 0UL));
	assert(control(OPENCCA_GPU_RESET, 0UL, 0UL));
	assert(control(OPENCCA_GPU_OPP_BEGIN, 600000000UL, 0UL));
	assert(!control(OPENCCA_GPU_OPP_END, 500000000UL, 0UL));
	assert(control(OPENCCA_GPU_OPP_END, 600000000UL, 0UL));

	assert(!opencca_gpu_mmio_grant(NULL));
	assert(opencca_gpu_mmio_grant(&owner_a));
	assert(opencca_gpu_mmio_grant(&owner_a));
	assert(!opencca_gpu_mmio_grant(&owner_b));
	assert(opencca_gpu_mapping_allowed(&owner_a, 0x80fb000000UL,
					 0xfb000000UL, 0x200000UL, 0x8000000000UL));
	assert(!opencca_gpu_mapping_allowed(&owner_b, 0x80fb000000UL,
					  0xfb000000UL, 0x200000UL, 0x8000000000UL));
	assert(!opencca_gpu_mapping_allowed(&owner_a, 0x80fa000000UL,
					  0xfb000000UL, 0x200000UL, 0x8000000000UL));
	assert(!opencca_gpu_mapping_allowed(&owner_a, 0x100fb000000UL,
					  0xfb000000UL, 0x200000UL, 0x8000000000UL));
	assert(!opencca_gpu_mapping_allowed(&owner_a, 0x80fb001000UL,
					  0xfb001000UL, 4096UL, 0x8000000000UL));
	assert(!opencca_gpu_mapping_allowed(&owner_a, 0x80c0000000UL,
					  0xc0000000UL, 0x40000000UL, 0x8000000000UL));
	assert(opencca_gpu_mapping_allowed(NULL, 0x8080000000UL,
					 0x80000000UL, 4096UL, 0x8000000000UL));
	assert(!opencca_gpu_mapping_allowed(&owner_a, 0x80fb000000UL,
					  0x80000000UL, 0x200000UL, 0x8000000000UL));
	assert(!opencca_gpu_claim(&owner_b));
	assert(!opencca_gpu_lease_acquire(&owner_a, &page, 1U));
	assert(opencca_gpu_claim(&owner_a));

	assert(!opencca_gpu_lease_page_busy(page));
	assert(opencca_gpu_lease_page_busy(page + 1UL));
	assert(opencca_gpu_lease_page_busy(ULONG_MAX & ~4095UL));
	assert(opencca_gpu_lease_acquire(&owner_a, &page, 1U));
	assert(opencca_gpu_lease_acquire(&owner_a, &page, 1U));
	assert(opencca_gpu_lease_page_busy(page));
	assert(!opencca_gpu_lease_page_busy(other));
	opencca_gpu_lease_release(&owner_b, &page, 1U);
	assert(opencca_gpu_lease_page_busy(page));
	opencca_gpu_lease_release(&owner_a, &page, 1U);
	assert(opencca_gpu_lease_page_busy(page));
	opencca_gpu_lease_release(&owner_a, &page, 1U);
	assert(!opencca_gpu_lease_page_busy(page));

	assert(!opencca_gpu_lease_acquire(NULL, &page, 1U));
	assert(!opencca_gpu_lease_acquire(&owner_a, &page, 0U));
	assert(opencca_gpu_lease_acquire(&owner_a, &other, 1U));
	assert(!opencca_gpu_lease_acquire(&owner_b, &other, 1U));
	opencca_gpu_lease_release(&owner_a, &other, 1U);
	assert(opencca_gpu_lease_active() == 0U);
	/* Two buckets used to expose a premature release-owner stop when the
	 * number released happened to equal the remaining global count.
	 */
	assert(opencca_gpu_lease_acquire(&owner_a, mixed, 2U));
	assert(opencca_gpu_lease_release_owner(&owner_a) == 2U);
	assert(opencca_gpu_lease_active() == 0U);

	for (unsigned int n = 0U; n < USHRT_MAX; n++)
		assert(opencca_gpu_lease_acquire(&owner_a, &page, 1U));
	assert(!opencca_gpu_lease_acquire(&owner_a, &page, 1U));
	mixed[0] = page;
	mixed[1] = page;
	assert(!opencca_gpu_lease_acquire(&owner_a, mixed, 2U));
	for (unsigned int n = 0U; n < USHRT_MAX; n++)
		opencca_gpu_lease_release(&owner_a, &page, 1U);
	assert(opencca_gpu_lease_active() == 0U);

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
	assert(opencca_gpu_lease_active() ==
	       OPENCCA_GPU_LEASE_CAPACITY - 1U);
	assert(opencca_gpu_lease_release_owner(&owner_a) ==
	       OPENCCA_GPU_LEASE_CAPACITY - 1U);
	assert(opencca_gpu_lease_active() == 0U);

	assert(control(OPENCCA_GPU_RELEASE, 0UL, 0UL));
	assert(!opencca_gpu_mmio_grant(&owner_a));
	assert(opencca_gpu_pm_destroy_begin(&owner_a));
	opencca_gpu_mmio_release(&owner_a);
	assert(opencca_gpu_mmio_grant(&owner_b));
	assert(opencca_gpu_claim(&owner_b));
	assert(opencca_gpu_lease_acquire(&owner_b, &other, 1U));
	assert(opencca_gpu_lease_release_owner(&owner_b) == 1U);
	assert(opencca_gpu_lease_acquire(&owner_b, &page, 1U));

	assert(opencca_gpu_pm_destroy_blocked(&owner_b));
	assert(!opencca_gpu_control(&ops, &owner_a, OPENCCA_GPU_RESET, 0UL, 0UL));
	assert(!opencca_gpu_control(&ops, &owner_b, OPENCCA_GPU_RELEASE, 0UL, 0UL));
	assert(!control(OPENCCA_GPU_OPP_BEGIN, 1UL, 0UL));
	assert(!control(OPENCCA_GPU_POWER_OFF, 0UL, 0UL));
	assert(!control(OPENCCA_GPU_RESET, 0UL, 1UL));
	reset_ok = false;
	assert(!control(OPENCCA_GPU_RESET, 0UL, 0UL));
	assert(opencca_gpu_state() == OPENCCA_GPU_QUARANTINED);
	assert(opencca_gpu_pm_destroy_blocked(&owner_b));
	assert(opencca_gpu_lease_active() == 1U);
	assert(!opencca_gpu_lease_acquire(&owner_b, &page, 1U));
	reset_ok = true;
	assert(control(OPENCCA_GPU_RESET, 0UL, 0UL));
	assert(opencca_gpu_claim(&owner_b));
	assert(control(OPENCCA_GPU_OPP_BEGIN, 600000000UL, 0UL));
	assert(!control(OPENCCA_GPU_RELEASE, 0UL, 0UL));
	assert(!opencca_gpu_lease_acquire(&owner_b, &page, 1U));
	assert(control(OPENCCA_GPU_OPP_END, 600000000UL, 0UL));
	expect_revoke = true;
	revoke_ok = false;
	assert(!control(OPENCCA_GPU_RELEASE, 0UL, 0UL));
	assert(opencca_gpu_lease_active() == 1U);
	revoke_ok = true;
	reset_ok = false;
	assert(!control(OPENCCA_GPU_RELEASE, 0UL, 0UL));
	assert(opencca_gpu_lease_active() == 1U);
	assert(opencca_gpu_pm_destroy_blocked(&owner_b));
	assert(opencca_gpu_lease_page_busy(page));
	reset_ok = true;
	assert(control(OPENCCA_GPU_RELEASE, 0UL, 0UL));
	expect_revoke = false;
	assert(!opencca_gpu_mmio_allowed(&owner_b));
	assert(!opencca_gpu_mapping_allowed(&owner_b, 0x80fb000000UL,
					  0xfb000000UL, 0x200000UL, 0x8000000000UL));
	assert(!opencca_gpu_lease_acquire(&owner_b, &page, 1U));
	assert(opencca_gpu_lease_active() == 0U);
	assert(!opencca_gpu_lease_page_busy(page));
	assert(!opencca_gpu_pm_destroy_blocked(&owner_b));
	/* A Host-issued reset cannot re-enable an already revoked owner. */
	assert(control(OPENCCA_GPU_RESET, 0UL, 0UL));
	assert(!opencca_gpu_claim(&owner_b));
	assert(opencca_gpu_pm_destroy_begin(&owner_b));
	assert(!control(OPENCCA_GPU_RELEASE, 0UL, 0UL));
	opencca_gpu_mmio_release(&owner_b);
	assert(control(OPENCCA_GPU_POWER_OFF, 0UL, 0UL));
	assert(opencca_gpu_state() == OPENCCA_GPU_OFF);
	assert(!opencca_gpu_mmio_grant(&owner_a));
	assert(!control(OPENCCA_GPU_RESET, 0UL, 0UL));
	assert(control(OPENCCA_GPU_POWER_ON, 0UL, 0UL));
	assert(resets >= 8U && revokes >= 3U);
	puts("GPU lease and trusted control: claim, backend reset, OPP, quarantine, revoke, reclaim PASS");
	return 0;
}
