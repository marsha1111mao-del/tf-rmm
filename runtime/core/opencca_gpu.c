/* SPDX-License-Identifier: BSD-3-Clause */
#include <stddef.h>
#include <limits.h>
#include <opencca_gpu.h>
#include <opencca_gpu_lease.h>

static const void *owner;
static enum opencca_gpu_state state = OPENCCA_GPU_OFF;
static enum opencca_gpu_state resume_state;
static unsigned long pending_frequency;

bool opencca_gpu_mmio_grant(const void *candidate)
{
	if (candidate == NULL)
		return false;
	if (state == OPENCCA_GPU_UNOWNED) {
		owner = candidate;
		state = OPENCCA_GPU_DESIGNATED;
		return true;
	}
	return opencca_gpu_mmio_allowed(candidate);
}

bool opencca_gpu_mmio_allowed(const void *candidate)
{
	return candidate != NULL && candidate == owner &&
	       (state == OPENCCA_GPU_DESIGNATED || state == OPENCCA_GPU_RUNNING);
}

bool opencca_gpu_mmio_running(const void *candidate)
{
	return candidate != NULL && candidate == owner && state == OPENCCA_GPU_RUNNING;
}

bool opencca_gpu_mapping_allowed(const void *candidate, unsigned long ipa,
		unsigned long pa, unsigned long size, unsigned long shared_base)
{
	unsigned long gpu_ipa = shared_base | OPENCCA_GPU_MMIO_BASE;
	bool physical_overlap, alias_overlap;

	if (size == 0UL || size > ULONG_MAX - pa || size > ULONG_MAX - ipa)
		return false;
	physical_overlap = pa < OPENCCA_GPU_MMIO_BASE + OPENCCA_GPU_MMIO_SIZE &&
			   OPENCCA_GPU_MMIO_BASE < pa + size;
	alias_overlap = ipa < gpu_ipa + OPENCCA_GPU_MMIO_SIZE && gpu_ipa < ipa + size;
	if (!physical_overlap && !alias_overlap)
		return true;
	return pa == OPENCCA_GPU_MMIO_BASE && size == OPENCCA_GPU_MMIO_SIZE &&
	       ipa == gpu_ipa &&
	       opencca_gpu_mmio_allowed(candidate);
}

bool opencca_gpu_claim(const void *caller)
{
	if (!opencca_gpu_mmio_allowed(caller))
		return false;
	state = OPENCCA_GPU_RUNNING;
	return true;
}

static bool reset(const struct opencca_gpu_ops *ops, bool preserve_irqs)
{
	enum opencca_gpu_state previous = state;

	if (state == OPENCCA_GPU_POWERING || state == OPENCCA_GPU_DESTROYING ||
	    state == OPENCCA_GPU_OFF)
		return false;
	state = OPENCCA_GPU_RESETTING;
	if (!ops->reset(preserve_irqs)) {
		state = OPENCCA_GPU_QUARANTINED;
		return false;
	}
	/* A quarantined owner must claim again after successful recovery. */
	state = previous == OPENCCA_GPU_QUARANTINED ?
		(owner == NULL ? OPENCCA_GPU_UNOWNED : OPENCCA_GPU_DESIGNATED) : previous;
	return true;
}

bool opencca_gpu_control(const struct opencca_gpu_ops *ops, const void *caller,
			 unsigned long operation, unsigned long argument,
			 unsigned long error)
{
	if (operation != OPENCCA_GPU_POWER_ON && operation != OPENCCA_GPU_STATUS &&
	    (ops == NULL || ops->reset == NULL || ops->revoke_mmio == NULL ||
	     ops->opp_valid == NULL))
		return false;
	/* A Realm can only reset its own claimed device. It cannot use board
	 * PM, designate a different owner, or reclaim any physical pages.
	 */
	if (caller != NULL &&
	    (operation != OPENCCA_GPU_RESET || !opencca_gpu_mmio_running(caller)))
		return false;
	switch (operation) {
	case OPENCCA_GPU_RESET:
		return argument == 0UL && error == 0UL && reset(ops, caller != NULL);
	case OPENCCA_GPU_RELEASE:
		if (argument != 0UL || error != 0UL)
			return false;
		if (state == OPENCCA_GPU_REVOKED)
			return true;
		if (state == OPENCCA_GPU_POWERING || state == OPENCCA_GPU_DESTROYING ||
		    state == OPENCCA_GPU_OFF)
			return false;
		/* Remove the CPU's MMIO access before stopping DMA; only a verified
		 * reset makes the old backing pages eligible for reclamation.
		 */
		if (owner != NULL && !ops->revoke_mmio(owner))
			return false;
		if (!reset(ops, false))
			return false;
		if (owner != NULL) {
			(void)opencca_gpu_lease_release_owner(owner);
			state = OPENCCA_GPU_REVOKED;
		}
		return true;
	case OPENCCA_GPU_OPP_BEGIN:
		if (error != 0UL || !ops->opp_valid(argument) ||
		    (state != OPENCCA_GPU_UNOWNED && state != OPENCCA_GPU_DESIGNATED &&
		     state != OPENCCA_GPU_RUNNING && state != OPENCCA_GPU_REVOKED &&
		     state != OPENCCA_GPU_OFF))
			return false;
		resume_state = state;
		pending_frequency = argument;
		state = OPENCCA_GPU_POWERING;
		return true;
	case OPENCCA_GPU_OPP_END:
		if (state != OPENCCA_GPU_POWERING || argument != pending_frequency)
			return false;
		state = error == 0UL ? resume_state : OPENCCA_GPU_QUARANTINED;
		pending_frequency = 0UL;
		return true;
	case OPENCCA_GPU_STATUS:
		return argument == 0UL && error == 0UL;
	case OPENCCA_GPU_POWER_OFF:
		if (argument != 0UL || error != 0UL || owner != NULL ||
		    state != OPENCCA_GPU_UNOWNED || !reset(ops, false))
			return false;
		state = OPENCCA_GPU_OFF;
		return true;
	case OPENCCA_GPU_POWER_ON:
		if (argument != 0UL || error != 0UL || owner != NULL ||
		    (state != OPENCCA_GPU_OFF && state != OPENCCA_GPU_UNOWNED))
			return false;
		state = OPENCCA_GPU_UNOWNED;
		return true;
	default:
		return false;
	}
}

enum opencca_gpu_state opencca_gpu_state(void)
{
	return state;
}

void opencca_gpu_mmio_release(const void *candidate)
{
	if (candidate != owner || state != OPENCCA_GPU_DESTROYING)
		return;
	owner = NULL;
	state = OPENCCA_GPU_UNOWNED;
}

bool opencca_gpu_pm_destroy_blocked(const void *candidate)
{
	return candidate == owner && state != OPENCCA_GPU_REVOKED;
}

bool opencca_gpu_pm_destroy_begin(const void *candidate)
{
	if (candidate != owner)
		return true;
	if (state != OPENCCA_GPU_REVOKED)
		return false;
	state = OPENCCA_GPU_DESTROYING;
	return true;
}
