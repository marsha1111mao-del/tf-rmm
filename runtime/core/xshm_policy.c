/* SPDX-License-Identifier: BSD-3-Clause */
#include <granule.h>
#include <opencca_iommu.h>
#include <s2tt.h>
#include <smc-rmi.h>
#include <spinlock.h>
#include <xshm_runtime.h>

static spinlock_t policy_lock;

void xshm_policy_lock(void)
{
	spinlock_acquire(&policy_lock);
}

void xshm_policy_unlock(void)
{
	spinlock_release(&policy_lock);
}

bool xshm_rmi_allowed(unsigned int fid, unsigned long arg0,
		     unsigned long arg1, unsigned long arg2, unsigned long arg3)
{
	struct granule *owner;
	unsigned long base, size;

	/* Unknown/misaligned RD addresses are rejected by the original handler. */
	owner = find_granule(arg0);
	if (owner == NULL)
		return true;
	switch (fid) {
	case SMC_RMI_REALM_DESTROY:
		return !xshm_memory_owner_busy(owner) &&
		       !opencca_iommu_owner_busy(owner);
	case SMC_RMI_DATA_CREATE:
	case SMC_RMI_DATA_CREATE_UNKNOWN:
		base = arg2;
		size = GRANULE_SIZE;
		break;
	case SMC_RMI_DATA_DESTROY:
		base = arg1;
		size = GRANULE_SIZE;
		break;
	case SMC_RMI_RTT_FOLD:
	case SMC_RMI_RTT_DESTROY:
		/* The operation replaces a parent entry, covering level-1. */
		if (arg2 > (unsigned long)S2TT_PAGE_LEVEL)
			return true;
		size = s2tte_map_size((long)arg2 - 1L);
		base = arg1 & ~(size - 1UL);
		break;
	case SMC_RMI_RTT_INIT_RIPAS:
		base = arg1;
		size = arg2 > arg1 ? arg2 - arg1 : 0UL;
		break;
	case SMC_RMI_RTT_SET_RIPAS:
		base = arg2;
		size = arg3 > arg2 ? arg3 - arg2 : 0UL;
		break;
	default:
		/* RTT_CREATE splits without changing the existing PA/permissions.
		 * UNPROTECTED operations cannot touch protected IPA entries. */
		return true;
	}
	return !xshm_memory_range_busy(owner, base, size) &&
	       !opencca_iommu_range_busy(owner, base, size);
}
