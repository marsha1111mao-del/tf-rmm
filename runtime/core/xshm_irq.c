/* SPDX-License-Identifier: BSD-3-Clause */
#include <xshm_irq.h>

#define LR_STATE (3UL << 62U)
#define LR_PENDING (1UL << 62U)
#define LR_GROUP1 (1UL << 60U)
#define LR_PRIORITY (0xa0UL << 48U)
#define LR_INTID 0xffffffffUL

bool xshm_irq_host_valid(const unsigned long *lrs, size_t count)
{
	if (lrs == NULL || count < 2U || lrs[count - 1U] != 0UL)
		return false;
	for (size_t i = 0U; i < count - 1U; i++) {
		if ((lrs[i] & LR_STATE) != 0UL &&
		    (lrs[i] & LR_INTID) == XSHM_IRQ_INTID)
			return false;
	}
	return true;
}

void xshm_irq_inject(unsigned long *lrs, size_t count)
{
	unsigned long *lr = &lrs[count - 1U];

	/* Preserve Active on an interrupt still in its trusted handler. */
	*lr = (*lr & LR_STATE) | LR_PENDING | LR_GROUP1 |
	      LR_PRIORITY | XSHM_IRQ_INTID;
}
