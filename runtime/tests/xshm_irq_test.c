/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <stdio.h>
#include <xshm_irq.h>

int main(void)
{
	unsigned long lr[4] = {0};

	assert(!xshm_irq_host_valid(NULL, 4));
	assert(!xshm_irq_host_valid(lr, 1));
	assert(xshm_irq_host_valid(lr, 4));
	lr[0] = (1UL << 62U) | 32UL;
	assert(xshm_irq_host_valid(lr, 4));
	/* A forged pending/active trusted INTID is rejected in every Host LR. */
	for (unsigned int slot = 0; slot < 4; slot++) {
		for (unsigned long state = 1; state <= 3; state++) {
			unsigned long saved = lr[slot];

			lr[slot] = (state << 62U) | XSHM_IRQ_INTID;
			assert(!xshm_irq_host_valid(lr, 4));
			lr[slot] = saved;
		}
	}
	/* Host cannot smuggle even an invalid descriptor into the private LR. */
	lr[3] = 1;
	assert(!xshm_irq_host_valid(lr, 4));
	lr[3] = 0;
	xshm_irq_inject(lr, 4);
	assert((lr[3] & 0xffffffffUL) == XSHM_IRQ_INTID);
	assert((lr[3] >> 62U) == 1);
	assert(lr[0] == ((1UL << 62U) | 32UL));
	xshm_irq_inject(lr, 4);
	assert((lr[3] >> 62U) == 1); /* Coalesced while Pending. */
	lr[3] = (lr[3] & ~(3UL << 62U)) | (2UL << 62U);
	xshm_irq_inject(lr, 4);
	assert((lr[3] >> 62U) == 3); /* Active + Pending, not lost. */
	puts("XSHM_IRQ_POLICY=PASS host_forgery=rejected private_lr=preserved");
	return 0;
}
