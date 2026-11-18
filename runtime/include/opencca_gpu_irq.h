/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef OPENCCA_GPU_IRQ_H
#define OPENCCA_GPU_IRQ_H
#include <stdbool.h>
#include <stdint.h>

/* Fixed trusted read: no pending RAW and actual masks match Root-approved values. */
bool plat_opencca_gpu_irq_idle(uint32_t gpu_mask, uint32_t job_mask,
			       uint32_t mmu_mask);

bool opencca_gpu_irq_start(void);
void opencca_gpu_irq_revoke(void);
bool opencca_gpu_irq_bind(const void *owner, unsigned long context,
			  unsigned long group, unsigned int csg,
			  unsigned int as, uint64_t *epoch);
bool opencca_gpu_irq_sync(unsigned int csg, uint64_t epoch, uint64_t *sequence);
bool opencca_gpu_irq_begin(unsigned int csg, uint64_t epoch,
			   uint64_t *sequence);
bool opencca_gpu_irq_close(unsigned int csg, uint64_t epoch);
unsigned int opencca_gpu_irq_next(unsigned int csg, uint64_t epoch,
				  uint64_t after, unsigned long values[4]);
unsigned int opencca_gpu_irq_claim(unsigned int csg, uint64_t epoch,
				   uint64_t after, uint64_t sequence,
				   uint64_t binding_epoch,
				   uint64_t device_epoch, unsigned int kind,
				   bool completed);
bool opencca_gpu_irq_status(unsigned int selector, unsigned long values[4]);
bool opencca_gpu_irq_selftest(const void *owner, unsigned long context,
			      unsigned long group, unsigned long values[4]);

#endif
