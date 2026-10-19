/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef OPENCCA_GPU_H
#define OPENCCA_GPU_H

#include <stdbool.h>

#define OPENCCA_GPU_MMIO_BASE 0xfb000000UL
#define OPENCCA_GPU_MMIO_SIZE 0x200000UL

/* RMI GPU_PM: x1=operation, x2=argument, x3=completion error. RESET and
 * RELEASE execute the reset in RMM; Host cannot assert reset completion.
 */
enum opencca_gpu_operation {
	OPENCCA_GPU_RESET = 0U,
	OPENCCA_GPU_RELEASE = 1U,
	OPENCCA_GPU_OPP_BEGIN = 2U,
	OPENCCA_GPU_OPP_END = 3U,
	OPENCCA_GPU_STATUS = 4U,
	OPENCCA_GPU_POWER_OFF = 5U,
	OPENCCA_GPU_POWER_ON = 6U
};

enum opencca_gpu_state {
	OPENCCA_GPU_UNOWNED,
	OPENCCA_GPU_DESIGNATED,
	OPENCCA_GPU_RUNNING,
	OPENCCA_GPU_RESETTING,
	OPENCCA_GPU_POWERING,
	OPENCCA_GPU_QUARANTINED,
	OPENCCA_GPU_REVOKED,
	OPENCCA_GPU_DESTROYING,
	OPENCCA_GPU_OFF
};

struct opencca_gpu_ops {
	bool (*reset)(bool preserve_irqs);
	bool (*revoke_mmio)(const void *owner);
	bool (*opp_valid)(unsigned long frequency);
};

/* All state/lease operations are serialized by the adapter's mapping lock. */
bool opencca_gpu_mmio_grant(const void *owner);
bool opencca_gpu_mmio_allowed(const void *owner);
bool opencca_gpu_mmio_running(const void *owner);
bool opencca_gpu_mapping_allowed(const void *owner, unsigned long ipa,
		unsigned long pa, unsigned long size, unsigned long shared_base);
bool opencca_gpu_authorize_mapping(const void *owner, unsigned long ipa,
		unsigned long pa, unsigned long size, unsigned long shared_base);
bool opencca_gpu_claim(const void *owner);
bool opencca_gpu_control(const struct opencca_gpu_ops *ops, const void *caller,
			 unsigned long operation, unsigned long argument,
			 unsigned long error);
enum opencca_gpu_state opencca_gpu_state(void);
void opencca_gpu_mmio_release(const void *owner);
bool opencca_gpu_pm_destroy_blocked(const void *owner);
bool opencca_gpu_pm_destroy_begin(const void *owner);

bool plat_opencca_gpu_reset(bool preserve_irqs);
bool plat_opencca_gpu_opp_valid(unsigned long frequency);
unsigned long plat_opencca_gpu_pa_bits(void);

#endif
