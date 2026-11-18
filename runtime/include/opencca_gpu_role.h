/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef OPENCCA_GPU_ROLE_H
#define OPENCCA_GPU_ROLE_H

#include <measurement.h>

#define OPENCCA_GPU_ROLE_MEASUREMENT_SLOT (MEASUREMENT_SLOT_NR - 1U)

void opencca_gpu_role_measure(enum hash_algo algorithm,
			      unsigned long endpoint_id,
			      unsigned char measurement[MAX_MEASUREMENT_SIZE]);
void opencca_gpu_role_clear(unsigned char measurement[MAX_MEASUREMENT_SIZE]);

#endif
