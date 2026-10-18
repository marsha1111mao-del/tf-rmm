/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef OPENCCA_GPU_LEASE_H
#define OPENCCA_GPU_LEASE_H

#include <stdbool.h>
#include <stddef.h>

/* Global bound: 512 MiB of distinct 4 KiB pages, including firmware/tables.
 * Software ownership metadata only; this does not configure device or GPT
 * permissions. Callers serialize every operation with the same lock.
 */
#define OPENCCA_GPU_LEASE_CAPACITY 131072U
#define OPENCCA_GPU_LEASE_BATCH 512U

bool opencca_gpu_lease_acquire(const void *owner, const unsigned long *hpas,
			       size_t count);
void opencca_gpu_lease_release(const void *owner, const unsigned long *hpas,
			      size_t count);
unsigned int opencca_gpu_lease_release_owner(const void *owner);
unsigned int opencca_gpu_lease_active(void);

#endif
