/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef OPENCCA_GPU_LEASE_H
#define OPENCCA_GPU_LEASE_H

#include <stdbool.h>
#include <opencca_gpu.h>
#include <stddef.h>

/* Global bound: 2 GiB of distinct 4 KiB pages, including firmware/tables.
 * Software ownership metadata only; this does not configure device or GPT
 * permissions. Callers serialize every operation with the same lock.
 */
#define OPENCCA_GPU_LEASE_CAPACITY 524288U
#define OPENCCA_GPU_LEASE_BATCH 512U

bool opencca_gpu_lease_acquire(const void *owner, const unsigned long *hpas,
			       size_t count);
void opencca_gpu_lease_release(const void *owner, const unsigned long *hpas,
			      size_t count);
unsigned int opencca_gpu_lease_release_owner(const void *owner);
unsigned int opencca_gpu_lease_active(void);
bool opencca_gpu_lease_page_busy(unsigned long hpa);
bool opencca_gpu_page_busy(unsigned long hpa);
/* DMA reservations precede device PTE publication and survive until completed
 * IOTLB invalidation. These operations share the GPU lease caller's lock.
 * They mediate mapping requests; a platform must also protect device tables
 * and registers against direct writes/bypass by untrusted software.
 */
#define OPENCCA_DMA_MAP_CAPACITY 1024U
#define OPENCCA_DMA_MAP_MAX_SIZE (2UL * 1024UL * 1024UL)
bool opencca_dma_map_acquire(unsigned long domain, unsigned long iova,
			    unsigned long pa, unsigned long size);
bool opencca_dma_map_release(unsigned long domain, unsigned long iova,
			    unsigned long size);
unsigned int opencca_dma_map_active(void);
unsigned long opencca_gpu_lease_first(void);
bool opencca_dma_map_overlaps(unsigned long pa, unsigned long size);
bool opencca_gpu_dma_busy(unsigned long pa, unsigned long size);
bool opencca_gpu_dma_reserve(unsigned long domain, unsigned long iova,
			    unsigned long pa, unsigned long size);
bool opencca_gpu_dma_retire(unsigned long domain, unsigned long iova,
			   unsigned long size);

#endif
