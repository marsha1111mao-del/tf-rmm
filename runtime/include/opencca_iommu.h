/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef OPENCCA_IOMMU_H
#define OPENCCA_IOMMU_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* This extension owns the real RK v2 device tables. Register/table access
 * protection is modelled by OpenCCA; this is not a hardware GPC claim.
 */
#define OPENCCA_IOMMU_ABI 1UL
#define OPENCCA_IOMMU_SIMULATED_PROTECTION 1UL
#define OPENCCA_IOMMU_DOMAINS 32U
#define OPENCCA_IOMMU_TABLE_PAGES 1024U
#define OPENCCA_IOMMU_BATCH_PAGES 512U
#define OPENCCA_IOMMU_PAGE_SIZE 4096UL
#define OPENCCA_IOMMU_READ 1UL
#define OPENCCA_IOMMU_WRITE 2UL
#define OPENCCA_IOMMU_FAULT_BANK_BITS 16U
#define OPENCCA_IOMMU_FAULT_WRITE (1UL << 8U)
#define OPENCCA_IOMMU_FAULT_GUEST (1UL << 32U)

enum opencca_iommu_operation {
	OPENCCA_IOMMU_VERSION = 0,
	OPENCCA_IOMMU_CREATE = 1,
	OPENCCA_IOMMU_MAP = 2,
	OPENCCA_IOMMU_UNMAP = 3,
	OPENCCA_IOMMU_QUERY = 4,
	OPENCCA_IOMMU_BIND = 5,
	OPENCCA_IOMMU_UNBIND = 6,
	OPENCCA_IOMMU_QUIESCE = 7,
	OPENCCA_IOMMU_DESTROY = 8,
	OPENCCA_IOMMU_GRANT = 9,
	OPENCCA_IOMMU_REVOKE = 10,
	OPENCCA_IOMMU_FAULT = 11
};

/* Shared RMI/RSI inputs are (operation, handle, arg1, arg2, arg3).
 * MAP:    (IOVA, Host HPA or Guest IPA, byte count | READ | WRITE).
 * UNMAP:  (IOVA, 0, byte count), returning actual bytes before first hole.
 * QUERY:  (IOVA, 0, 0), returning PA, RW, root PA and mapped page count.
 * BIND/UNBIND: (fixed platform device ID, 0, 0). Other inputs are zero.
 */

enum opencca_iommu_status {
	OPENCCA_IOMMU_SUCCESS = 0,
	OPENCCA_IOMMU_INPUT = 1,
	OPENCCA_IOMMU_STATE = 2,
	OPENCCA_IOMMU_FULL = 3
};

enum opencca_iommu_device_command {
	OPENCCA_IOMMU_DEVICE_BIND,
	OPENCCA_IOMMU_DEVICE_STALL,
	OPENCCA_IOMMU_DEVICE_INVALIDATE,
	OPENCCA_IOMMU_DEVICE_RESUME,
	/* Remain in paging mode using an empty deny-all table. Never bypass. */
	OPENCCA_IOMMU_DEVICE_PARK
};

struct opencca_iommu_result {
	unsigned long status;
	unsigned long value[4];
};

/* All core calls require the outer ownership/policy lock. GPU/DMA index
 * callbacks additionally take the existing GPU mapping lock. A device
 * callback returns success only after RMM itself completed the operation.
 */
struct opencca_iommu_ops {
	unsigned long (*table_pa)(const void *table);
	void (*clean)(const void *table, size_t bytes);
	bool (*reserve)(unsigned long handle, unsigned long iova,
			unsigned long pa, unsigned long size);
	bool (*retire)(unsigned long handle, unsigned long iova,
		       unsigned long size);
	bool (*device_valid)(unsigned long device);
	bool (*device)(unsigned long device, unsigned long root,
		       enum opencca_iommu_device_command command);
	bool (*fault)(unsigned long device, unsigned long root,
		      struct opencca_iommu_result *result);
};

void opencca_iommu_call(const struct opencca_iommu_ops *ops, const void *owner,
		unsigned long operation, unsigned long handle,
		unsigned long arg1, unsigned long arg2, unsigned long arg3,
		struct opencca_iommu_result *result);
void opencca_iommu_map(const struct opencca_iommu_ops *ops, const void *owner,
		unsigned long handle, unsigned long iova,
		const unsigned long *pages, size_t count, unsigned long prot,
		unsigned long source_ipa, struct opencca_iommu_result *result);

/* Protect guest backing against Host RTT/data teardown while DMA can use it.
 * Also returns busy for quarantined mappings whose invalidation failed.
 */
bool opencca_iommu_owner_busy(const void *owner);
bool opencca_iommu_range_busy(const void *owner, unsigned long ipa,
			      unsigned long size);
bool opencca_iommu_secure_handle(unsigned long handle);

/* Fixed RK3588 platform backend; no caller-supplied register addresses. */
bool plat_opencca_iommu_device_valid(unsigned long device);
bool plat_opencca_iommu_mmio_overlaps(unsigned long pa, unsigned long size);
bool plat_opencca_iommu_device(unsigned long device, unsigned long root,
			      enum opencca_iommu_device_command command);
bool plat_opencca_iommu_fault(unsigned long device, unsigned long root,
			     struct opencca_iommu_result *result);

#endif
