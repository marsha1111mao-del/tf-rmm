/* SPDX-License-Identifier: BSD-3-Clause */
#include <arch_helpers.h>
#include <mmio.h>
#include <opencca_iommu.h>
#include <stdint.h>

#define DTE_ADDR 0x00UL
#define STATUS 0x04UL
#define COMMAND 0x08UL
#define FAULT_ADDR 0x0cUL
#define INT_CLEAR 0x18UL
#define INT_MASK 0x1cUL
#define INT_STATUS 0x20UL
#define IRQ_MASK 3U
#define PAGING 1U
#define STALLED (1U << 2U)
#define IDLE (1U << 3U)
#define ENABLE_PAGING 0U
#define ENABLE_STALL 2U
#define DISABLE_STALL 3U
#define ZAP_CACHE 4U
#define PAGE_FAULT_DONE 5U
#define PAGE_FAULT_WRITE (1U << 5U)
#define TIMEOUT_US 10000UL

struct rk_device {
	unsigned long base[2];
	unsigned int count;
};

/* Matches rk3588-base.dtsi. The first register bank is the ABI device ID.
 * The VOP has two MMUs; both must be configured and invalidated together.
 * SMMUv3 and devices absent from this list are not this backend's devices.
 */
static const struct rk_device devices[] = {
	{{0xfdb50800UL, 0UL}, 1U},
	{{0xfdba0800UL, 0UL}, 1U},
	{{0xfdba4800UL, 0UL}, 1U},
	{{0xfdba8800UL, 0UL}, 1U},
	{{0xfdbac800UL, 0UL}, 1U},
	{{0xfdd97e00UL, 0xfdd97f00UL}, 2U}
};

static const struct rk_device *find_device(unsigned long device)
{
	for (unsigned int i = 0U; i < sizeof(devices) / sizeof(devices[0]); i++) {
		if (devices[i].base[0] == device)
			return &devices[i];
	}
	return NULL;
}

bool plat_opencca_iommu_device_valid(unsigned long device)
{
	return find_device(device) != NULL;
}

bool plat_opencca_iommu_mmio_overlaps(unsigned long pa, unsigned long size)
{
	for (unsigned int i = 0U; i < sizeof(devices) / sizeof(devices[0]); i++) {
		for (unsigned int bank = 0U; bank < devices[i].count; bank++) {
			unsigned long base = devices[i].base[bank] & ~4095UL;

			if (pa < base + 4096UL && base < pa + size)
				return true;
		}
	}
	return false;
}

static uint32_t reg_read(unsigned long base, unsigned long offset)
{
	return read32((volatile void *)(uintptr_t)(base + offset));
}

static void reg_write(unsigned long base, unsigned long offset, uint32_t value)
{
	write32(value, (volatile void *)(uintptr_t)(base + offset));
}

static bool poll_status(unsigned long base, uint32_t mask, uint32_t value)
{
	unsigned long start = read_cntpct_el0();
	unsigned long ticks = read_cntfrq_el0() / 1000000UL * TIMEOUT_US;

	if (ticks == 0UL)
		return false;
	do {
		if ((reg_read(base, STATUS) & mask) == value)
			return true;
	} while (read_cntpct_el0() - start < ticks);
	return false;
}

static uint32_t encode_root(unsigned long root)
{
	return (uint32_t)((root & 0xfffff000UL) | ((root >> 24U) & 0xf00UL) |
			 ((root >> 32U) & 0xf0UL)) | 1U;
}

static bool root_matches(unsigned long base, unsigned long root)
{
	/* The root register need not retain the descriptor's validity bit. */
	return (reg_read(base, DTE_ADDR) & 0xfffffff0U) ==
	       (encode_root(root) & 0xfffffff0U);
}

static bool stall(unsigned long base)
{
	if ((reg_read(base, STATUS) & PAGING) == 0U)
		return true;
	reg_write(base, COMMAND, ENABLE_STALL);
	/* RMM observes hardware status, not a Host completion assertion. The
	 * device driver must still finish its DMA before normal DMA unmapping.
	 * On failure the core keeps reservations and quarantines the domain.
	 */
	return poll_status(base, STALLED | IDLE, STALLED | IDLE);
}

bool plat_opencca_iommu_fault(unsigned long device, unsigned long root,
			     struct opencca_iommu_result *result)
{
	const struct rk_device *entry = find_device(device);
	uint32_t pending[2] = {0U, 0U};

	if (entry == NULL || root == 0UL || (root & 4095UL) != 0UL || root >= (1UL << 40U))
		return false;
	for (unsigned int bank = 0U; bank < entry->count; bank++) {
		unsigned long base = entry->base[bank];
		uint32_t status;
		unsigned long flags;

		if (!root_matches(base, root) || (reg_read(base, STATUS) & PAGING) == 0U)
			return false;
		pending[bank] = reg_read(base, INT_STATUS);
		if ((pending[bank] & ~IRQ_MASK) != 0U)
			return false;
		if (pending[bank] == 0U)
			continue;
		status = reg_read(base, STATUS);
		flags = pending[bank];
		if ((pending[bank] & 1U) != 0U && (status & PAGE_FAULT_WRITE) != 0U)
			flags |= OPENCCA_IOMMU_FAULT_WRITE;
		result->value[0] |= flags << (bank * OPENCCA_IOMMU_FAULT_BANK_BITS);
		result->value[bank + 1U] = reg_read(base, FAULT_ADDR);
	}
	for (unsigned int bank = 0U; bank < entry->count; bank++) {
		unsigned long base = entry->base[bank];

		if (pending[bank] == 0U)
			continue;
		if ((pending[bank] & 1U) != 0U) {
			reg_write(base, COMMAND, ZAP_CACHE);
			reg_write(base, COMMAND, PAGE_FAULT_DONE);
		}
		reg_write(base, INT_CLEAR, pending[bank]);
		(void)reg_read(base, STATUS);
		dsb(sy);
		if (!root_matches(base, root) || (reg_read(base, STATUS) & PAGING) == 0U)
			return false;
	}
	return true;
}

bool plat_opencca_iommu_device(unsigned long device, unsigned long root,
			      enum opencca_iommu_device_command command)
{
	const struct rk_device *entry = find_device(device);

	if (entry == NULL || root == 0UL || (root & 4095UL) != 0UL || root >= (1UL << 40U))
		return false;
	for (unsigned int i = 0U; i < entry->count; i++) {
		unsigned long base = entry->base[i];
		bool replace = command == OPENCCA_IOMMU_DEVICE_BIND ||
			       command == OPENCCA_IOMMU_DEVICE_PARK;

		if (!replace && (!root_matches(base, root) ||
				 (reg_read(base, STATUS) & PAGING) == 0U))
			return false;
		switch (command) {
		case OPENCCA_IOMMU_DEVICE_BIND:
		case OPENCCA_IOMMU_DEVICE_PARK:
			if (!stall(base))
				return false;
			reg_write(base, DTE_ADDR, encode_root(root));
			reg_write(base, COMMAND, ZAP_CACHE);
			reg_write(base, COMMAND, ENABLE_PAGING);
			if (!root_matches(base, root) || !poll_status(base, PAGING, PAGING))
				return false;
			/* Keep parked MMUs translating through the deny-all root. */
			reg_write(base, INT_MASK,
				  command == OPENCCA_IOMMU_DEVICE_PARK ? 0U : IRQ_MASK);
			reg_write(base, COMMAND, DISABLE_STALL);
			if (!poll_status(base, STALLED, 0U))
				return false;
			break;
		case OPENCCA_IOMMU_DEVICE_STALL:
			if (!stall(base))
				return false;
			break;
		case OPENCCA_IOMMU_DEVICE_INVALIDATE:
			if ((reg_read(base, STATUS) & STALLED) == 0U)
				return false;
			reg_write(base, COMMAND, ZAP_CACHE);
			/* Same ordered cache-zap interface as the native driver; a
			 * readback and barriers finish RMM's register transaction.
			 */
			(void)reg_read(base, STATUS);
			dsb(sy);
			if (!root_matches(base, root) ||
			    !poll_status(base, STALLED | IDLE, STALLED | IDLE))
				return false;
			break;
		case OPENCCA_IOMMU_DEVICE_RESUME:
			reg_write(base, COMMAND, DISABLE_STALL);
			if (!poll_status(base, STALLED, 0U))
				return false;
			break;
		default:
			return false;
		}
	}
	return true;
}
