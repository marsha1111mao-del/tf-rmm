/* SPDX-License-Identifier: BSD-3-Clause */
#include <arch_helpers.h>
#include <mmio.h>
#include <opencca_gpu.h>
#include <stdint.h>

#define GPU_INT_RAWSTAT 0x20UL
#define GPU_INT_CLEAR 0x24UL
#define GPU_INT_MASK 0x28UL
#define GPU_CMD 0x30UL
#define GPU_RESET_COMPLETED (1U << 8U)
#define GPU_SOFT_RESET 0x101U
#define GPU_HARD_RESET 0x201U
#define MCU_CONTROL 0x700UL
#define MCU_STATUS 0x704UL
#define JOB_INT_RAWSTAT 0x1000UL
#define JOB_INT_CLEAR 0x1004UL
#define JOB_INT_MASK 0x1008UL
#define MMU_INT_RAWSTAT 0x2000UL
#define MMU_INT_CLEAR 0x2004UL
#define MMU_INT_MASK 0x2008UL
#define TIMEOUT_US 100000UL

static uint32_t reg_read(unsigned long offset)
{
	return read32((volatile void *)(uintptr_t)(OPENCCA_GPU_MMIO_BASE + offset));
}

static void reg_write(unsigned long offset, uint32_t value)
{
	write32(value, (volatile void *)(uintptr_t)(OPENCCA_GPU_MMIO_BASE + offset));
}

static bool poll(unsigned long offset, uint32_t mask, uint32_t expected)
{
	unsigned long start = read_cntpct_el0();
	unsigned long ticks = read_cntfrq_el0() / 1000000UL * TIMEOUT_US;

	if (ticks == 0UL)
		return false;
	do {
		if ((reg_read(offset) & mask) == expected)
			return true;
	} while (read_cntpct_el0() - start < ticks);
	return false;
}

static void clear_irqs(void)
{
	reg_write(GPU_INT_CLEAR, reg_read(GPU_INT_RAWSTAT));
	reg_write(JOB_INT_CLEAR, reg_read(JOB_INT_RAWSTAT));
	reg_write(MMU_INT_CLEAR, reg_read(MMU_INT_RAWSTAT));
}

bool plat_opencca_gpu_reset(bool preserve_irqs)
{
	uint32_t gpu_mask = reg_read(GPU_INT_MASK);
	uint32_t job_mask = reg_read(JOB_INT_MASK);
	uint32_t mmu_mask = reg_read(MMU_INT_MASK);
	bool completed;

	reg_write(GPU_INT_MASK, 0U);
	reg_write(JOB_INT_MASK, 0U);
	reg_write(MMU_INT_MASK, 0U);
	clear_irqs();
	reg_write(MCU_CONTROL, 0U);
	/* A hung MCU must not prevent the hard-reset recovery attempt. */
	(void)poll(MCU_STATUS, UINT32_MAX, 0U);
	reg_write(GPU_INT_CLEAR, GPU_RESET_COMPLETED);
	reg_write(GPU_CMD, GPU_SOFT_RESET);
	completed = poll(GPU_INT_RAWSTAT, GPU_RESET_COMPLETED, GPU_RESET_COMPLETED);
	if (!completed) {
		reg_write(GPU_CMD, GPU_HARD_RESET);
		completed = poll(GPU_INT_RAWSTAT, GPU_RESET_COMPLETED, GPU_RESET_COMPLETED);
	}
	clear_irqs();
	if (completed && preserve_irqs) {
		reg_write(JOB_INT_MASK, job_mask);
		reg_write(MMU_INT_MASK, mmu_mask);
		reg_write(GPU_INT_MASK, gpu_mask);
	}
	dsb(sy);
	return completed;
}

bool plat_opencca_gpu_opp_valid(unsigned long frequency)
{
	/* Fixed board policy, matching rk3588-opp.dtsi rather than a mutable
	 * Host-supplied list. Clock rounding (e.g. 600 -> 594 MHz) is allowed.
	 */
	return frequency >= 300000000UL && frequency <= 1000000000UL &&
	       frequency % 100000000UL == 0UL;
}

unsigned long plat_opencca_gpu_pa_bits(void)
{
	/* Board DMA policy is readable even with clocks off. Do not access GPU
	 * registers merely to answer an untrusted Host's capability query.
	 */
	return 40UL;
}
