/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <opencca_gpu.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint32_t registers[0x2010U / 4U];
static unsigned int soft_commands, hard_commands, barriers;
static bool soft_succeeds, hard_succeeds;
static unsigned long clock_ticks;

unsigned long read_cntpct_el0(void)
{
	clock_ticks += 1000UL;
	return clock_ticks;
}

unsigned long read_cntfrq_el0(void)
{
	return 1000000UL;
}

void test_dsb(void)
{
	barriers++;
}

static unsigned long reg_offset(const volatile void *address)
{
	uintptr_t offset = (uintptr_t)address - OPENCCA_GPU_MMIO_BASE;

	assert(offset < sizeof(registers) && offset % 4UL == 0UL);
	return offset;
}

uint32_t read32(const volatile void *address)
{
	return registers[reg_offset(address) / 4UL];
}

void write32(uint32_t value, volatile void *address)
{
	unsigned long offset = reg_offset(address);

	registers[offset / 4UL] = value;
	if (offset == 0x24UL || offset == 0x1004UL || offset == 0x2004UL)
		registers[(offset - 4UL) / 4UL] &= ~value;
	if (offset == 0x30UL) {
		assert(value == 0x101U || value == 0x201U);
		if (value == 0x101U)
			soft_commands++;
		else
			hard_commands++;
		if ((value == 0x101U && soft_succeeds) ||
		    (value == 0x201U && hard_succeeds))
			registers[0x20U / 4U] |= 1U << 8U;
	}
}

static void initialize(void)
{
	memset(registers, 0, sizeof(registers));
	registers[0x14U / 4U] = 40U << 8U;
	registers[0x28U / 4U] = 0x77U;
	registers[0x1008U / 4U] = 0x55U;
	registers[0x2008U / 4U] = 0x33U;
	soft_commands = 0U;
	hard_commands = 0U;
	soft_succeeds = true;
	hard_succeeds = true;
}

int main(void)
{
	initialize();
	assert(plat_opencca_gpu_pa_bits() == 40UL);
	assert(plat_opencca_gpu_reset(true));
	assert(soft_commands == 1U && hard_commands == 0U);
	assert(registers[0x28U / 4U] == 0x77U);
	assert(registers[0x1008U / 4U] == 0x55U);
	assert(registers[0x2008U / 4U] == 0x33U);
	assert(registers[0x20U / 4U] == 0U);
	initialize();
	soft_succeeds = false;
	assert(plat_opencca_gpu_reset(false));
	assert(soft_commands == 1U && hard_commands == 1U);
	assert(registers[0x28U / 4U] == 0U);
	initialize();
	soft_succeeds = false;
	hard_succeeds = false;
	assert(!plat_opencca_gpu_reset(true));
	assert(soft_commands == 1U && hard_commands == 1U);
	assert(registers[0x28U / 4U] == 0U);
	assert(registers[0x1008U / 4U] == 0U);
	assert(registers[0x2008U / 4U] == 0U);
	assert(barriers == 3U);
	assert(plat_opencca_gpu_opp_valid(300000000UL));
	assert(plat_opencca_gpu_opp_valid(600000000UL));
	assert(plat_opencca_gpu_opp_valid(1000000000UL));
	assert(!plat_opencca_gpu_opp_valid(0UL));
	assert(!plat_opencca_gpu_opp_valid(594000000UL));
	assert(!plat_opencca_gpu_opp_valid(1100000000UL));
	puts("RK GPU backend: real reset sequence, IRQ preservation, hard fallback, timeout and OPP policy PASS");
	return 0;
}
