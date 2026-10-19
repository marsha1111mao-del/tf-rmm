#include <arch_helpers.h>
#include <assert.h>
#include <cpuid.h>
#include <mmio.h>
#include <rec.h>
#include <stdbool.h>
#include <stdio.h>
#include <timers.h>

#define VIRTUAL_BIT (1U << EL1_VIRT_TIMER_PPI)
#define PHYSICAL_BIT (1U << EL1_PHYS_TIMER_PPI)
#define TIMER_BITS (VIRTUAL_BIT | PHYSICAL_BIT)
#define OTHER_BITS 0x80001234U

static unsigned int current_cpu;
static unsigned long virtual_control, physical_control;
static unsigned int pending_intid = 1023U;
static unsigned int pending_reads;
static unsigned int retire_after;
static uint32_t enabled[MAX_CPUS];

unsigned int my_cpuid(void)
{
	return current_cpu;
}

unsigned long read_mpidr_el1(void)
{
	return (unsigned long)current_cpu << 8U;
}

unsigned long read_cntv_ctl_el02(void)
{
	return virtual_control;
}

unsigned long read_cntp_ctl_el02(void)
{
	return physical_control;
}

unsigned long read_icc_hppir1_el1(void)
{
	return pending_reads++ < retire_after ? pending_intid : 1023U;
}

void test_dsb(void)
{
}

static unsigned int frame_cpu(const volatile void *address, uintptr_t offset)
{
	uintptr_t location = (uintptr_t)address - 0xfe680000UL;

	assert(location % 0x20000UL == offset);
	assert(location / 0x20000UL < MAX_CPUS);
	return (unsigned int)(location / 0x20000UL * 3U) % MAX_CPUS;
}

uint64_t read64(const volatile void *address)
{
	return (uint64_t)frame_cpu(address, 0x8UL) << 40U;
}

uint32_t read32(const volatile void *address)
{
	return enabled[frame_cpu(address, 0x10100UL)];
}

void write32(uint32_t value, volatile void *address)
{
	uintptr_t offset = ((uintptr_t)address - 0xfe680000UL) % 0x20000UL;
	unsigned int cpu = frame_cpu(address, offset);

	assert((value & ~TIMER_BITS) == 0U);
	if (offset == 0x10100UL)
		enabled[cpu] |= value;
	else {
		assert(offset == 0x10180UL);
		enabled[cpu] &= ~value;
	}
}

static bool asserted(unsigned long control)
{
	return control == (CNTx_CTL_ENABLE | CNTx_CTL_ISTATUS);
}

int main(void)
{
	unsigned int cases = 0U;

	for (current_cpu = 0U; current_cpu < MAX_CPUS; current_cpu++) {
		for (unsigned int initial = 0U; initial < 4U; initial++) {
			uint32_t baseline = OTHER_BITS | (initial & 1U ? VIRTUAL_BIT : 0U) |
					    (initial & 2U ? PHYSICAL_BIT : 0U);

			for (unsigned int controls = 0U; controls < 4096U; controls++) {
				struct rec rec = { .sysregs = {
					.cntv_ctl_el0 = controls & 7U,
					.cntp_ctl_el0 = (controls >> 3U) & 7U,
				} };
				uint32_t mask;
				bool expected;

				virtual_control = (controls >> 6U) & 7U;
				physical_control = (controls >> 9U) & 7U;
				enabled[current_cpu] = baseline;
				plat_opencca_timers_save();
				expected = asserted(virtual_control) != asserted(rec.sysregs.cntv_ctl_el0) ||
					   asserted(physical_control) != asserted(rec.sysregs.cntp_ctl_el0);
				assert(opencca_check_pending_timers(&rec) == expected);
				assert(rec.sysregs.cntv_ctl_el0 == (controls & 7U));
				assert(rec.sysregs.cntp_ctl_el0 == ((controls >> 3U) & 7U));
				mask = (asserted(virtual_control) ? VIRTUAL_BIT : 0U) |
				       (asserted(physical_control) ? PHYSICAL_BIT : 0U);
				assert(enabled[current_cpu] == (baseline & ~mask));
				plat_opencca_timers_restore();
				assert(enabled[current_cpu] == baseline);
				cases++;
			}
		}
	}
	current_cpu = 0U;
	virtual_control = CNTx_CTL_ENABLE | CNTx_CTL_ISTATUS;
	physical_control = 0UL;
	pending_intid = EL1_VIRT_TIMER_PPI;
	for (retire_after = 0U; retire_after < 66U; retire_after++) {
		struct rec rec = { .sysregs.cntv_ctl_el0 = virtual_control };

		pending_reads = 0U;
		plat_opencca_timers_save();
		assert(opencca_check_pending_timers(&rec) == (retire_after >= 64U));
		assert(pending_reads <= 64U);
		plat_opencca_timers_restore();
	}
	puts("OPENCCA_TIMER_TEST=PASS transitions=131072 bounded_retirement=66");
	assert(cases == 131072U);
	return 0;
}
