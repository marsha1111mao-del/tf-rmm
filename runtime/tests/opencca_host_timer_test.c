/* SPDX-License-Identifier: BSD-3-Clause */
#include <arch_helpers.h>
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <timers.h>

#define HOST_TIMER_BIT (1U << 26)
#define REALM_TIMER_BITS ((1U << 27) | (1U << 30))

static unsigned int cpu;
static uint32_t enabled[8], pending[8];
static unsigned long control[8], compare[8], now;

unsigned int my_cpuid(void)
{
	return cpu;
}

unsigned long read_mpidr_el1(void)
{
	return (unsigned long)cpu << 8;
}

unsigned long read_cntpct_el0(void)
{
	return now;
}

unsigned long read_cnthp_ctl_el2(void)
{
	return control[cpu];
}

unsigned long read_cnthp_cval_el2(void)
{
	return compare[cpu];
}

void write_cnthp_ctl_el2(unsigned long value)
{
	control[cpu] = value & 3UL;
}

void write_cnthp_cval_el2(unsigned long value)
{
	compare[cpu] = value;
}

void test_dsb(void)
{
}

void test_isb(void)
{
}

static unsigned int frame_cpu(const volatile void *address)
{
	uintptr_t offset = (uintptr_t)address - 0xfe680000UL;

	assert(offset / 0x20000UL < 8);
	return offset / 0x20000UL;
}

uint64_t read64(const volatile void *address)
{
	assert(((uintptr_t)address & 0x1ffffUL) == 8);
	return (uint64_t)frame_cpu(address) << 40;
}

uint32_t read32(const volatile void *address)
{
	unsigned int target = frame_cpu(address);
	unsigned long offset = (uintptr_t)address & 0x1ffffUL;

	if (offset == 0x10100)
		return enabled[target];
	assert(offset == 0x10200);
	return pending[target];
}

void write32(uint32_t value, volatile void *address)
{
	unsigned int target = frame_cpu(address);
	unsigned long offset = (uintptr_t)address & 0x1ffffUL;

	assert(!(value & ~(HOST_TIMER_BIT | REALM_TIMER_BITS)));
	if (offset == 0x10100)
		enabled[target] |= value;
	else if (offset == 0x10180)
		enabled[target] &= ~value;
	else {
		assert(offset == 0x10280);
		pending[target] &= ~value;
	}
}

static void expire(void)
{
	if ((control[cpu] & 3) == 1 && (int64_t)(now - compare[cpu]) >= 0)
		pending[cpu] |= HOST_TIMER_BIT;
}

static void check_state(unsigned int old_control, bool old_enabled,
			bool old_pending, unsigned int host_control,
			bool earlier)
{
	uint32_t saved_enabled = 0x80001234U |
				 (old_enabled ? HOST_TIMER_BIT : 0);
	uint32_t saved_pending = 0x12345U |
				 (old_pending ? HOST_TIMER_BIT : 0);
	unsigned long saved_compare = earlier ? 1050 : 1200;
	bool active = host_control == 1;

	now = 1000;
	control[cpu] = old_control;
	compare[cpu] = saved_compare;
	enabled[cpu] = saved_enabled;
	pending[cpu] = saved_pending;
	plat_opencca_host_timer_start(host_control, 1100);
	assert(!plat_opencca_host_timer_expired());
	assert((enabled[cpu] & ~HOST_TIMER_BIT) ==
	       (saved_enabled & ~HOST_TIMER_BIT));
	if (active) {
		assert(enabled[cpu] & HOST_TIMER_BIT);
		assert(compare[cpu] ==
		       ((old_control == 1 && earlier) ? 1050UL : 1100UL));
		/* Masked Guest PPIs must not suppress the Host's deadline. */
		plat_opencca_timers_save();
		plat_opencca_timers_mask(true, true);
		assert(enabled[cpu] & HOST_TIMER_BIT);
		plat_opencca_timers_restore();
	} else {
		assert(enabled[cpu] == saved_enabled);
		assert(control[cpu] == old_control);
	}

	now = 1100;
	expire();
	assert(plat_opencca_host_timer_expired() == active);
	plat_opencca_host_timer_stop();
	assert(!plat_opencca_host_timer_expired());
	assert(control[cpu] == old_control && compare[cpu] == saved_compare);
	assert(enabled[cpu] == saved_enabled);
	/* Preserve existing pending state and retire the temporary interrupt. */
	if (active)
		assert(pending[cpu] == saved_pending);
	else
		assert((pending[cpu] & saved_pending) == saved_pending);
	plat_opencca_host_timer_stop();
	assert(enabled[cpu] == saved_enabled);
}

static void check_wrap_and_cpu_ownership(void)
{
	cpu = 0;
	control[0] = 0;
	enabled[0] = 0;
	pending[0] = 0;
	now = ULONG_MAX - 20;
	plat_opencca_host_timer_start(1, 10);
	assert(!plat_opencca_host_timer_expired());
	cpu = 1;
	assert(!plat_opencca_host_timer_expired());
	cpu = 0;
	now = 10;
	assert(plat_opencca_host_timer_expired());
	plat_opencca_host_timer_stop();
	now = 200;
	plat_opencca_host_timer_start(1, 100);
	assert(plat_opencca_host_timer_expired());
	plat_opencca_host_timer_stop();

	now = 1000;
	plat_opencca_host_timer_start(1, 1100);
	cpu = 1;
	control[1] = 0;
	enabled[1] = 0;
	pending[1] = 0;
	plat_opencca_host_timer_start(1, 1200);
	now = 1150;
	assert(!plat_opencca_host_timer_expired());
	cpu = 0;
	assert(plat_opencca_host_timer_expired());
	plat_opencca_host_timer_stop();
	cpu = 1;
	assert(!plat_opencca_host_timer_expired());
	assert(control[1] == 1 && compare[1] == 1200);
	assert(enabled[1] & HOST_TIMER_BIT);
	now = 1200;
	assert(plat_opencca_host_timer_expired());
	plat_opencca_host_timer_stop();
}

int main(void)
{
	unsigned int count = 0;

	for (cpu = 0; cpu < 8; cpu++)
		for (unsigned int old_control = 0; old_control < 4; old_control++)
			for (unsigned int en = 0; en < 2; en++)
				for (unsigned int pend = 0; pend < 2; pend++)
					for (unsigned int host = 0; host < 4; host++)
						for (unsigned int earlier = 0; earlier < 2; earlier++) {
							check_state(old_control, en, pend, host, earlier);
							count++;
						}
	check_wrap_and_cpu_ownership();
	printf("HOST_TIMER_GUARD_PASS combinations=%u plus_wrap_overdue_cpu_isolation\n",
	       count);
	return 0;
}
