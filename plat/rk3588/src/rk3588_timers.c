#include <arch_helpers.h>
#include <assert.h>
#include <cpuid.h>
#include <mmio.h>
#include <stdint.h>
#include <timers.h>

#define GICR_BASE 0xfe680000UL
#define GICR_STRIDE 0x20000UL
#define GICR_TYPER 0x8UL
#define GICR_ISENABLER0 0x10100UL
#define GICR_ICENABLER0 0x10180UL
#define TIMER_MASK ((1U << EL1_VIRT_TIMER_PPI) | (1U << EL1_PHYS_TIMER_PPI))

static uintptr_t timer_frames[MAX_CPUS];
static uint32_t timer_enables[MAX_CPUS];

static uintptr_t timer_frame(unsigned int cpu)
{
	unsigned long mpidr = read_mpidr_el1();
	uint32_t affinity = (uint32_t)(mpidr & 0xffffffUL) |
			    (uint32_t)((mpidr >> 8U) & 0xff000000UL);

	assert(cpu < MAX_CPUS);
	if (timer_frames[cpu] != 0UL)
		return timer_frames[cpu];
	for (unsigned int index = 0U; index < 8U; index++) {
		uintptr_t frame = GICR_BASE + index * GICR_STRIDE;

		if ((uint32_t)(read64((volatile void *)(frame + GICR_TYPER)) >> 32U) == affinity) {
			timer_frames[cpu] = frame;
			return frame;
		}
	}
	assert(false);
	return 0UL;
}

void plat_opencca_timers_save(void)
{
	unsigned int cpu = my_cpuid();
	uintptr_t frame = timer_frame(cpu);

	timer_enables[cpu] = read32((volatile void *)(frame + GICR_ISENABLER0)) & TIMER_MASK;
}

void plat_opencca_timers_mask(bool virtual_masked, bool physical_masked)
{
	unsigned int cpu = my_cpuid();
	uintptr_t frame = timer_frame(cpu);
	uint32_t mask = (virtual_masked ? 1U << EL1_VIRT_TIMER_PPI : 0U) |
			(physical_masked ? 1U << EL1_PHYS_TIMER_PPI : 0U);

	write32(mask, (volatile void *)(frame + GICR_ICENABLER0));
	write32(timer_enables[cpu] & ~mask, (volatile void *)(frame + GICR_ISENABLER0));
	dsb(sy);
}

void plat_opencca_timers_restore(void)
{
	unsigned int cpu = my_cpuid();
	uintptr_t frame = timer_frame(cpu);

	write32(TIMER_MASK & ~timer_enables[cpu],
		(volatile void *)(frame + GICR_ICENABLER0));
	write32(timer_enables[cpu], (volatile void *)(frame + GICR_ISENABLER0));
	dsb(sy);
}

/* OpenCCA shares EL1 physical timer registers with the NS Host. Preserve
 * its deadline with the otherwise separate EL2 timer while Realm EL1 owns
 * CNTP. This is a scheduling interrupt only, never GPU completion evidence.
 */
#define HOST_TIMER_PPI 26U
#define HOST_TIMER_BIT (1U << HOST_TIMER_PPI)
#define GICR_ISPENDR0 0x10200UL
#define GICR_ICPENDR0 0x10280UL

struct host_timer_guard {
	unsigned long control, cval, deadline;
	uint32_t enabled, pending;
	bool armed;
};
static struct host_timer_guard host_guards[MAX_CPUS];

void plat_opencca_host_timer_start(unsigned long control, unsigned long cval)
{
	unsigned int cpu = my_cpuid();
	struct host_timer_guard *guard = &host_guards[cpu];
	uintptr_t frame = timer_frame(cpu);
	unsigned long now, deadline = cval;

	assert(!guard->armed);
	if ((control & (CNTx_CTL_ENABLE | CNTx_CTL_IMASK)) != CNTx_CTL_ENABLE)
		return;

	guard->control = read_cnthp_ctl_el2();
	guard->cval = read_cnthp_cval_el2();
	guard->enabled = read32((volatile void *)(frame + GICR_ISENABLER0)) & HOST_TIMER_BIT;
	guard->pending = read32((volatile void *)(frame + GICR_ISPENDR0)) & HOST_TIMER_BIT;
	guard->deadline = cval;
	guard->armed = true;
	/* Do not postpone a previously enabled EL2 timer. */
	now = read_cntpct_el0();
	if ((guard->control & (CNTx_CTL_ENABLE | CNTx_CTL_IMASK)) == CNTx_CTL_ENABLE &&
	    (int64_t)(guard->cval - now) < (int64_t)(deadline - now))
		deadline = guard->cval;
	write_cnthp_ctl_el2(0UL);
	isb();
	write_cnthp_cval_el2(deadline);
	write_cnthp_ctl_el2(CNTx_CTL_ENABLE);
	isb();
	write32(HOST_TIMER_BIT, (volatile void *)(frame + GICR_ISENABLER0));
	dsb(sy);
}

bool plat_opencca_host_timer_expired(void)
{
	struct host_timer_guard *guard = &host_guards[my_cpuid()];

	return guard->armed &&
	       (int64_t)(read_cntpct_el0() - guard->deadline) >= 0;
}

void plat_opencca_host_timer_stop(void)
{
	unsigned int cpu = my_cpuid();
	struct host_timer_guard *guard = &host_guards[cpu];
	uintptr_t frame = timer_frame(cpu);

	if (!guard->armed)
		return;
	write_cnthp_ctl_el2(0UL);
	isb();
	/* No IAR acknowledgement occurs on the Realm exit path. Retire only
	 * the temporary pending bit; preserve a pre-existing Host pending IRQ.
	 */
	if (guard->pending == 0U)
		write32(HOST_TIMER_BIT, (volatile void *)(frame + GICR_ICPENDR0));
	if (guard->enabled == 0U)
		write32(HOST_TIMER_BIT, (volatile void *)(frame + GICR_ICENABLER0));
	write_cnthp_cval_el2(guard->cval);
	write_cnthp_ctl_el2(guard->control);
	isb();
	dsb(sy);
	guard->armed = false;
}
