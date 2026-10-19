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
