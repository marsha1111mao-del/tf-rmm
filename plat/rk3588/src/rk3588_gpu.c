/* SPDX-License-Identifier: BSD-3-Clause */
#include <arch_helpers.h>
#include <debug.h>
#include <mmio.h>
#include <opencca_gpu.h>
#include <opencca_gpu_firmware.h>
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
/* CSF MMU bits 0..15 are faults; bits 16..31 are AS REQ_COMPLETE. */
#define MMU_FAULT_MASK UINT32_C(0xffff)
#define TIMEOUT_US 100000UL
#define BOOT_TIMEOUT_US 5000000UL
#define GPU_ID 0x0UL
#define GPU_SHADER_PRESENT_LO 0x100UL
#define GPU_SHADER_PRESENT_HI 0x104UL
#define GPU_TILER_PRESENT_LO 0x110UL
#define GPU_TILER_PRESENT_HI 0x114UL
#define GLOBAL_DOORBELL 0x80000UL
#define GPU_L2_PRESENT_LO 0x120UL
#define L2_READY_LO 0x160UL
#define L2_PWRON_LO 0x1a0UL
#define L2_PWRTRANS_LO 0x220UL
#define GPU_COHERENCY_PROTOCOL 0x304UL
#define GPU_COHERENCY_NONE 31U
#define JOB_GLOBAL_IF (1U << 31U)
#define GPU_MMU_FEATURES 0x14UL
#define GPU_AS_PRESENT 0x18UL
#define GPU_STATUS 0x34UL
#define GPU_ACTIVE 1U
#define AS_BASE(slot) (0x2400UL + (unsigned long)(slot) * 0x40UL)
#define AS_TRANSTAB_LO(slot) (AS_BASE(slot) + 0x00UL)
#define AS_TRANSTAB_HI(slot) (AS_BASE(slot) + 0x04UL)
#define AS_MEMATTR_LO(slot) (AS_BASE(slot) + 0x08UL)
#define AS_MEMATTR_HI(slot) (AS_BASE(slot) + 0x0cUL)
#define AS_LOCKADDR_LO(slot) (AS_BASE(slot) + 0x10UL)
#define AS_LOCKADDR_HI(slot) (AS_BASE(slot) + 0x14UL)
#define AS_COMMAND(slot) (AS_BASE(slot) + 0x18UL)
#define AS_STATUS(slot) (AS_BASE(slot) + 0x28UL)
#define AS_FAULTSTATUS(slot) (AS_BASE(slot) + 0x1cUL)
#define AS_FAULTADDRESS_LO(slot) (AS_BASE(slot) + 0x20UL)
#define AS_FAULTADDRESS_HI(slot) (AS_BASE(slot) + 0x24UL)
#define AS_TRANSCFG_LO(slot) (AS_BASE(slot) + 0x30UL)
#define AS_TRANSCFG_HI(slot) (AS_BASE(slot) + 0x34UL)
#define AS_ACTIVE 1U
#define AS_UPDATE 1U
#define AS_LOCK 2U
#define AS_FLUSH_PT 4U
#define AS_FLUSH_MEM 5U
#define GPU_AS_COUNT 16U
/* Match RMM's PTE attr indices: 0=NC, 1=WB R/W allocate, all others fault.
 * NC uses Mali inner sharing and WB uses standard CPU inner sharing, as in
 * Panthor mair_to_memattr(). No caller-supplied memory attributes are accepted.
 */
#define PRIVATE_MEMATTR UINT64_C(0xc0c0c0c0c0c09f4c)
#define PRIVATE_TRANSCFG ((2UL << 24U) | (1UL << 30U) | (7UL << 6U) | 6UL)

static uint32_t reg_read(unsigned long offset)
{
	return read32((volatile void *)(uintptr_t)(OPENCCA_GPU_MMIO_BASE + offset));
}

static void reg_write(unsigned long offset, uint32_t value)
{
	write32(value, (volatile void *)(uintptr_t)(OPENCCA_GPU_MMIO_BASE + offset));
}

static bool poll_timeout(unsigned long offset, uint32_t mask, uint32_t expected,
		unsigned long microseconds)
{
	unsigned long start = read_cntpct_el0();
	unsigned long ticks = read_cntfrq_el0() / 1000000UL * microseconds;

	if (ticks == 0UL)
		return false;
	do {
		if ((reg_read(offset) & mask) == expected)
			return true;
	} while (read_cntpct_el0() - start < ticks);
	return false;
}

static bool poll(unsigned long offset, uint32_t mask, uint32_t expected)
{
	return poll_timeout(offset, mask, expected, TIMEOUT_US);
}

static void clear_irqs(void)
{
	reg_write(GPU_INT_CLEAR, reg_read(GPU_INT_RAWSTAT));
	reg_write(JOB_INT_CLEAR, reg_read(JOB_INT_RAWSTAT));
	reg_write(MMU_INT_CLEAR, reg_read(MMU_INT_RAWSTAT));
}

static bool private_pt_format(unsigned long root)
{
	uint32_t features;

	if (root == 0UL || (root & 4095UL) != 0UL ||
	    root >= (1UL << plat_opencca_gpu_pa_bits()))
		return false;
	features = reg_read(GPU_MMU_FEATURES);
	/* Four levels starting at L0 require the 48-bit input format used by
	 * the private PT core. Other formats are rejected, not silently coerced.
	 */
	return (features & 255U) == 48U && ((features >> 8U) & 255U) >= 40U;
}

static bool private_pt_ready(unsigned long root)
{
	return private_pt_format(root) && reg_read(MCU_CONTROL) == 0U && reg_read(MCU_STATUS) == 0U &&
		(reg_read(GPU_STATUS) & GPU_ACTIVE) == 0U;
}

static unsigned long private_pt_root(unsigned int slot)
{
	return reg_read(AS_TRANSTAB_LO(slot)) |
		((unsigned long)reg_read(AS_TRANSTAB_HI(slot)) << 32U);
}

static bool private_pt_command(unsigned int slot, uint32_t command)
{
	if (!poll(AS_STATUS(slot), AS_ACTIVE, 0U))
		return false;
	reg_write(AS_COMMAND(slot), command);
	dsb(sy);
	return poll(AS_STATUS(slot), AS_ACTIVE, 0U);
}

static bool private_pt_flush(unsigned int slot, uint32_t command)
{
	/* The whole 48-bit VA range, encoded as log2(size)-1 at address zero. */
	reg_write(AS_LOCKADDR_LO(slot), 47U);
	reg_write(AS_LOCKADDR_HI(slot), 0U);
	return private_pt_command(slot, AS_LOCK) && private_pt_command(slot, command);
}

static bool program_pt(unsigned long root, unsigned int slot)
{
	unsigned long previous;

	if (slot >= GPU_AS_COUNT || !private_pt_format(root) ||
	    (reg_read(GPU_AS_PRESENT) & (1U << slot)) == 0U)
		return false;
	previous = private_pt_root(slot);
	/* The core also owns the AS slot. Refuse unexplained hardware roots. */
	if (previous != 0UL && previous != root)
		return false;
	if (!private_pt_flush(slot, AS_FLUSH_MEM))
		return false;
	reg_write(AS_TRANSTAB_LO(slot), (uint32_t)root);
	reg_write(AS_TRANSTAB_HI(slot), (uint32_t)(root >> 32U));
	reg_write(AS_MEMATTR_LO(slot), (uint32_t)PRIVATE_MEMATTR);
	reg_write(AS_MEMATTR_HI(slot), (uint32_t)(PRIVATE_MEMATTR >> 32U));
	reg_write(AS_TRANSCFG_LO(slot), (uint32_t)PRIVATE_TRANSCFG);
	reg_write(AS_TRANSCFG_HI(slot), 0U);
	if (!private_pt_command(slot, AS_UPDATE))
		return false;
	dsb(sy);
	return private_pt_root(slot) == root &&
		reg_read(AS_MEMATTR_LO(slot)) == (uint32_t)PRIVATE_MEMATTR &&
		reg_read(AS_MEMATTR_HI(slot)) == (uint32_t)(PRIVATE_MEMATTR >> 32U) &&
		reg_read(AS_TRANSCFG_LO(slot)) == (uint32_t)PRIVATE_TRANSCFG &&
		reg_read(AS_TRANSCFG_HI(slot)) == 0U;
}

bool plat_opencca_gpu_pt_install(unsigned long root, unsigned int slot)
{
	return slot != 0U && private_pt_ready(root) && program_pt(root, slot);
}

bool plat_opencca_gpu_pt_sync(unsigned long root)
{
	unsigned int found = GPU_AS_COUNT;
	uint32_t present;

	if (!private_pt_ready(root))
		return false;
	present = reg_read(GPU_AS_PRESENT);
	for (unsigned int slot = 1U; slot < GPU_AS_COUNT; slot++) {
		if ((present & (1U << slot)) == 0U || private_pt_root(slot) != root)
			continue;
		if (found != GPU_AS_COUNT)
			return false; /* Unexpected alias of the same protected root. */
		found = slot;
	}
	return found != GPU_AS_COUNT && private_pt_flush(found, AS_FLUSH_PT);
}

static bool firmware_device_ready(unsigned long root)
{
	return private_pt_ready(root) && (reg_read(GPU_ID) >> 24U) == 0xa8U &&
		(reg_read(GPU_AS_PRESENT) & 1U) != 0U &&
		(reg_read(GPU_STATUS) & ((1U << 4U) | (1U << 7U) | (1U << 8U))) == 0U;
}

static bool firmware_boot_failed(const char *phase)
{
	/* Fixed status registers only: never log PT roots or Client addresses. */
	ERROR("GPU FW %s: mcu=%x/%x gpu=%x irq=%x/%x/%x l2=%x as0=%x fault=%x\n",
		phase, reg_read(MCU_CONTROL), reg_read(MCU_STATUS), reg_read(GPU_STATUS),
		reg_read(GPU_INT_RAWSTAT), reg_read(JOB_INT_RAWSTAT),
		reg_read(MMU_INT_RAWSTAT), reg_read(L2_READY_LO),
		reg_read(AS_STATUS(0U)), reg_read(AS_BASE(0U) + 0x1cUL));
	return false;
}

bool plat_opencca_gpu_firmware_install(unsigned long root)
{
	unsigned long previous;

	if (!firmware_device_ready(root) || (reg_read(GPU_L2_PRESENT_LO) & 1U) == 0U)
		return firmware_boot_failed("install-readiness");
	previous = private_pt_root(0U);
	if (previous != 0UL && previous != root)
		return firmware_boot_failed("install-root");
	/* Like native Panthor resume, power the first L2 group before MCU/MMU
	 * use. Remaining blocks are controlled by the authenticated firmware.
	 */
	if (!poll(L2_PWRTRANS_LO, 1U, 0U))
		return firmware_boot_failed("install-l2-transition");
	reg_write(L2_PWRON_LO, 1U);
	if (!poll(L2_READY_LO, 1U, 1U))
		return firmware_boot_failed("install-l2-power");
	if (!program_pt(root, 0U))
		return firmware_boot_failed("install-pt");
	INFO("GPU FW install complete\n");
	return true;
}

bool plat_opencca_gpu_firmware_boot(unsigned long root)
{
	if (!firmware_device_ready(root) || private_pt_root(0U) != root ||
	    reg_read(AS_MEMATTR_LO(0U)) != (uint32_t)PRIVATE_MEMATTR ||
	    reg_read(AS_MEMATTR_HI(0U)) != (uint32_t)(PRIVATE_MEMATTR >> 32U) ||
	    reg_read(AS_TRANSCFG_LO(0U)) != (uint32_t)PRIVATE_TRANSCFG ||
	    reg_read(AS_TRANSCFG_HI(0U)) != 0U || (reg_read(L2_READY_LO) & 1U) == 0U)
		return firmware_boot_failed("boot-readiness");
	for (unsigned int slot = 1U; slot < GPU_AS_COUNT; slot++)
		if ((reg_read(GPU_AS_PRESENT) & (1U << slot)) != 0U &&
		    private_pt_root(slot) == root)
			return firmware_boot_failed("boot-alias");
	/* Do not depend on interrupt delivery or a Proxy completion report. Keep
	 * routing masked until trusted event/queue support has been connected.
	 * Remove a stale boot bit BEFORE enabling the MCU.
	 */
	reg_write(GPU_INT_MASK, 0U);
	reg_write(MMU_INT_MASK, 0U);
	reg_write(JOB_INT_MASK, 0U);
	reg_write(JOB_INT_CLEAR, JOB_GLOBAL_IF);
	reg_write(GPU_COHERENCY_PROTOCOL, GPU_COHERENCY_NONE);
	dsb(sy);
	reg_write(MCU_CONTROL, 2U); /* MCU_CONTROL_AUTO, fixed trusted operation. */
	dsb(sy);
	if (!poll_timeout(JOB_INT_RAWSTAT, JOB_GLOBAL_IF, JOB_GLOBAL_IF, BOOT_TIMEOUT_US))
		return firmware_boot_failed("boot-timeout");
	if (!(reg_read(MCU_STATUS) == 1U && reg_read(MCU_CONTROL) == 2U &&
		reg_read(GPU_COHERENCY_PROTOCOL) == GPU_COHERENCY_NONE && private_pt_root(0U) == root &&
		(reg_read(MMU_INT_RAWSTAT) & MMU_FAULT_MASK) == 0U &&
		(reg_read(GPU_INT_RAWSTAT) & 3U) == 0U))
		return firmware_boot_failed("boot-status");
	INFO("GPU FW boot indication verified\n");
	return true;
}

static bool firmware_running(unsigned long root)
{
	uint32_t mmu = reg_read(MMU_INT_RAWSTAT) & MMU_FAULT_MASK;
	uint32_t gpu = reg_read(GPU_INT_RAWSTAT) & 3U;

	if (mmu != 0U || gpu != 0U) {
		ERROR("GPU FW fault mmu=%x gpu=%x\n", mmu, gpu);
		if ((mmu & 1U) != 0U) {
			uint32_t fault = reg_read(AS_FAULTSTATUS(0U));
			uint64_t va = reg_read(AS_FAULTADDRESS_LO(0U)) |
				((uint64_t)reg_read(AS_FAULTADDRESS_HI(0U)) << 32U);
			unsigned int region = 0U;

			/* Coarse public-layout classes only; never expose the fault VA,
			 * roots, PTEs or Client data through a diagnostic log.
			 * 1=null page, 2=firmware low VA, 3=shared interface,
			 * 4=trusted MCU arena, 5=Client protected control, 0=other.
			 */
			if (va < 4096UL)
				region = 1U;
			else if (va < 0x04000000UL)
				region = 2U;
			else if (va >= GPU_FIRMWARE_CONTROL_VA &&
				va < GPU_FIRMWARE_CONTROL_VA + GPU_PRIVATE_CONTROL_PAGES * 4096UL)
				region = 4U;
			else if (va < 0x08000000UL)
				region = 3U;
			else if (va >= GPU_PRIVATE_CONTROL_GPU_VA && va < (UINT64_C(1) << 48U))
				region = 5U;
			ERROR("GPU AS0 fault type=%x access=%u source=%x region=%u\n",
				fault & 255U, (fault >> 8U) & 3U, fault >> 16U, region);
			/* AS0's fixed low firmware VA layout is public. A virtual page
			 * number here identifies missing MCU backing; never print a PA,
			 * a root, a Client AS fault address or addresses outside this band.
			 */
			if (region == 2U)
				ERROR("GPU MCU image fault page=%x\n", (uint32_t)(va >> 12U));
		}
	}
	return root != 0UL && (root & 4095UL) == 0UL &&
		root < (1UL << plat_opencca_gpu_pa_bits()) &&
		(reg_read(GPU_ID) >> 24U) == 0xa8U &&
		(reg_read(GPU_AS_PRESENT) & 1U) != 0U && private_pt_root(0U) == root &&
		reg_read(AS_MEMATTR_LO(0U)) == (uint32_t)PRIVATE_MEMATTR &&
		reg_read(AS_MEMATTR_HI(0U)) == (uint32_t)(PRIVATE_MEMATTR >> 32U) &&
		reg_read(AS_TRANSCFG_LO(0U)) == (uint32_t)PRIVATE_TRANSCFG &&
		reg_read(AS_TRANSCFG_HI(0U)) == 0U &&
		reg_read(MCU_CONTROL) == 2U && reg_read(MCU_STATUS) == 1U &&
		reg_read(GPU_COHERENCY_PROTOCOL) == GPU_COHERENCY_NONE &&
		(reg_read(MMU_INT_RAWSTAT) & MMU_FAULT_MASK) == 0U &&
		(reg_read(GPU_INT_RAWSTAT) & 3U) == 0U;
}

bool plat_opencca_gpu_pt_prepare(unsigned long root, unsigned int slot, unsigned long firmware_root, bool existing)
{
	unsigned long previous;

	if (slot == 0U || slot >= GPU_AS_COUNT || root == firmware_root ||
	    !private_pt_format(root) || !firmware_running(firmware_root) ||
	    (reg_read(GPU_AS_PRESENT) & (1U << slot)) == 0U)
		return false;
	previous = private_pt_root(slot);
	if (existing) {
		/* Never flush/rewrite an already installed AS. The RMM core owns the
		 * slot and all hardware groups; unexplained or changed roots fail.
		 */
		return previous == root &&
			reg_read(AS_MEMATTR_LO(slot)) == (uint32_t)PRIVATE_MEMATTR &&
			reg_read(AS_MEMATTR_HI(slot)) == (uint32_t)(PRIVATE_MEMATTR >> 32U) &&
			reg_read(AS_TRANSCFG_LO(slot)) == (uint32_t)PRIVATE_TRANSCFG &&
			reg_read(AS_TRANSCFG_HI(slot)) == 0U;
	}
	return previous == 0UL && program_pt(root, slot) && firmware_running(firmware_root);
}

bool plat_opencca_gpu_pt_extend(unsigned long root, unsigned int slot, unsigned long firmware_root)
{
	for (unsigned int pass = 0U; pass < 2U; pass++) {
		if (!plat_opencca_gpu_pt_prepare(root, slot, firmware_root, true))
			return false;
		for (unsigned int other = 1U; other < GPU_AS_COUNT; other++)
			if (other != slot && private_pt_root(other) == root)
				return false;
		/* PTE stores and PoC maintenance precede this callback. Flush only
		 * this AS; recheck roots/attributes/aliases after completion too.
		 */
		if (pass == 0U && !private_pt_flush(slot, AS_FLUSH_PT))
			return false;
	}
	return true;
}

bool plat_opencca_gpu_pt_flush_live(unsigned long root, unsigned int slot,
		unsigned long firmware_root)
{
	struct gpu_firmware_config before, after;
	unsigned long frequency = read_cntfrq_el0();

	for (unsigned int pass = 0U; pass < 2U; pass++) {
		if (!plat_opencca_gpu_pt_prepare(root, slot, firmware_root, true) ||
		    !plat_opencca_gpu_firmware_configuration(firmware_root,
				pass == 0U ? &before : &after))
			return false;
		for (unsigned int other = 1U; other < GPU_AS_COUNT; other++)
			if (other != slot && private_pt_root(other) == root)
				return false;
		if (!poll(AS_STATUS(slot), AS_ACTIVE, 0U))
			return false;
		/* No UPDATE, root/attribute write, queue publication or doorbell.
		 * Flush completion orders earlier device writes; it does not stop
		 * future execution. The consumer retains all task/mapping leases.
		 */
		if (pass == 0U && !private_pt_flush(slot, AS_FLUSH_MEM))
			return false;
	}
	return read_cntfrq_el0() == frequency &&
		before.shader_mask == after.shader_mask &&
		before.poweroff_timer == after.poweroff_timer &&
		before.idle_timer == after.idle_timer &&
		before.ack_timeout_ticks == after.ack_timeout_ticks;
}

bool plat_opencca_gpu_pt_detach(unsigned long root, unsigned int slot,
		unsigned long firmware_root, bool detached)
{
	struct gpu_firmware_config config;

	if (!detached) {
		if (!plat_opencca_gpu_pt_flush_live(root, slot, firmware_root))
			return false;
		/* Match native panthor_mmu_as_disable(). Zero is NOT Mali UNMAPPED;
		 * the fixed address-mode encoding is one. Retain software ownership
		 * until the caller has verified UPDATE and later returned CPU caches.
		 */
		reg_write(AS_TRANSTAB_LO(slot), 0U);
		reg_write(AS_TRANSTAB_HI(slot), 0U);
		reg_write(AS_MEMATTR_LO(slot), 0U);
		reg_write(AS_MEMATTR_HI(slot), 0U);
		reg_write(AS_TRANSCFG_LO(slot), 1U);
		reg_write(AS_TRANSCFG_HI(slot), 0U);
		if (!private_pt_command(slot, AS_UPDATE))
			return false;
	} else {
		/* The live primitive already validates these before first detach.
		 * A disabled replay cannot use it; retain its read-only checks here.
		 */
		if (slot == 0U || slot >= GPU_AS_COUNT || root == firmware_root ||
		    !private_pt_format(root) ||
		    !plat_opencca_gpu_firmware_configuration(firmware_root, &config) ||
		    (reg_read(GPU_AS_PRESENT) & (1U << slot)) == 0U)
			return false;
		/* A duplicate root would leave a DMA path through another AS. */
		for (unsigned int other = 1U; other < GPU_AS_COUNT; other++)
			if (other != slot && private_pt_root(other) == root)
				return false;
	}
	/* Replays replace the firmware consumer's duplicate configuration reads.
	 * Check the complete trusted configuration on both sides of AS validation;
	 * never reuse a proof from an earlier call or across cache callbacks.
	 */
	return poll(AS_STATUS(slot), AS_ACTIVE, 0U) &&
		(detached ? plat_opencca_gpu_firmware_configuration(firmware_root, &config) :
		 firmware_running(firmware_root)) &&
		private_pt_root(slot) == 0UL && reg_read(AS_MEMATTR_LO(slot)) == 0U &&
		reg_read(AS_MEMATTR_HI(slot)) == 0U && reg_read(AS_TRANSCFG_LO(slot)) == 1U &&
		reg_read(AS_TRANSCFG_HI(slot)) == 0U;
}

bool plat_opencca_gpu_firmware_configuration(unsigned long root, struct gpu_firmware_config *config)
{
	unsigned long frequency = read_cntfrq_el0();

	if (config == NULL || !firmware_running(root) || frequency == 0UL ||
	    frequency > 1000000000UL)
		return false;
	config->shader_mask = reg_read(GPU_SHADER_PRESENT_LO) |
		((uint64_t)reg_read(GPU_SHADER_PRESENT_HI) << 32U);
	if (config->shader_mask == 0U || reg_read(GPU_TILER_PRESENT_LO) != 1U ||
	    reg_read(GPU_TILER_PRESENT_HI) != 0U)
		return false;
	/* Native time conversion, trusted architectural counter, 1024-cycle
	 * units. Neither the timer source nor the enabled shader mask is RPC data.
	 */
	config->poweroff_timer = (uint32_t)((frequency * 10000UL + 1023999999UL) / 1024000000UL);
	config->idle_timer = (uint32_t)((frequency * 800UL + 1023999999UL) / 1024000000UL);
	config->ack_timeout_ticks = (frequency + 9UL) / 10UL; /* 100 ms. */
	return true;
}

bool plat_opencca_gpu_pt_check_running(unsigned long root, unsigned int slot,
		unsigned long firmware_root, struct gpu_firmware_config *config)
{
	unsigned long frequency = read_cntfrq_el0();

	/* This entry only checks a previously programmed Client AS. The RMM
	 * policy and mapping locks exclude register/configuration writers. Share
	 * one fresh MCU/root/configuration check with the Client AS check; never
	 * retain its result across calls, cache callbacks, or hardware commands.
	 */
	if (slot == 0U || slot >= GPU_AS_COUNT || root == firmware_root ||
	    !plat_opencca_gpu_firmware_configuration(firmware_root, config) ||
	    !private_pt_format(root) ||
	    (reg_read(GPU_AS_PRESENT) & (1U << slot)) == 0U ||
	    private_pt_root(slot) != root ||
	    reg_read(AS_MEMATTR_LO(slot)) != (uint32_t)PRIVATE_MEMATTR ||
	    reg_read(AS_MEMATTR_HI(slot)) != (uint32_t)(PRIVATE_MEMATTR >> 32U) ||
	    reg_read(AS_TRANSCFG_LO(slot)) != (uint32_t)PRIVATE_TRANSCFG ||
	    reg_read(AS_TRANSCFG_HI(slot)) != 0U)
		return false;
	/* Faults and MCU progress can change without a CPU configuration writer.
	 * Recheck those dynamic fields after the Client AS read, as well as the
	 * trusted timer. Static roots/attributes were all read in this invocation.
	 */
	return read_cntfrq_el0() == frequency &&
		reg_read(MCU_CONTROL) == 2U && reg_read(MCU_STATUS) == 1U &&
		(reg_read(MMU_INT_RAWSTAT) & MMU_FAULT_MASK) == 0U &&
		(reg_read(GPU_INT_RAWSTAT) & 3U) == 0U;
}

bool plat_opencca_gpu_firmware_notify(unsigned long root)
{
	if (!firmware_running(root))
		return false;
	/* Only the trusted core can issue this fixed notification. No register
	 * offset, CSG mask, user doorbell or arbitrary value comes from Proxy.
	 */
	dsb(sy);
	reg_write(GLOBAL_DOORBELL, 1U);
	dsb(sy);
	return firmware_running(root);
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
