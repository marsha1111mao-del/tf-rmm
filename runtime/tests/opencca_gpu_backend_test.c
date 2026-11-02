/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <opencca_gpu.h>
#include <opencca_gpu_lease.h>
#include <opencca_gpu_private.h>
#include <opencca_gpu_firmware.h>
#include <mbedtls/sha256.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint32_t registers[0x80004U / 4U];
static unsigned int soft_commands, hard_commands, barriers;
/* Two Clients now exercise a second AS lifecycle before whole-device reset. */
static unsigned int writes, as_commands[2048], as_count;
static unsigned int fail_as_command;
static unsigned int extend_corruption;
static unsigned int live_flush_corruption;
static unsigned int drain_case, drain_flushes, drain_post_corruption;
static unsigned int domain_case;
static bool domain_active, domain_dispatch_only;
#ifdef GPU_DOMAIN_RSI_TEST
static bool domain_policy_locked, domain_dispatch_active;
#endif
static unsigned int domain_write_fault;
static unsigned int domain_read_fault, domain_reads_until_fault;
static unsigned long domain_idle_group;
static void model_domain_ack(void);
static bool drain_barrier_failure;
static unsigned char nc_data_visibility[2][2];
static uint32_t *drain_fault, drain_fault_saved;
static void drain_corrupt_controls(unsigned int scenario);
static bool soft_succeeds, hard_succeeds;
static unsigned long clock_ticks;
static bool allow_firmware, firmware_succeeds, l2_succeeds;
static bool update_firmware_shared;
static unsigned int firmware_starts;
static unsigned long timer_frequency = 1000000UL;
static unsigned int firmware_doorbells;
static unsigned int mmio_reads, firmware_checks, shader_checks;
static unsigned int detach_read_corruption;
static bool firmware_acks = true;
static unsigned int control_writes, fail_control_write;
static unsigned int data_syncs, fail_data_sync, fault_after_data_sync;
static unsigned long sync_expected_base, sync_expected_pages;
static bool synced_data[GPU_PRIVATE_BATCH + 1U];
static unsigned int cpu_returns, fail_cpu_return, return_case;
static unsigned long return_expected_base, return_expected_pages;
static bool returned_data[GPU_PRIVATE_BATCH + 1U];
static bool track_retire;
static unsigned int retire_case, retire_clears, retire_expected_count;
static unsigned int retire_boundary_case;
static unsigned int complete_boundary_case, reclaim_case, finish_case;
static uint32_t *complete_boundary_fault[2], complete_boundary_saved[2];
static unsigned long retire_expected_pa[GPU_PRIVATE_BATCH];
/* Model MCU addresses are captured at boot, independently of the production
 * cached offsets. Later tests corrupt public descriptor pointers deliberately.
 */
static uint32_t *model_glb_in, *model_glb_out;
static struct {
	uint32_t *input, *output;
	uint32_t *cs_input[GPU_FIRMWARE_STREAMS], *cs_output[GPU_FIRMWARE_STREAMS];
} model_groups[GPU_FIRMWARE_GROUPS];
static unsigned int model_group_count, model_stream_count;
static bool fatal_snapshot_case;
static bool model_limited_groups;
static unsigned int launch_case, launch_csg, launch_queue, launch_cleans, refresh_failure;
static bool track_launch;
static bool track_stop;
static unsigned int stop_case;
static unsigned long quiesce_sync_pa[2];
static bool track_complete;
static bool track_heap;
static unsigned int heap_case, heap_cleans;
static unsigned int complete_case, status_cleans, control_reads, complete_reads_this_call;
static unsigned long complete_read_pa[3];

/* Independent multi-queue MCU double. Tests production page tables and backend
 * MMIO functions; this is not evidence that real firmware executed commands.
 */
static bool batch_mode, batch_trace, batch_publish;
static unsigned int resume_accept_case;
static unsigned int dispatch_case;
static unsigned int suspend_observe_case;
static bool suspend_observe_active;
static bool first_launch_exact;
static unsigned int batch_case, batch_cleans, batch_cs_cleans;
static unsigned long batch_io[2][2], batch_sync;
static unsigned int batch_counts[2];
static unsigned int persistent_case, suspend_count;
static uint64_t model_queue_state;
static uint64_t *firmware_leaf(unsigned long root, unsigned long va);

static uint64_t *model_saved_state(void)
{
	unsigned long root = registers[0x2400U / 4U] | ((unsigned long)registers[0x2404U / 4U] << 32U);
	uint32_t *in = model_groups[0].input;
	unsigned long va = in[16] | ((unsigned long)in[17] << 32U);

	return (void *)(uintptr_t)(*firmware_leaf(root, va) & UINT64_C(0x000000fffffff000));
}

static void model_batch_ack(void)
{
	uint32_t *input = model_groups[0].input, *output = model_groups[0].output;
	bool stop = (input[0] & 7U) == 0U;
	if (persistent_case != 0U && !stop && (input[0] & 7U) == 3U &&
	    (output[0] & 7U) == 2U) {
		model_queue_state = *model_saved_state();
		assert(model_queue_state == UINT64_C(0xc5f123456789abcd));
	}
	bool status = !stop && ((input[0] ^ output[0]) & (1U << 5U)) != 0U;

	if (batch_publish) {
		assert(!stop && !status && batch_cleans == 2U && batch_cs_cleans == 0U);
		assert(((model_glb_in[2] ^ model_glb_out[2]) & 1U) != 0U);
		assert(((input[2] ^ output[2]) & 3U) != 0U);
		if (batch_case == 47U)
			return; /* Actual notification, but no ACK: keep uncertain state. */
		model_glb_out[2] = model_glb_in[2];
		output[2] = input[2];
		if (batch_case == 48U)
			registers[(0x2400U + input[20] * 0x40U) / 4U] ^= 0x1000U;
		if (batch_case == 49U)
			model_groups[0].cs_output[1][32] = 7U;
		if (batch_case == 50U)
			model_groups[0].cs_output[2][0] = 1U;
		return;
	}
	if (status && batch_cs_cleans == 2U) {
		assert(batch_cleans == 6U && ((input[0] ^ output[0]) & 0x17U) == 0U);
		assert(input[2] == output[2]);
		assert(((model_glb_in[2] ^ model_glb_out[2]) & 1U) != 0U);
		model_glb_out[2] = model_glb_in[2];
		output[0] = input[0];
		for (unsigned int q = 0U; q < 2U; q++) {
			if (q == 1U && batch_case == 1U)
				continue; /* Fresh observation still reports STOP. */
			model_groups[0].cs_output[q][0] = model_groups[0].cs_input[q][0];
		}
		return;
	}
	assert(batch_cleans == (status ? 2U : 4U));
	assert(batch_cs_cleans == (status ? 0U : 2U));
	assert(((model_glb_in[2] ^ model_glb_out[2]) & 1U) != 0U);
	model_glb_out[2] = model_glb_in[2];
	if (status) {
		for (unsigned int q = 0U; q < 2U; q++) {
			uint64_t *in = (void *)(uintptr_t)batch_io[q][0];
			uint64_t *out = (void *)(uintptr_t)batch_io[q][1];
			uint32_t *sync = (void *)(uintptr_t)(batch_sync + q * 16U);
			uint32_t *cs = model_groups[0].cs_output[q];

			if (suspend_observe_active) cs[23] = cs[24] = 0U;

			out[0] = in[0];
			sync[0] = (persistent_case != 0U || batch_case >= 36U) ?
				(unsigned int)(in[0] / 128U) : batch_counts[q];
			if (persistent_case == 7U && suspend_count != 0U) sync[0] = 0U;
			sync[1] = sync[2] = sync[3] = 0U;
			if (q == 1U) {
				if (batch_case == 2U) out[0] = 0U, sync[0] = 0U;
				if (batch_case == 3U) cs[23] = 1U;
				if (batch_case == 4U) cs[32] = 7U;
				if (batch_case == 5U) sync[0]++;
				if (batch_case == 6U || batch_case == 9U) in[0] += 128U;
				if (batch_case == 17U) cs[24] = 1U;
			}
			if (q == 0U && batch_case == 9U) out[0] = 0U, sync[0] = 0U;
			if (batch_case == 19U && q == 1U) out[0] = 0U, sync[0] = 0U;
			if (batch_case >= 20U && batch_case <= 23U) {
				if (q == 0U) out[0] = 0U, sync[0] = 0U;
				else {
					out[0] = batch_case == 20U || batch_case == 21U ? 128U : 256U;
					sync[0] = batch_case == 21U ? 2U : batch_case == 23U ? 0U : 1U;
				}
			}
			if (q == 1U) {
				if (batch_case == 25U) sync[0]++;
				if (batch_case == 26U) cs[32] = 7U;
				if (batch_case == 30U) sync[2] = 7U;
				if (batch_case == 34U) cs[23] = 1U;
				if (batch_case == 35U) out[0] = 127U;
			}
			if (batch_case == 32U) {
				if (q == 0U) out[0] = 0U, sync[0] = 0U;
				else out[0] = 120U, sync[0] = 1U;
			}
			if (batch_case == 33U) out[0] = q == 0U ? 256U : 128U, sync[0] = q == 0U ? 2U : 1U;
		}
		if (batch_case != 13U && batch_case != 27U) output[0] = input[0];
		if (batch_case == 12U || batch_case == 28U)
			registers[(0x2400U + input[20] * 0x40U) / 4U] ^= 0x1000U;
	} else {
		if (persistent_case != 0U && stop) model_queue_state = 0U;
		assert((input[2] ^ output[2]) == 3U);
		output[0] = input[0];
		output[2] = input[2];
		for (unsigned int q = 0U; q < 2U; q++) {
			assert((model_groups[0].cs_input[q][0] & 7U) == (stop ? 0U : 1U));
			if (q == 1U && ((!stop && batch_case == 1U) || (stop && batch_case == 7U)))
				continue;
			if (stop || first_launch_exact)
				model_groups[0].cs_output[q][0] = model_groups[0].cs_input[q][0];
		}
		if (!stop && batch_case == 15U)
			model_groups[0].cs_output[2][0] = 1U;
	}
}

static void model_stop_ack(void)
{
	unsigned int csg = launch_csg, queue = launch_queue;
	uint32_t parent = 1U << csg, child = 1U << queue;
	uint32_t *input = model_groups[csg].input, *output = model_groups[csg].output;
	uint32_t *cs = model_groups[csg].cs_input[queue];
	uint32_t *cs_out = model_groups[csg].cs_output[queue];

	assert(launch_cleans == 3U && (cs[0] & 7U) == 0U && (input[0] & 7U) == 0U);
	assert(((input[0] ^ output[0]) & 0x10U) == 0U); /* STOP preserves endpoint toggle. */
	assert(((model_glb_in[2] ^ model_glb_out[2]) & parent) != 0U);
	assert(((input[2] ^ output[2]) & child) != 0U);
	if (stop_case == 34U)
		return;
	model_glb_out[2] = (model_glb_out[2] & ~parent) | (model_glb_in[2] & parent);
	output[2] = (output[2] & ~child) | (input[2] & child);
	output[0] = input[0];
	if (stop_case != 35U)
		cs_out[0] = cs[0];
	if (stop_case == 36U)
		output[0] = (output[0] & ~7U) | 2U;
	if (stop_case == 42U)
		registers[0x2000U / 4U] = 1U;
	if (stop_case == 43U)
		registers[(0x2400U + input[20] * 0x40U) / 4U] ^= 0x1000U;
	if (stop_case == 46U)
		registers[(0x2428U + input[20] * 0x40U) / 4U] = 1U;
}

static void model_task_ack(void)
{
	unsigned int csg = launch_csg, queue = launch_queue;
	uint32_t parent = 1U << csg, child = 1U << queue;
	uint32_t *input = model_groups[csg].input, *output = model_groups[csg].output;
	uint32_t *cs = model_groups[csg].cs_input[queue];

	assert(csg < model_group_count && queue < model_stream_count);
	if (launch_cleans == 5U) {
		/* START acknowledged without refreshing CS output. Only a later
		 * STATUS_UPDATE publishes the fresh queue snapshot in this model.
		 */
		assert(((input[0] ^ output[0]) & (1U << 5U)) != 0U);
		assert(((input[0] ^ output[0]) & 0x17U) == 0U);
		assert(((input[2] ^ output[2]) & child) == 0U);
		assert(((model_glb_in[2] ^ model_glb_out[2]) & parent) != 0U);
		if (refresh_failure != 1U)
			model_glb_out[2] = (model_glb_out[2] & ~parent) | (model_glb_in[2] & parent);
		if (refresh_failure != 2U)
			output[0] = input[0];
		if (launch_case != 15U && refresh_failure != 3U)
			for (unsigned int q = 0U; q < model_stream_count; q++)
				model_groups[csg].cs_output[q][0] = model_groups[csg].cs_input[q][0];
		return;
	}
	assert(launch_cleans == 3U);
	assert((cs[0] & ~(1U << 26U)) == 0x511U &&
		(cs[0] & (1U << 26U)) == (model_groups[csg].cs_output[queue][0] & (1U << 26U)) &&
		cs[3] == 0U && input[1] == 0U && model_glb_in[1] == 0U);
	assert(((input[0] & 7U) == 1U || (input[0] & 7U) == 3U) &&
		((input[0] ^ output[0]) & 0x10U) != 0U);
	assert(((model_glb_in[2] ^ model_glb_out[2]) & parent) != 0U);
	assert(((input[2] ^ output[2]) & child) != 0U);
	if (launch_case == 14U)
		return; /* No launch ACKs: bounded timeout, no completion fabrication. */
	model_glb_out[2] = (model_glb_out[2] & ~parent) | (model_glb_in[2] & parent);
	output[2] = (output[2] & ~child) | (input[2] & child);
	output[0] = input[0];
	/* CS output intentionally remains the previous STOP snapshot. */
	if (launch_case == 17U)
		output[0] = (output[0] & ~7U) | 3U; /* Must not match START state 1. */
	if (launch_case == 20U)
		registers[0x2000U / 4U] = 1U;
	if (launch_case == 21U)
		registers[(0x2400U + input[20] * 0x40U) / 4U] ^= 0x1000U;
	if (launch_case == 25U)
		model_glb_out[4] = 1U;
}

static uint64_t *firmware_leaf(unsigned long root, unsigned long va)
{
	uint64_t *table = (void *)root;

	for (unsigned int level = 0U; level < 3U; level++) {
		uint64_t pte = table[(va >> (39U - level * 9U)) & 511UL];

		assert((pte & 3UL) == 3UL);
		table = (void *)(uintptr_t)(pte & UINT64_C(0x000000fffffff000));
	}
	return &table[(va >> 12U) & 511UL];
}

static void model_status_ack(void)
{
	unsigned int csg = launch_csg, queue = launch_queue;
	uint32_t *input = model_groups[csg].input, *output = model_groups[csg].output;
	uint32_t *cs_out = model_groups[csg].cs_output[queue];
	uint32_t parent = 1U << csg;
	uint64_t *ring_output = (void *)(uintptr_t)complete_read_pa[1];
	uint32_t *sync = (void *)(uintptr_t)(complete_read_pa[2] + queue * 16U);

	if (!(status_cleans == 2U && (input[0] & 7U) == 1U))
		fprintf(stderr, "STATUS_FIXTURE csg=%u input=%x cleans=%u boundary_case=%u\n", csg, input[0], status_cleans, retire_boundary_case);
	assert(status_cleans == 2U && (input[0] & 7U) == 1U);
	assert(((input[0] ^ output[0]) & (1U << 5U)) != 0U);
	assert(((model_glb_in[2] ^ model_glb_out[2]) & parent) != 0U);
	if (complete_case == 67U)
		return;
	if (complete_case != 91U)
		model_glb_out[2] = (model_glb_out[2] & ~parent) | (model_glb_in[2] & parent);
	if (complete_case == 68U)
		return; /* Stale STATUS ACK cannot bless the initial zero idle fields. */
	output[0] = input[0];
	cs_out[23] = complete_case == 70U ? 1U : 0U;
	cs_out[24] = complete_case == 71U ? 3U : 0U;
	ring_output[0] = complete_case == 72U ? 64U : 128U;
	sync[0] = complete_case == 73U ? 0U : 1U;
	sync[1] = sync[2] = sync[3] = 0U;
	if (complete_case == 74U)
		sync[0] = sync[1] = UINT32_MAX;
	if (complete_case == 75U)
		sync[2] = 7U;
	if (complete_case == 76U)
		*(uint64_t *)(uintptr_t)complete_read_pa[0] = 256U;
	if (complete_case == 78U)
		registers[0x2000U / 4U] = 1U;
	if (complete_case == 79U)
		registers[(0x2400U + input[20] * 0x40U) / 4U] ^= 0x1000U;
	if (complete_case == 89U)
		model_groups[csg].cs_output[0][0] |= 1U << 31U;
	if (complete_case == 90U)
		output[0] = (output[0] & ~7U) | 3U;
}

unsigned long read_cntpct_el0(void)
{
	clock_ticks += 1000UL;
	return clock_ticks;
}

unsigned long read_cntfrq_el0(void)
{
	return timer_frequency;
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
	unsigned long offset = reg_offset(address);
	uint32_t value = registers[offset / 4UL];

	mmio_reads++;
	if (offset == 0UL) firmware_checks++;
	if (offset == 0x100UL) shader_checks++;
	/* Restore an invalid precondition only after the precheck should reject;
	 * inject new corruption after the first check to require the postcheck.
	 */
	if (offset == 0x2480UL && detach_read_corruption == 1U)
		timer_frequency = 1000000UL;
	if (offset == 0x2468UL) {
		if (detach_read_corruption == 2U) timer_frequency = 0UL;
		if (detach_read_corruption == 3U) registers[0x110U / 4U] = 0U;
		if (detach_read_corruption == 4U) registers[0x2000U / 4U] = 1U;
		if (detach_read_corruption == 5U) registers[0x2400U / 4U] ^= 0x1000U;
		if (detach_read_corruption == 6U) registers[0x704U / 4U] = 0U;
	}
	return value;
}

static void corrupt_live_flush(unsigned int scenario)
{
	switch (scenario) {
	case 1U: registers[0x2440U / 4U] ^= 0x1000U; break;
	case 2U: registers[0x2444U / 4U] ^= 1U; break;
	case 3U: registers[0x2448U / 4U] ^= 1U; break;
	case 4U: registers[0x244cU / 4U] ^= 1U; break;
	case 5U: registers[0x2470U / 4U] ^= 1U; break;
	case 6U: registers[0x2474U / 4U] ^= 1U; break;
	case 7U: registers[0x18U / 4U] &= ~2U; break;
	case 8U: registers[0x18U / 4U] &= ~1U; break;
	case 9U: registers[0x2400U / 4U] ^= 0x1000U; break;
	case 10U: registers[0x2404U / 4U] ^= 1U; break;
	case 11U: registers[0x2408U / 4U] ^= 1U; break;
	case 12U: registers[0x2430U / 4U] ^= 1U; break;
	case 13U: registers[0x700U / 4U] = 0U; break;
	case 14U: registers[0x704U / 4U] = 0U; break;
	case 15U: registers[0x304U / 4U] = 0U; break;
	case 16U: registers[0x2000U / 4U] |= 1U; break;
	case 17U: registers[0x20U / 4U] |= 1U; break;
	case 18U:
	case 29U: {
		unsigned int offset = scenario == 18U ? 0x2480U : 0x27c0U;

		registers[offset / 4U] = registers[0x2440U / 4U];
		registers[(offset + 4U) / 4U] = registers[0x2444U / 4U];
		break;
	}
	case 19U: registers[0x100U / 4U] = registers[0x104U / 4U] = 0U; break;
	case 20U: registers[0x110U / 4U] = 0U; break;
	case 21U: registers[0x114U / 4U] = 1U; break;
	case 22U: timer_frequency = 0UL; break;
	case 23U: timer_frequency = 1000000001UL; break;
	case 24U: registers[0x14U / 4U] = (40U << 8U) | 47U; break;
	case 25U: registers[0U] ^= 1U << 24U; break;
	case 26U: registers[0x100U / 4U] ^= 1U; break;
	case 27U: timer_frequency++; break;
	case 28U: registers[0x2468U / 4U] = 1U; break;
	default: assert(false);
	}
}

void write32(uint32_t value, volatile void *address)
{
	unsigned long offset = reg_offset(address);

	registers[offset / 4UL] = value;
	writes++;
	if (offset == 0x80000UL) {
		assert(value == 1U && allow_firmware);
		firmware_doorbells++;
		if (domain_active) { model_domain_ack(); return; }
		for (unsigned int g = 0U; g < model_group_count; g++) {
			assert(!((model_groups[g].input[0] & 7U) == 0U &&
				(model_groups[g].output[0] & 7U) == 2U)); /* No post-suspend TERMINATE. */
			if ((model_groups[g].input[0] & 7U) == 2U &&
			    ((model_glb_in[2] ^ model_glb_out[2]) & (1U << g)) != 0U) {
				/* Native SUSPEND saves context and leaves stale CS snapshots.
				 * No queue publication or completion counter is fabricated.
				 */
				if (persistent_case == 3U || (track_complete && complete_case == 88U) ||
				    (batch_mode && batch_case == 7U)) return;
				if (persistent_case != 0U) {
					assert(g == 0U && model_queue_state == UINT64_C(0xc5f123456789abcd));
					*model_saved_state() = model_queue_state;
					suspend_count++;
				}
				if (finish_case == 3U && complete_case == 66U) {
					model_groups[g].cs_output[launch_queue][23] = 0U;
					model_groups[g].cs_output[launch_queue][24] = 0U;
				}
				if (suspend_observe_active) {
					uint64_t *in = (void *)(uintptr_t)batch_io[1][0];
					uint64_t *out = (void *)(uintptr_t)batch_io[1][1];
					uint32_t *sync = (void *)(uintptr_t)(batch_sync + 16U);
					for (unsigned int q = 0U; q < 2U; q++) {
						model_groups[g].cs_output[q][23] = 0U;
						model_groups[g].cs_output[q][24] = 0U;
					}
					if (suspend_observe_case == 4U) model_groups[g].cs_output[1][23] = 1U;
					if (suspend_observe_case == 5U) model_groups[g].cs_output[1][24] = 3U;
					if (suspend_observe_case == 6U) sync[0]--;
					if (suspend_observe_case == 7U) sync[0]++;
					if (suspend_observe_case == 8U) sync[2] = 7U;
					if (suspend_observe_case == 9U) in[0] += 128U;
					if (suspend_observe_case == 10U) out[0] -= 128U;
					if (suspend_observe_case == 11U)
						registers[(0x2400U + model_groups[g].input[20] * 0x40U) / 4U] ^= 0x1000U;
					if (suspend_observe_case == 12U) model_groups[g].cs_output[2][32] = 7U;
					if (suspend_observe_case == 13U) model_glb_out[4] = 1U;
					if (suspend_observe_case == 18U) model_groups[g].cs_output[1][0] ^= 1U << 26U;
					if (suspend_observe_case == 14U) { model_groups[g].output[0] = model_groups[g].input[0]; return; }
					if (suspend_observe_case == 15U) { model_glb_out[2] = model_glb_in[2]; return; }
					if (suspend_observe_case == 16U) model_groups[g].output[2] ^= 1U;
				}
				model_groups[g].output[0] = model_groups[g].input[0];
				if (persistent_case == 10U) model_groups[g].cs_output[0][32] = 7U;
				if (persistent_case == 11U) model_groups[g].output[2] ^= 1U;
				if (persistent_case != 4U) model_glb_out[2] = model_glb_in[2];
				if (persistent_case == 5U || (batch_mode && batch_case == 8U))
					registers[(0x2400U + model_groups[g].input[20] * 0x40U) / 4U] ^= 0x1000U;
				return;
			}
		}
		if (track_heap) {
			assert(heap_cleans == 3U);
			if (heap_case == 15U)
				return;
			model_glb_out[2] = model_glb_in[2];
			model_groups[0].output[2] = model_groups[0].input[2];
			if (heap_case == 16U) registers[0x2440U / 4U] ^= 0x1000U;
			if (heap_case == 17U) model_groups[0].cs_output[1][32] = 7U;
			return;
		}
		if (batch_mode) {
			model_batch_ack();
			return;
		}
		if (track_complete) {
			model_status_ack();
			return;
		}
		if (track_stop) {
			model_stop_ack();
			return;
		}
		if (track_launch) {
			model_task_ack();
			return;
		}
		if (update_firmware_shared && firmware_acks) {
			unsigned long root = registers[0x2400U / 4U] |
				((unsigned long)registers[0x2404U / 4U] << 32U);
			uint32_t *shared = (void *)(uintptr_t)(
				*firmware_leaf(root, 0x04000000UL) & UINT64_C(0x000000fffffff000));
			uint32_t *input = (void *)(uintptr_t)(
				(*firmware_leaf(root, shared[2]) & UINT64_C(0x000000fffffff000)) + (shared[2] & 4095U));
			uint32_t *output = (void *)(uintptr_t)(
				(*firmware_leaf(root, shared[3]) & UINT64_C(0x000000fffffff000)) + (shared[3] & 4095U));

			assert(input[0] == 14U && input[1] == 0U && input[2] == 0U);
			assert(input[4] == 2560000U && input[5] == 10U);
			assert(input[6] == 15U && input[7] == 1U && input[33] == 1U);
			assert(input[9] == 0U && input[10] == 0U && input[11] == 0U);
			output[0] = input[0];
		}
	}
	if (offset == 0x700UL) {
		assert(value == 0U || (allow_firmware && value == 2U));
		if (value == 2U) {
			firmware_starts++;
			assert(registers[0x1000U / 4U] == 0U); /* Old boot indication cleared first. */
			assert(registers[0x1008U / 4U] == 0U);
			assert(registers[0x304U / 4U] == 31U);
			if (firmware_succeeds) {
				registers[0x704U / 4U] = 1U;
				registers[0x1000U / 4U] |= 1U << 31U;
				if (update_firmware_shared) {
					unsigned long root = registers[0x2400U / 4U] |
						((unsigned long)registers[0x2404U / 4U] << 32U);
					uint32_t *shared = (void *)(uintptr_t)(
						*firmware_leaf(root, 0x04000000UL) & UINT64_C(0x000000fffffff000));

					assert(shared[0] == 0U);
					shared[0] = 0x01010000U;
					/* Test-only MCU capacity, parsed by the unmodified core. */
					if (model_limited_groups)
						shared[4] = 3U;
					model_glb_in = (void *)((unsigned char *)shared + shared[2] - 0x04000000U);
					model_glb_out = (void *)((unsigned char *)shared + shared[3] - 0x04000000U);
					model_group_count = shared[4];
					assert(model_group_count <= GPU_FIRMWARE_GROUPS);
					for (unsigned int g = 0U; g < shared[4]; g++) {
						uint32_t *group = (void *)((unsigned char *)shared + 4096U + g * shared[5]);

						group[3] = 0x40000U; /* Synthetic MCU properties. */
						group[4] = 0x20000U;
						model_groups[g].input = (void *)((unsigned char *)shared + group[1] - 0x04000000U);
						model_groups[g].output = (void *)((unsigned char *)shared + group[2] - 0x04000000U);
						model_stream_count = group[5];
						assert(model_stream_count <= GPU_FIRMWARE_STREAMS);
						for (unsigned int s = 0U; s < group[5]; s++) {
							uint32_t *stream = (void *)((unsigned char *)group + 64U + s * group[6]);

							stream[0] = 0x7015fU;
							model_groups[g].cs_input[s] = (void *)((unsigned char *)shared + stream[1] - 0x04000000U);
							model_groups[g].cs_output[s] = (void *)((unsigned char *)shared + stream[2] - 0x04000000U);
						}
					}
				}
			}
		}
	}
	if (offset == 0x1a0UL && l2_succeeds)
		registers[0x160U / 4U] |= value;
	if (offset >= 0x2400UL && (offset - 0x2400UL) % 0x40UL == 0x18UL) {
		assert(as_count < sizeof(as_commands) / sizeof(as_commands[0]));
		as_commands[as_count++] = value;
		/* Real G610 leaves AS REQ_COMPLETE pending after UPDATE. This is
		 * independent of faults in the lower half of MMU_INT_RAWSTAT.
		 */
		if (value == 1U)
			registers[0x2000U / 4U] |= 1U << (16U + (offset - 0x2400UL) / 0x40UL);
		if (value == fail_as_command)
			registers[(offset + 0x10UL) / 4UL] = 1U;
		if (offset == 0x2458UL && value == 5U && live_flush_corruption != 0U)
			corrupt_live_flush(live_flush_corruption);
		if (offset == 0x2458UL && value == 4U) {
			if (extend_corruption == 1U) registers[0x2000U / 4U] = 1U;
			if (extend_corruption == 2U) {
				registers[0x2480U / 4U] = registers[0x2440U / 4U];
				registers[0x2484U / 4U] = registers[0x2444U / 4U];
			}
			if (extend_corruption == 3U) registers[0x2440U / 4U] ^= 0x1000U;
			if (extend_corruption == 4U) registers[0x2448U / 4U] ^= 1U;
			if (extend_corruption == 5U) registers[0x704U / 4U] = 0U;
			if (extend_corruption == 6U) registers[0x2400U / 4U] ^= 0x1000U;
			if (extend_corruption == 7U) registers[0x18U / 4U] &= ~2U;
		}
	}
	if (offset == 0x24UL || offset == 0x1004UL || offset == 0x2004UL)
		registers[(offset - 4UL) / 4UL] &= ~value;
	if (offset == 0x30UL) {
		assert(value == 0x101U || value == 0x201U);
		if (value == 0x101U)
			soft_commands++;
		else
			hard_commands++;
		if ((value == 0x101U && soft_succeeds) ||
		    (value == 0x201U && hard_succeeds)) {
			registers[0x20U / 4U] |= 1U << 8U;
			memset(&registers[0x2400U / 4U], 0, 0x400U);
			registers[0x704U / 4U] = 0U;
		}
	}
}

static void initialize(void)
{
	memset(registers, 0, sizeof(registers));
	registers[0x14U / 4U] = (40U << 8U) | 48U;
	registers[0x18U / 4U] = 0xffffU;
	registers[0x0U / 4U] = 0xa8670000U;
	registers[0x120U / 4U] = 1U;
	registers[0x100U / 4U] = 15U;
	registers[0x104U / 4U] = 1U;
	registers[0x110U / 4U] = 1U;
	registers[0x28U / 4U] = 0x77U;
	registers[0x1008U / 4U] = 0x55U;
	registers[0x2008U / 4U] = 0x33U;
	soft_commands = 0U;
	hard_commands = 0U;
	soft_succeeds = true;
	hard_succeeds = true;
	writes = 0U;
	as_count = 0U;
	fail_as_command = 0U;
	extend_corruption = 0U;
	live_flush_corruption = 0U;
	allow_firmware = false;
	firmware_succeeds = l2_succeeds = true;
	firmware_starts = 0U;
	update_firmware_shared = false;
	firmware_doorbells = 0U;
	firmware_acks = true;
	timer_frequency = 1000000UL;
	control_writes = fail_control_write = 0U;
	mmio_reads = firmware_checks = shader_checks = detach_read_corruption = 0U;
}

static void detach_replay_mmio(unsigned long root, unsigned long firmware_root)
{
	uint32_t snapshot[sizeof(registers) / sizeof(registers[0])];
	unsigned int before = writes;

	memcpy(snapshot, registers, sizeof(snapshot));
	for (unsigned int scenario = 0U; scenario < 23U; scenario++) {
		memcpy(registers, snapshot, sizeof(snapshot));
		timer_frequency = 1000000UL;
		detach_read_corruption = 0U;
		switch (scenario) {
		case 0U: break;
		case 1U: timer_frequency = 0UL; break;
		case 2U: timer_frequency = 1000000001UL; break;
		case 3U: registers[0x100U / 4U] = registers[0x104U / 4U] = 0U; break;
		case 4U: registers[0x110U / 4U] = 0U; break;
		case 5U: registers[0x114U / 4U] = 1U; break;
		case 6U: registers[0U] ^= 1U << 24U; break;
		case 7U: registers[0x2000U / 4U] = 1U; break;
		case 8U: registers[0x2400U / 4U] ^= 0x1000U; break;
		case 9U: registers[0x704U / 4U] = 0U; break;
		case 10U: registers[0x18U / 4U] &= ~2U; break;
		case 11U:
			registers[0x2480U / 4U] = (uint32_t)root;
			registers[0x2484U / 4U] = (uint32_t)(root >> 32U);
			break;
		case 12U: registers[0x2440U / 4U] = 0x1000U; break;
		case 13U: registers[0x2448U / 4U] = 1U; break;
		case 14U: registers[0x2470U / 4U] = 0U; break;
		case 15U: registers[0x2468U / 4U] = 1U; break;
		case 16U: registers[0x2474U / 4U] = 1U; break;
		case 17U: timer_frequency = 0UL; detach_read_corruption = 1U; break;
		default: detach_read_corruption = scenario - 16U; break;
		}
		firmware_checks = shader_checks = mmio_reads = 0U;
		bool ok = plat_opencca_gpu_pt_detach(root, 1U, firmware_root, true);

		assert(ok == (scenario == 0U) && writes == before);
		if (ok)
			assert(firmware_checks == 2U && shader_checks == 2U);
		printf("GPU_DETACH_REPLAY_MMIO=PASS scenario=%u firmware_checks=%u shaders=%u reads=%u check-only; MODEL_ONLY\n",
			scenario, firmware_checks, shader_checks, mmio_reads);
	}
	memcpy(registers, snapshot, sizeof(snapshot));
	timer_frequency = 1000000UL;
	detach_read_corruption = 0U;
}

static void extend_mmio(unsigned long root, unsigned long firmware_root)
{
	uint32_t snapshot[sizeof(registers) / sizeof(registers[0])];
	unsigned int before = writes, commands_before = as_count, bells = firmware_doorbells;

	memcpy(snapshot, registers, sizeof(registers));
	assert(plat_opencca_gpu_pt_extend(root, 1U, firmware_root));
	assert(writes == before + 4U && as_count == commands_before + 2U);
	assert(as_commands[commands_before] == 2U && as_commands[commands_before + 1U] == 4U);
	for (unsigned int i = 0U; i < sizeof(registers) / sizeof(registers[0]); i++) {
		if (i == 0x2450U / 4U || i == 0x2454U / 4U || i == 0x2458U / 4U)
			continue;
		assert(registers[i] == snapshot[i]);
	}
	assert(registers[0x2450U / 4U] == 47U && registers[0x2454U / 4U] == 0U);
	/* Invalid inputs and pre-existing hardware changes must be read-only. */
	for (unsigned int scenario = 0U; scenario < 11U; scenario++) {
		unsigned long selected_root = root, selected_fw = firmware_root;
		unsigned int slot = 1U;

		memcpy(registers, snapshot, sizeof(registers));
		if (scenario == 0U) slot = 0U;
		if (scenario == 1U) slot = 16U;
		if (scenario == 2U) selected_root++;
		if (scenario == 3U) selected_root += 4096UL;
		if (scenario == 4U) selected_fw += 4096UL;
		if (scenario == 5U) registers[0x2448U / 4U] ^= 1U;
		if (scenario == 6U) registers[0x2470U / 4U] ^= 1U;
		if (scenario == 7U) registers[0x2000U / 4U] = 1U;
		if (scenario == 8U) registers[0x18U / 4U] &= ~2U;
		if (scenario == 9U) {
			registers[0x2480U / 4U] = (uint32_t)root;
			registers[0x2484U / 4U] = (uint32_t)(root >> 32U);
		}
		if (scenario == 10U) registers[0x704U / 4U] = 0U;
		before = writes;
		commands_before = as_count;
		assert(!plat_opencca_gpu_pt_extend(selected_root, slot, selected_fw));
		assert(writes == before && as_count == commands_before);
	}
	for (unsigned int command = 2U; command <= 4U; command += 2U) {
		memcpy(registers, snapshot, sizeof(registers));
		fail_as_command = command;
		assert(!plat_opencca_gpu_pt_extend(root, 1U, firmware_root));
	}
	fail_as_command = 0U;
	for (extend_corruption = 1U; extend_corruption <= 7U; extend_corruption++) {
		memcpy(registers, snapshot, sizeof(registers));
		assert(!plat_opencca_gpu_pt_extend(root, 1U, firmware_root));
	}
	extend_corruption = 0U;
	memcpy(registers, snapshot, sizeof(registers));
	assert(firmware_doorbells == bells);
	puts("GPU_TASK_EXTEND_MMIO=PASS actual platform LOCK/FLUSH_PT only, unchanged roots/attributes/MCU, 11 read-only rejections, LOCK/FLUSH timeouts, 7 postflush state changes rejected; MODEL_ONLY");
}

static void live_flush_mmio(unsigned long root, unsigned long firmware_root)
{
	uint32_t snapshot[sizeof(registers) / sizeof(registers[0])];
	unsigned int before, commands_before = as_count, bells = firmware_doorbells;

	memcpy(snapshot, registers, sizeof(snapshot));
	/* A live GPU is explicitly permitted; this primitive cannot claim STOP. */
	registers[0x34U / 4U] |= 1U;
	snapshot[0x34U / 4U] |= 1U;
	for (unsigned int repeat = 0U; repeat < 2U; repeat++) {
		before = writes;
		as_count = commands_before;
		assert(plat_opencca_gpu_pt_flush_live(root, 1U, firmware_root));
		assert(writes == before + 4U && as_count == commands_before + 2U);
		assert(as_commands[commands_before] == 2U && as_commands[commands_before + 1U] == 5U);
		for (unsigned int i = 0U; i < sizeof(registers) / sizeof(registers[0]); i++) {
			if (i == 0x2450U / 4U || i == 0x2454U / 4U || i == 0x2458U / 4U)
				continue;
			assert(registers[i] == snapshot[i]);
		}
		assert(registers[0x2450U / 4U] == 47U && registers[0x2454U / 4U] == 0U);
	}
	puts("GPU_LIVE_FLUSH_MMIO=PASS live GPU and exact retry, LOCK/FLUSH_MEM only, unchanged roots/attributes/MCU/queues, no UPDATE/doorbell; MODEL_ONLY");
	for (unsigned int scenario = 0U; scenario < 8U; scenario++) {
		unsigned long selected_root = root, selected_fw = firmware_root;
		unsigned int slot = 1U;

		memcpy(registers, snapshot, sizeof(snapshot));
		if (scenario == 0U) slot = 0U;
		if (scenario == 1U) slot = 16U;
		if (scenario == 2U) selected_root = 0UL;
		if (scenario == 3U) selected_root++;
		if (scenario == 4U) selected_root = firmware_root;
		if (scenario == 5U) selected_root = 1UL << 40U;
		if (scenario == 6U) selected_fw++;
		if (scenario == 7U) selected_fw = 0UL;
		before = writes;
		as_count = commands_before;
		assert(!plat_opencca_gpu_pt_flush_live(selected_root, slot, selected_fw));
		assert(writes == before && as_count == commands_before);
		printf("GPU_LIVE_FLUSH_ARGUMENT=PASS scenario=%u read-only rejection; MODEL_ONLY\n", scenario);
	}
	for (unsigned int scenario = 1U; scenario <= 29U; scenario++) {
		/* 26/27 are valid configurations, but changes across a flush are not. */
		if (scenario == 26U || scenario == 27U) continue;
		memcpy(registers, snapshot, sizeof(snapshot));
		timer_frequency = 1000000UL;
		corrupt_live_flush(scenario);
		before = writes;
		as_count = commands_before;
		assert(!plat_opencca_gpu_pt_flush_live(root, 1U, firmware_root));
		assert(writes == before && as_count == commands_before);
		printf("GPU_LIVE_FLUSH_PRECHECK=PASS scenario=%u read-only rejection; MODEL_ONLY\n", scenario);
	}
	for (unsigned int failure = 0U; failure < 2U; failure++) {
		memcpy(registers, snapshot, sizeof(snapshot));
		timer_frequency = 1000000UL;
		fail_as_command = failure == 0U ? 2U : 5U;
		before = writes;
		as_count = commands_before;
		assert(!plat_opencca_gpu_pt_flush_live(root, 1U, firmware_root));
		assert(writes == before + 3U + failure && as_count == commands_before + 1U + failure);
		assert(registers[0x2440U / 4U] == snapshot[0x2440U / 4U]);
		assert(registers[0x2444U / 4U] == snapshot[0x2444U / 4U]);
		printf("GPU_LIVE_FLUSH_TIMEOUT=PASS command=%u no root repair/disable; MODEL_ONLY\n", fail_as_command);
	}
	fail_as_command = 0U;
	for (live_flush_corruption = 1U; live_flush_corruption <= 29U; live_flush_corruption++) {
		memcpy(registers, snapshot, sizeof(snapshot));
		timer_frequency = 1000000UL;
		before = writes;
		as_count = commands_before;
		assert(!plat_opencca_gpu_pt_flush_live(root, 1U, firmware_root));
		assert(writes == before + 4U && as_count == commands_before + 2U);
		/* The real detach consumer must not disable a possibly changed AS. */
		memcpy(registers, snapshot, sizeof(snapshot));
		timer_frequency = 1000000UL;
		before = writes;
		as_count = commands_before;
		assert(!plat_opencca_gpu_pt_detach(root, 1U, firmware_root, false));
		assert(writes == before + 4U && as_count == commands_before + 2U);
		printf("GPU_LIVE_FLUSH_POSTCHECK=PASS scenario=%u flush and detach retain translation, no rollback/disable; MODEL_ONLY\n", live_flush_corruption);
	}
	live_flush_corruption = 0U;
	memcpy(registers, snapshot, sizeof(snapshot));
	registers[0x34U / 4U] &= ~1U;
	timer_frequency = 1000000UL;
	as_count = commands_before;
	assert(firmware_doorbells == bells);
}

static void prepare_mmio(unsigned long firmware_root)
{
	const unsigned long root = 0x100008000UL;
	unsigned int before = writes;
	struct gpu_firmware_config config;

	assert(!plat_opencca_gpu_pt_prepare(root, 0U, firmware_root, false));
	assert(!plat_opencca_gpu_pt_prepare(root, 16U, firmware_root, false));
	assert(!plat_opencca_gpu_pt_prepare(firmware_root, 1U, firmware_root, false));
	assert(!plat_opencca_gpu_pt_prepare(root + 1UL, 1U, firmware_root, false));
	assert(!plat_opencca_gpu_pt_prepare(root, 1U, firmware_root, true));
	registers[0x18U / 4U] &= ~2U;
	assert(!plat_opencca_gpu_pt_prepare(root, 1U, firmware_root, false));
	registers[0x18U / 4U] |= 2U;
	registers[0x2440U / 4U] = (uint32_t)root;
	registers[0x2444U / 4U] = (uint32_t)(root >> 32U);
	assert(!plat_opencca_gpu_pt_prepare(root, 1U, firmware_root, false));
	registers[0x2440U / 4U] = registers[0x2444U / 4U] = 0U;
	registers[0x2000U / 4U] = 1U;
	assert(!plat_opencca_gpu_pt_prepare(root, 1U, firmware_root, false));
	registers[0x2000U / 4U] = 0U;
	assert(writes == before);
	assert(plat_opencca_gpu_pt_prepare(root, 1U, firmware_root, false));
	before = writes;
	assert(plat_opencca_gpu_pt_prepare(root, 1U, firmware_root, true));
	assert(!plat_opencca_gpu_pt_prepare(root, 1U, firmware_root, false));
	registers[0x2440U / 4U] = registers[0x2444U / 4U] = 0U;
	assert(!plat_opencca_gpu_pt_prepare(root, 1U, firmware_root, true));
	registers[0x2440U / 4U] = (uint32_t)root;
	registers[0x2444U / 4U] = (uint32_t)(root >> 32U);
	registers[0x2448U / 4U] ^= 1U;
	assert(!plat_opencca_gpu_pt_prepare(root, 1U, firmware_root, true));
	registers[0x2448U / 4U] ^= 1U;
	assert(writes == before && firmware_doorbells == 1U);
	registers[0x110U / 4U] = 0U;
	assert(!plat_opencca_gpu_firmware_configuration(firmware_root, &config));
	registers[0x110U / 4U] = 1U;
	registers[0x114U / 4U] = 1U;
	assert(!plat_opencca_gpu_firmware_configuration(firmware_root, &config));
	registers[0x114U / 4U] = 0U;
	assert(plat_opencca_gpu_firmware_configuration(firmware_root, &config));
	puts("GPU_TASK_PREPARE_MMIO=PASS live MCU nonzero AS, first-use empty root, replay exact root/attributes without writes, missing-root replay rejected, absent AS/fault/topology rejection, no task doorbell; MODEL_ONLY");
	extend_mmio(root, firmware_root);
	live_flush_mmio(root, firmware_root);
	before = writes;
	assert(!plat_opencca_gpu_pt_detach(root, 0U, firmware_root, false));
	assert(!plat_opencca_gpu_pt_detach(root, 16U, firmware_root, false));
	assert(!plat_opencca_gpu_pt_detach(firmware_root, 1U, firmware_root, false));
	assert(!plat_opencca_gpu_pt_detach(root + 1UL, 1U, firmware_root, false));
	assert(!plat_opencca_gpu_pt_detach(root + 4096UL, 1U, firmware_root, false));
	assert(!plat_opencca_gpu_pt_detach(root, 1U, firmware_root, true));
	registers[0x2480U / 4U] = (uint32_t)root;
	registers[0x2484U / 4U] = (uint32_t)(root >> 32U);
	assert(!plat_opencca_gpu_pt_detach(root, 1U, firmware_root, false));
	registers[0x2480U / 4U] = registers[0x2484U / 4U] = 0U;
	assert(writes == before);
	unsigned int commands_before = as_count;

	assert(plat_opencca_gpu_pt_detach(root, 1U, firmware_root, false));
	assert(as_count == commands_before + 3U && as_commands[commands_before] == 2U &&
		as_commands[commands_before + 1U] == 5U && as_commands[commands_before + 2U] == 1U);
	assert(registers[0x2440U / 4U] == 0U && registers[0x2444U / 4U] == 0U &&
		registers[0x2448U / 4U] == 0U && registers[0x244cU / 4U] == 0U &&
		registers[0x2470U / 4U] == 1U && registers[0x2474U / 4U] == 0U);
	before = writes;
	assert(plat_opencca_gpu_pt_detach(root, 1U, firmware_root, true));
	assert(!plat_opencca_gpu_pt_detach(root, 1U, firmware_root, false));
	registers[0x2470U / 4U] = 0U;
	assert(!plat_opencca_gpu_pt_detach(root, 1U, firmware_root, true));
	registers[0x2470U / 4U] = 1U;
	assert(writes == before && firmware_doorbells == 1U);
	puts("GPU_TASK_DETACH_MMIO=PASS exact nonzero AS/root/attributes, alias rejection, LOCK/FLUSH_MEM/UNMAPPED_1/UPDATE, 64-bit root zero, disabled replay check-only, no firmware halt/reset or doorbell; MODEL_ONLY");
	detach_replay_mmio(root, firmware_root);
}

static void firmware_mmio(void)
{
	const unsigned long root = 0x100002000UL;
	struct gpu_firmware_config config;
	unsigned int before;

	initialize();
	registers[0x0U / 4U] = 0xa9000000U;
	assert(!plat_opencca_gpu_firmware_install(root) && writes == 0U);
	registers[0x0U / 4U] = 0xa8670000U;
	registers[0x120U / 4U] = 0U;
	assert(!plat_opencca_gpu_firmware_install(root) && writes == 0U);
	registers[0x120U / 4U] = 1U;
	registers[0x2400U / 4U] = 0xdead000U;
	assert(!plat_opencca_gpu_firmware_install(root) && writes == 0U);
	initialize();
	l2_succeeds = false;
	assert(!plat_opencca_gpu_firmware_install(root));
	assert(registers[0x2400U / 4U] == 0U && firmware_starts == 0U);
	initialize();
	assert(plat_opencca_gpu_firmware_install(root));
	assert(registers[0x2400U / 4U] == 0x2000U && registers[0x2404U / 4U] == 1U);
	assert(registers[0x160U / 4U] == 1U && firmware_starts == 0U);
	assert(!plat_opencca_gpu_firmware_boot(root + 4096UL));
	registers[0x2430U / 4U] = 0U; /* Wrong AS0 attributes. */
	assert(!plat_opencca_gpu_firmware_boot(root));
	registers[0x2430U / 4U] = 0x420001c6U;
	registers[0x2440U / 4U] = 0x2000U;
	registers[0x2444U / 4U] = 1U;
	assert(!plat_opencca_gpu_firmware_boot(root)); /* Root aliased in Client AS. */
	registers[0x2440U / 4U] = registers[0x2444U / 4U] = 0U;
	registers[0x1000U / 4U] = 1U << 31U; /* Stale boot bit must be cleared. */
	allow_firmware = true;
	assert(plat_opencca_gpu_firmware_boot(root));
	assert(firmware_starts == 1U && registers[0x700U / 4U] == 2U);
	assert(plat_opencca_gpu_firmware_configuration(root, &config));
	assert(config.shader_mask == UINT64_C(0x10000000f));
	assert(config.poweroff_timer == 10U && config.idle_timer == 1U && config.ack_timeout_ticks == 100000UL);
	before = writes;
	assert(!plat_opencca_gpu_firmware_notify(root + 4096UL) && writes == before);
	timer_frequency = 0UL;
	assert(!plat_opencca_gpu_firmware_configuration(root, &config));
	timer_frequency = 1000000001UL;
	assert(!plat_opencca_gpu_firmware_configuration(root, &config));
	timer_frequency = 1000000UL;
	registers[0x2000U / 4U] = 1U;
	assert(!plat_opencca_gpu_firmware_notify(root) && writes == before);
	registers[0x2000U / 4U] = 0U;
	assert(plat_opencca_gpu_firmware_notify(root));
	assert(firmware_doorbells == 1U && writes == before + 1U);
	assert(!plat_opencca_gpu_firmware_boot(root)); /* Already running. */
	prepare_mmio(root);
	initialize();
	assert(plat_opencca_gpu_firmware_install(root));
	allow_firmware = true;
	firmware_succeeds = false;
	registers[0x1000U / 4U] = 1U << 31U;
	assert(!plat_opencca_gpu_firmware_boot(root)); /* Bounded real indication wait. */
	assert(firmware_starts == 1U && registers[0x1000U / 4U] == 0U);
	puts("GPU_FIRMWARE_MMIO=PASS fixed arch10.8/AS0, L2 power, protected root/attributes, stale boot rejection, real raw completion and MCU state, trusted shaders/timers/global doorbell, fault rejection, no Client task doorbell");
}

static void private_pt(void)
{
	const unsigned long root = 0x100002000UL;
	unsigned int before;

	initialize();
	assert(!plat_opencca_gpu_pt_install(root, 0U));
	assert(!plat_opencca_gpu_pt_install(root, 16U));
	assert(!plat_opencca_gpu_pt_install(0UL, 1U));
	assert(!plat_opencca_gpu_pt_install(root + 1UL, 1U));
	assert(!plat_opencca_gpu_pt_install(1UL << 40U, 1U));
	registers[0x14U / 4U] = (40U << 8U) | 47U;
	assert(!plat_opencca_gpu_pt_install(root, 1U));
	registers[0x14U / 4U] = (39U << 8U) | 48U;
	assert(!plat_opencca_gpu_pt_install(root, 1U));
	registers[0x14U / 4U] = (40U << 8U) | 48U;
	registers[0x18U / 4U] = 1U;
	assert(!plat_opencca_gpu_pt_install(root, 1U));
	registers[0x18U / 4U] = 0xffffU;
	registers[0x700U / 4U] = 1U;
	assert(!plat_opencca_gpu_pt_install(root, 1U));
	registers[0x700U / 4U] = 0U;
	registers[0x704U / 4U] = 1U;
	assert(!plat_opencca_gpu_pt_install(root, 1U));
	registers[0x704U / 4U] = 0U;
	registers[0x34U / 4U] = 1U;
	assert(!plat_opencca_gpu_pt_install(root, 1U));
	registers[0x34U / 4U] = 0U;
	/* An unexplained hardware root cannot be replaced using this API. */
	registers[0x2440U / 4U] = 0xdead000U;
	assert(!plat_opencca_gpu_pt_install(root, 1U));
	assert(writes == 0U);
	registers[0x2440U / 4U] = 0U;
	assert(plat_opencca_gpu_pt_install(root, 1U));
	assert(registers[0x2440U / 4U] == 0x2000U);
	assert(registers[0x2444U / 4U] == 1U); /* Preserve the high root bits. */
	assert(registers[0x2448U / 4U] == 0xc0c09f4cU);
	assert(registers[0x244cU / 4U] == 0xc0c0c0c0U);
	assert(registers[0x2470U / 4U] == 0x420001c6U);
	assert(registers[0x2474U / 4U] == 0U);
	assert(registers[0x2450U / 4U] == 47U);
	assert(registers[0x2454U / 4U] == 0U);
	assert(as_count == 3U && as_commands[0] == 2U &&
		as_commands[1] == 5U && as_commands[2] == 1U);
	assert(registers[0x700U / 4U] == 0U);
	assert(registers[0x30U / 4U] == 0U); /* No GPU start/reset command. */
	assert(plat_opencca_gpu_pt_sync(root));
	assert(as_count == 5U && as_commands[3] == 2U && as_commands[4] == 4U);
	before = writes;
	assert(!plat_opencca_gpu_pt_sync(root + 4096UL));
	registers[0x2480U / 4U] = 0x2000U;
	registers[0x2484U / 4U] = 1U;
	assert(!plat_opencca_gpu_pt_sync(root)); /* Duplicate root in another AS. */
	assert(writes == before);
	registers[0x2480U / 4U] = 0U;
	registers[0x2484U / 4U] = 0U;
	registers[0x700U / 4U] = 1U;
	assert(!plat_opencca_gpu_pt_sync(root));
	assert(writes == before);
	initialize();
	registers[0x2468U / 4U] = 1U;
	assert(!plat_opencca_gpu_pt_install(root, 1U)); /* Bounded busy timeout. */
	assert(registers[0x2440U / 4U] == 0U && as_count == 0U);
	initialize();
	fail_as_command = 5U;
	assert(!plat_opencca_gpu_pt_install(root, 1U));
	assert(registers[0x2440U / 4U] == 0U && as_count == 2U);
	initialize();
	fail_as_command = 1U;
	assert(!plat_opencca_gpu_pt_install(root, 1U));
	assert(registers[0x2440U / 4U] == 0x2000U && as_count == 3U);
	/* Partial programming returns failure; core tests require quarantine and
	 * retained backing, not a guessed rollback or success from MMIO writes.
	 */
	initialize();
	assert(plat_opencca_gpu_pt_install(root, 15U));
	assert(registers[0x27c0U / 4U] == 0x2000U);
	assert(plat_opencca_gpu_pt_sync(root));
	puts("GPU_PRIVATE_MMIO=PASS nonzero AS, stopped MCU/GPU, address/features, fixed attributes, real install/flush register sequence, bounded failures, no firmware/doorbell start");
}

static unsigned char client_a, client_b, service, stranger;
static const unsigned char *table_base;
static unsigned long latest_table_pa;
static bool alias_revoked;
#define TABLE_BASE 0x100000000UL

static bool revoke_alias(const void *owner)
{
	assert(owner == &service && !opencca_gpu_mmio_allowed(owner));
	alias_revoked = true;
	return true;
}

static const struct opencca_gpu_ops device_ops = {
	.reset = plat_opencca_gpu_reset, .revoke_mmio = revoke_alias,
	.opp_valid = plat_opencca_gpu_opp_valid
};

static bool resolve(const void *owner, unsigned long ipa, unsigned long *pa)
{
	assert(owner == &client_a || owner == &client_b);
	*pa = ipa + (owner == &client_a ? 0x40000000UL : 0x80000000UL);
	return true; /* RTT metadata translation; never read the data page. */
}

static unsigned long table_address(const void *table)
{
	if (table_base == NULL)
		table_base = table;
	assert((const unsigned char *)table >= table_base);
	return TABLE_BASE + (unsigned long)((const unsigned char *)table - table_base);
}

static void table_clean(const void *table, size_t bytes)
{
	assert(table != NULL && bytes != 0U);
	if (bytes == 4096UL)
		latest_table_pa = table_address(table);
}

static bool activate_private(unsigned long context, unsigned long root,
		unsigned int slot)
{
	assert(context != 0UL && alias_revoked);
	return opencca_gpu_service_isolated(&service) &&
		plat_opencca_gpu_pt_install(root, slot);
}

static bool sync_private(unsigned long context, unsigned long root)
{
	assert(context != 0UL);
	return opencca_gpu_service_isolated(&service) && plat_opencca_gpu_pt_sync(root);
}

static const struct gpu_private_ops private_ops = {
	.source_page = resolve, .table_pa = table_address, .clean = table_clean,
	.activate = activate_private, .synchronize = sync_private
};

static void authorized_page(const void *owner, unsigned long context,
		unsigned long bo, unsigned long offset, unsigned long va)
{
	struct gpu_private_result result;
	unsigned long grant;

	gpu_private_map_authorize(owner, context, bo, offset, va, 1U, 3UL, &result);
	assert(result.status == 0UL);
	grant = result.value[0];
	gpu_private_service_map(&private_ops, &service, owner, context, grant,
		offset, va, 1U, 3UL, &result);
	assert(result.status == 0UL);
}

static unsigned long hardware_leaf(unsigned int slot, unsigned long va)
{
	unsigned long address = registers[(0x2400U + slot * 0x40U) / 4U] |
		((unsigned long)registers[(0x2404U + slot * 0x40U) / 4U] << 32U);

	/* Walk from the root actually written to the hardware model, not a root
	 * exported through the service API or inferred from Client metadata.
	 */
	for (unsigned int level = 0U; level < 4U; level++) {
		const uint64_t *table;
		uint64_t pte;

		assert(address >= TABLE_BASE &&
			address < TABLE_BASE + GPU_PRIVATE_TABLES * 4096UL);
		table = (const uint64_t *)(table_base + address - TABLE_BASE);
		pte = table[(va >> (39U - level * 9U)) & 511UL];
		assert((pte & 3UL) == 3UL);
		address = pte & 0x0000fffffffff000UL;
	}
	return address;
}

static void private_integration(void)
{
	struct gpu_private_result result;
	unsigned long objects[2], contexts[2], uncertain;
	unsigned long pages[2] = { 0x100000UL, 0x101000UL };
	const void *owners[2] = { &client_a, &client_b };
	unsigned int before;

	initialize();
	assert(opencca_gpu_control(&device_ops, NULL, OPENCCA_GPU_POWER_ON, 0UL, 0UL));
	assert(opencca_gpu_mmio_grant(&service) && opencca_gpu_claim(&service));
	assert(opencca_gpu_service_isolate(&device_ops, &service));
	assert(alias_revoked && opencca_gpu_service_isolated(&service));
	for (unsigned int i = 0U; i < 2U; i++) {
		gpu_private_bo_create(owners[i], &service, 8192UL, 3UL, &result);
		assert(result.status == 0UL);
		objects[i] = result.value[0];
		gpu_private_bo_append(&private_ops, owners[i], objects[i], 0UL, pages, 2U, &result);
		assert(result.status == 0UL);
		gpu_private_context_create(&private_ops, owners[i], &service, &result);
		assert(result.status == 0UL);
		contexts[i] = result.value[0];
		authorized_page(owners[i], contexts[i], objects[i], 0UL, 0x1000UL);
		before = writes;
		gpu_private_context_activate(&private_ops, &stranger, contexts[i], i + 1U, &result);
		assert(result.status == GPU_PRIVATE_INPUT && writes == before);
		gpu_private_context_activate(&private_ops, &service, contexts[i], i + 1U, &result);
		assert(result.status == 0UL && result.value[0] == contexts[i]);
		assert(result.value[1] == i + 1U && result.value[2] == 0UL && result.value[3] == 0UL);
	}
	assert(hardware_leaf(1U, 0x1000UL) == 0x40100000UL);
	assert(hardware_leaf(2U, 0x1000UL) == 0x80100000UL);
	assert(registers[0x2440U / 4U] != registers[0x2480U / 4U]);
	authorized_page(&client_a, contexts[0], objects[0], 4096UL, 0x2000UL);
	assert(hardware_leaf(1U, 0x2000UL) == 0x40101000UL);
	gpu_private_context_create(&private_ops, &client_a, &service, &result);
	assert(result.status == 0UL);
	uncertain = result.value[0];
	authorized_page(&client_a, uncertain, objects[0], 0UL, 0x1000UL);
	fail_as_command = 1U;
	gpu_private_context_activate(&private_ops, &service, uncertain, 3U, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_private_query(&client_a, uncertain, 0UL, &result);
	assert(result.status == 0UL && result.value[1] == 1UL && result.value[2] == 1UL);
	gpu_private_bo_destroy(&client_a, objects[0], &result);
	assert(result.status == GPU_PRIVATE_STATE); /* Partial MMIO retains backing. */
	assert(opencca_gpu_control(&device_ops, NULL, OPENCCA_GPU_RELEASE, 0UL, 0UL));
	assert(registers[0x2440U / 4U] == 0U && registers[0x24c0U / 4U] == 0U);
	/* Same retirement entry used by the RMI release/RSI handoff adapters. */
	gpu_private_device_revoked(&private_ops);
	for (unsigned int i = 0U; i < 2U; i++) {
		gpu_private_bo_destroy(owners[i], objects[i], &result);
		assert(result.status == 0UL);
		gpu_private_context_destroy(&private_ops, owners[i], contexts[i], &result);
		assert(result.status == 0UL);
	}
	gpu_private_context_destroy(&private_ops, &client_a, uncertain, &result);
	assert(result.status == 0UL && !gpu_private_owner_busy(&service));
	puts("GPU_PRIVATE_BACKEND_INTEGRATION=PASS service handoff, exact grants, actual installed roots/PTE walks for two Clients, trusted invalidation, partial-write quarantine and reset retirement");
}

static bool fw_digest(const void *image, size_t size, unsigned char output[32])
{
	return mbedtls_sha256(image, size, output, 0) == 0;
}

static unsigned long fw_address(const void *memory)
{
	return (uintptr_t)memory;
}

static void fw_cache(const void *memory, size_t size)
{
	assert(memory != NULL && size != 0U);
	for (unsigned int g = 0U; g < model_group_count; g++)
		for (unsigned int q = 0U; q < model_stream_count; q++)
			if (memory == model_groups[g].cs_output[q])
				/* Full snapshots, or the existing diagnostic ACK read. */
				assert(size == 0xd8U || size == sizeof(uint32_t));
}

static void fw_clean(const void *memory, size_t size)
{
	fw_cache(memory, size);
	for (unsigned int g = 0U; g < model_group_count; g++) {
		if ((model_groups[g].input[0] & 7U) == 2U &&
		    (memory == model_groups[g].input || (memory == model_glb_in &&
		     ((model_glb_in[2] ^ model_glb_out[2]) & (1U << g)) != 0U)))
			return; /* Separate real SUSPEND handshake. */
		if ((model_groups[g].output[0] & 7U) == 2U)
			for (unsigned int q = 0U; q < model_stream_count; q++)
				if (memory == model_groups[g].cs_input[q] &&
				    (model_groups[g].cs_input[q][0] & 7U) == 0U)
					return; /* Reset input only: stale START output is deliberate. */
	}
	if (track_heap) {
		const void *expected[] = {model_groups[0].cs_input[1], model_groups[0].input, model_glb_in};
		const size_t sizes[] = {0x60U, 0x58U, 0x88U};

		assert(heap_cleans < 3U && memory == expected[heap_cleans] && size == sizes[heap_cleans]);
		heap_cleans++;
		return;
	}
	/* Combined dispatch includes stopped PREPARE writes before START. */
	if (dispatch_case && batch_mode && !batch_trace &&
	    memory == model_groups[0].cs_input[0] &&
	    (model_groups[0].cs_input[0][0] & 7U) == 1U)
		batch_trace = true;
	if (batch_mode && batch_trace) {
		for (unsigned int q = 0U; q < 2U; q++) {
			if (memory == model_groups[0].cs_input[q]) {
				if (q == 0U && batch_cs_cleans == 0U && batch_cleans == 2U)
					batch_cleans = 0U; /* Fresh status ACK led to STOP publication. */
				assert(q == batch_cs_cleans && batch_cleans == q && size == 0x60U);
				batch_cs_cleans++;
				batch_cleans++;
				return;
			}
		}
		if (batch_cs_cleans == 2U && batch_cleans >= 4U) {
			assert(batch_cleans < 6U && size == (batch_cleans == 4U ? 0x58U : 0x88U) &&
				memory == (batch_cleans == 4U ? (void *)model_groups[0].input : (void *)model_glb_in));
			batch_cleans++;
			return;
		}
		if (memory == model_groups[0].input) {
			assert(batch_cleans == batch_cs_cleans && size == 0x58U);
		} else {
			assert(memory == model_glb_in && batch_cleans == batch_cs_cleans + 1U && size == 0x88U);
		}
		batch_cleans++;
		return;
	}
	if (domain_active) return; /* Domain MCU double checks each actual notification below. */
	if (track_complete) {
		if (memory == model_groups[launch_csg].cs_input[launch_queue]) {
			/* Completion evidence has led to the real trusted STOP path. */
			track_complete = false;
			track_stop = true;
			launch_cleans = 0U;
		} else {
			const void *expected[] = { model_groups[launch_csg].input, model_glb_in };
			const size_t sizes[] = { 0x58U, 0x88U };

			assert(status_cleans < 2U && memory == expected[status_cleans] && size == sizes[status_cleans]);
			status_cleans++;
			return;
		}
	}
	if (!track_launch)
		return;
	if (!track_stop && launch_cleans >= 3U) {
		const void *expected[] = {model_groups[launch_csg].input, model_glb_in};
		const size_t sizes[] = {0x58U, 0x88U};

		assert(launch_cleans < 5U && memory == expected[launch_cleans - 3U] &&
			size == sizes[launch_cleans - 3U]);
		launch_cleans++;
		return;
	}
	assert(launch_cleans < 3U);
	const void *expected[] = { model_groups[launch_csg].cs_input[launch_queue],
		model_groups[launch_csg].input, model_glb_in };
	const size_t sizes[] = { 0x60U, 0x58U, 0x88U };

	assert(memory == expected[launch_cleans] && size == sizes[launch_cleans]);
	launch_cleans++;
}

static bool fw_notify(unsigned long root)
{
	if (persistent_case == 2U && (model_groups[0].input[0] & 7U) == 2U)
		return false;
	if (track_heap && heap_case == 14U)
		return false;
	if (track_complete && complete_case == 69U)
		return false;
	if ((track_launch && launch_case == 16U) || (track_stop && stop_case == 37U)) {
		assert(launch_cleans == 3U);
		return false;
	}
	return plat_opencca_gpu_firmware_notify(root);
}

static bool fw_install(unsigned long root)
{
	assert(alias_revoked && opencca_gpu_service_isolated(&service));
	return plat_opencca_gpu_firmware_install(root);
}

static bool fw_boot(unsigned long root)
{
	assert(alias_revoked && opencca_gpu_service_isolated(&service));
	return plat_opencca_gpu_firmware_boot(root);
}

static unsigned int replay_configuration_checks;
static bool replay_configuration(unsigned long root, struct gpu_firmware_config *cfg)
{
	replay_configuration_checks++;
	return plat_opencca_gpu_firmware_configuration(root, cfg);
}

static const struct gpu_firmware_ops fw_ops = {
	.digest = fw_digest, .address = fw_address,
	.clean = fw_clean, .invalidate = fw_cache, .install = fw_install, .boot = fw_boot,
	.configuration = plat_opencca_gpu_firmware_configuration,
	.notify = fw_notify, .clock = read_cntpct_el0
};

#define CONTROL_TEST_PAGES 513U
#define CONTROL_TEST_IPA 0x1000000UL
static unsigned char donated_pages[CONTROL_TEST_PAGES][4096]
	__attribute__((aligned(4096)));
static bool donated_visible[CONTROL_TEST_PAGES];

static unsigned int donated_index(unsigned long pa)
{
	unsigned long base = (uintptr_t)donated_pages;

	assert(pa >= base && pa < base + sizeof(donated_pages));
	assert((pa - base) % 4096UL == 0UL);
	return (unsigned int)((pa - base) / 4096UL);
}

static bool donated_source(const void *owner, unsigned long ipa, unsigned long *pa)
{
	unsigned long index;

	if (owner != &service || ipa < CONTROL_TEST_IPA ||
	    (ipa - CONTROL_TEST_IPA) % 4096UL != 0UL ||
	    gpu_private_range_busy(owner, ipa, 4096UL))
		return false;
	index = (ipa - CONTROL_TEST_IPA) / 4096UL;
	if (index >= CONTROL_TEST_PAGES || !donated_visible[index])
		return false;
	*pa = (uintptr_t)donated_pages[index];
	return true;
}

static bool donated_hide(const void *owner, unsigned long ipa, unsigned long pa)
{
	unsigned int index = donated_index(pa);

	assert(owner == &service && ipa == CONTROL_TEST_IPA + index * 4096UL);
	assert(donated_visible[index] && gpu_private_range_busy(owner, ipa, 4096UL));
	donated_visible[index] = false;
	return true; /* CPU permissions are a model; real RTT tested separately. */
}

static bool donated_clear(unsigned long pa)
{
	unsigned int index = donated_index(pa);

	assert(!donated_visible[index]);
	if (track_retire) {
		assert(retire_clears < retire_expected_count && pa == retire_expected_pa[retire_clears]);
		retire_clears++;
		if (retire_case == 61U && retire_clears == 2U)
			return false;
		if (retire_clears == retire_expected_count) {
			if (retire_case == 62U)
				registers[0x2000U / 4U] = 1U;
			if (retire_case == 63U)
				registers[(0x2400U + model_groups[launch_csg].input[20] * 0x40U) / 4U] = 0x1000U;
		}
	}
	memset(donated_pages[index], 0, sizeof(donated_pages[index]));
	return true;
}

static bool donated_restore(const void *owner, unsigned long ipa, unsigned long pa)
{
	unsigned int index = donated_index(pa);

	assert(owner == &service && ipa == CONTROL_TEST_IPA + index * 4096UL);
	assert(!donated_visible[index] && gpu_private_range_busy(owner, ipa, 4096UL));
	for (unsigned int i = 0U; i < 4096U; i++)
		assert(donated_pages[index][i] == 0U);
	donated_visible[index] = true;
	return true;
}

static bool donated_write(unsigned long pa, size_t offset, const void *source, size_t bytes)
{
	unsigned int index = donated_index(pa);

	assert(!donated_visible[index] && source != NULL && bytes != 0U);
	assert(offset <= 4096U && bytes <= 4096U - offset);
#ifdef GPU_DOMAIN_RSI_TEST
	if (domain_dispatch_active) assert(domain_policy_locked);
#endif
	control_writes++;
	if (control_writes == fail_control_write)
		return false;
	memcpy(donated_pages[index] + offset, source, bytes);
	if (domain_active && domain_write_fault >= 6U) {
		if (domain_write_fault <= 23U) {
			drain_corrupt_controls(domain_write_fault - 5U);
		} else {
			domain_read_fault = domain_write_fault - 23U;
			domain_reads_until_fault = 3U;
		}
		domain_write_fault = 0U;
	} else if (domain_active && domain_write_fault != 0U) {
		unsigned int as = model_groups[launch_csg].input[20];

		switch (domain_write_fault) {
		case 1U: drain_fault = &registers[(0x2400U + as * 0x40U) / 4U]; break;
		case 2U: drain_fault = &registers[0x2400U / 4U]; break;
		case 3U: drain_fault = (uint32_t *)(uintptr_t)(complete_read_pa[0] + 8UL); break;
		case 4U: drain_fault = (uint32_t *)(uintptr_t)complete_read_pa[0]; break;
		case 5U: drain_fault = &model_groups[launch_csg].cs_output[1][32]; break;
		default: assert(false);
		}
		drain_fault_saved = *drain_fault;
		*drain_fault ^= domain_write_fault <= 2U ? 0x1000U : 128U;
		domain_write_fault = 0U;
	}
	return true;
}

static bool prepare_private(unsigned long root, unsigned int slot,
		unsigned long firmware_root, bool existing)
{
	assert(alias_revoked && opencca_gpu_service_isolated(&service));
	return plat_opencca_gpu_pt_prepare(root, slot, firmware_root, existing);
}

static bool extend_private(unsigned long root, unsigned int slot, unsigned long firmware_root)
{
	assert(alias_revoked && opencca_gpu_service_isolated(&service));
	return plat_opencca_gpu_pt_extend(root, slot, firmware_root);
}

static void assert_model_nonexecuting(unsigned int csg)
{
	uint32_t req = model_groups[csg].input[0], ack = model_groups[csg].output[0];

	assert((req & 7U) == 0U || (req & 7U) == 2U);
	assert(((req ^ ack) & 0x37U) == 0U);
	for (unsigned int q = 0U; q < model_stream_count; q++) {
		assert((model_groups[csg].cs_input[q][0] & 7U) == 0U);
		assert((req & 7U) == 2U ? (model_groups[csg].cs_output[q][0] & 7U) <= 1U :
			(model_groups[csg].cs_output[q][0] & 7U) == 0U);
	}
}

static bool detach_private(unsigned long root, unsigned int slot,
		unsigned long firmware_root, bool detached)
{
	unsigned int selected = launch_csg;

	if (domain_active) {
		for (selected = 0U; selected < model_group_count; selected++)
			if (model_groups[selected].input[20] == slot) break;
		assert(selected < model_group_count);
	}
	assert(alias_revoked && opencca_gpu_service_isolated(&service) && (track_stop || batch_mode || (track_complete &&
		(model_groups[selected].output[0] & 7U) == 2U)));
	assert_model_nonexecuting(selected);
	assert(model_groups[selected].input[20] == slot);
	return plat_opencca_gpu_pt_detach(root, slot, firmware_root, detached);
}

static bool drain_barrier(void)
{
	return !drain_barrier_failure;
}

static bool flush_private(unsigned long root, unsigned int slot, unsigned long firmware_root)
{
	assert(alias_revoked && opencca_gpu_service_isolated(&service));
	drain_flushes++;
	bool ok = plat_opencca_gpu_pt_flush_live(root, slot, firmware_root);

	if (ok && drain_post_corruption != 0U)
		drain_corrupt_controls(drain_post_corruption);
	return ok;
}

static bool data_sync(unsigned long pa)
{
	unsigned long index;

	assert(pa >= sync_expected_base && (pa - sync_expected_base) % 4096UL == 0UL);
	index = (pa - sync_expected_base) / 4096UL;
	assert(index < sync_expected_pages && index < sizeof(synced_data) / sizeof(synced_data[0]));
	assert(!synced_data[index]); /* Neither an internal page nor duplicate traversal. */
	data_syncs++;
	if (data_syncs == fail_data_sync)
		return false;
	synced_data[index] = true;
	if (data_syncs == fault_after_data_sync)
		registers[0x2000U / 4U] = 1U;
	return true; /* Cache instructions themselves run only on real ARM hardware. */
}

static bool data_return(unsigned long pa)
{
	unsigned int as = model_groups[launch_csg].input[20];
	unsigned int at = (0x2400U + as * 0x40U) / 4U;
	unsigned long index;

	assert((track_stop || batch_mode || (track_complete &&
		(model_groups[launch_csg].output[0] & 7U) == 2U)) && as != 0U && as < 16U);
	assert_model_nonexecuting(launch_csg);
	assert(registers[at] == 0U && registers[at + 1U] == 0U && registers[at + 12U] == 1U);
	assert(pa >= return_expected_base && (pa - return_expected_base) % 4096UL == 0UL);
	index = (pa - return_expected_base) / 4096UL;
	assert(index < return_expected_pages && index < sizeof(returned_data) / sizeof(returned_data[0]));
	assert(!returned_data[index]); /* No control, foreign or duplicate page. */
	cpu_returns++;
	if (cpu_returns == fail_cpu_return)
		return false;
	returned_data[index] = true;
	if (index + 1UL == return_expected_pages) {
		if (return_case == 51U)
			registers[0x2000U / 4U] = 1U;
		if (return_case == 52U)
			registers[at] = 0x1000U;
		/* Inject before the post-cache state check even when all data fits
		 * in one RSI call after sparse-table skipping. */
		if (return_case == 53U)
			model_groups[launch_csg].cs_output[launch_queue][0] |= 1U;
		if (return_case == 54U)
			model_groups[launch_csg].cs_output[launch_queue][32] = 1U;
	}
	return true; /* Actual ARM invalidation is in the RSI adapter, not this model. */
}

static void complete_boundary_inject(unsigned int as)
{
	uint32_t *fault = NULL, *high = NULL, value = 1U;

	switch (complete_boundary_case) {
	case 1U: fault = &registers[0x2000U / 4U]; break;
	case 2U: fault = &registers[(0x2400U + as * 0x40U) / 4U]; value = 0x1000U; break;
	case 3U: fault = &registers[0x2400U / 4U]; value = 0x1000U; break;
	case 4U: fault = &registers[0x100U / 4U]; high = &registers[0x104U / 4U]; value = *fault; break;
	case 5U: fault = &model_glb_out[4]; break;
	case 6U: fault = &model_groups[launch_csg].cs_output[0][32]; break;
	case 7U: fault = &model_groups[launch_csg].input[20]; break;
	case 8U: fault = &model_glb_out[2]; value = 1U << launch_csg; break;
	case 9U: fault = &model_groups[launch_csg].output[2]; value = 1U << 1U; break;
	case 10U: fault = &model_groups[launch_csg].cs_input[1][0]; value = 2U; break;
	case 11U: fault = &registers[(0x2408U + as * 0x40U) / 4U]; break;
	case 12U: fault = &registers[(0x2430U + as * 0x40U) / 4U]; break;
	case 13U: fault = &registers[0x2408U / 4U]; break;
	case 14U: fault = &registers[0x704U / 4U]; break;
	case 15U: fault = &model_glb_out[0]; value = 2U; break;
	default: assert(false);
	}
	assert(complete_boundary_fault[0] == NULL && complete_boundary_fault[1] == NULL);
	complete_boundary_fault[0] = fault;
	complete_boundary_saved[0] = *fault;
	*fault ^= value;
	if (high != NULL) {
		complete_boundary_fault[1] = high;
		complete_boundary_saved[1] = *high;
		*high = 0U;
	}
}

static bool batch_read(unsigned long pa, size_t offset, void *data, size_t bytes);
static bool donated_read(unsigned long pa, size_t offset, void *data, size_t bytes)
{
	unsigned int index = donated_index(pa);

#ifdef GPU_DOMAIN_RSI_TEST
	if (domain_dispatch_active) assert(domain_policy_locked);
#endif
	assert(offset != 64U); /* Canonical history never reads donated pages. */
	if (dispatch_case) return batch_read(pa, offset, data, bytes);
	if (domain_active) {
		assert(!donated_visible[index] && data != NULL && bytes == 16U && offset <= 4096U - bytes);
		control_reads++;
		memcpy(data, donated_pages[index] + offset, bytes);
		/* Mutate after the last snapshot copy: only the post-read START
		 * check can reject this otherwise valid queue observation. */
		if (domain_read_fault != 0U && --domain_reads_until_fault == 0U) {
			unsigned int as = model_groups[launch_csg].input[20];
			drain_fault = domain_read_fault == 1U ? &registers[(0x2400U + as * 0x40U) / 4U] :
				domain_read_fault == 2U ? &registers[0x2400U / 4U] :
				&model_glb_out[4];
			drain_fault_saved = *drain_fault;
			*drain_fault ^= 0x1000U;
			domain_read_fault = 0U;
		}
		return true;
	}
	if (drain_case != 0U && track_complete) {
		assert(!donated_visible[index] && bytes == 16U && data != NULL);
		assert((pa == complete_read_pa[0] && offset == 0U) ||
			(pa == complete_read_pa[1] && offset == 0U) ||
			(pa == complete_read_pa[2] && offset == launch_queue * 16U));
		control_reads++;
		if (drain_case == 60U && launch_csg == 0U && drain_flushes != 0U)
			return false;
		memcpy(data, donated_pages[index] + offset, bytes);
		return true;
	}
	if (finish_case != 0U && status_cleans == 0U) {
		assert(!donated_visible[index] && bytes == 16U && data != NULL);
		assert((pa == complete_read_pa[0] && offset == 0U) ||
			(pa == complete_read_pa[1] && offset == 0U) ||
			(pa == complete_read_pa[2] && offset == launch_queue * 16U));
		control_reads++;
		memcpy(data, donated_pages[index] + offset, bytes);
		return true; /* Device progress is still made by model_status_ack. */
	}
	unsigned int read = complete_reads_this_call++;
	unsigned int expected = read < 3U ? read : 2U;
	unsigned int as = model_groups[launch_csg].input[20];

	assert(!donated_visible[index] && read < 4U && bytes == 16U && data != NULL);
	assert(pa == complete_read_pa[expected] && offset == (expected == 2U ? launch_queue * 16U : 0U));
	control_reads++;
	if (complete_case == 77U && read == 1U)
		return false;
	if (complete_case == 80U && read == 0U)
		registers[0x2000U / 4U] = 1U;
	if (complete_boundary_case != 0U && read == 2U)
		complete_boundary_inject(as);
	if (read == 3U) {
		assert(registers[(0x2400U + as * 0x40U) / 4U] == 0U);
		if (complete_case == 84U)
			((uint32_t *)(donated_pages[index] + offset))[2] = 7U;
		if (complete_case == 85U)
			registers[0x2000U / 4U] = 1U;
		if (complete_case == 86U)
			registers[(0x2400U + as * 0x40U) / 4U] = 0x1000U;
	}
	memcpy(data, donated_pages[index] + offset, bytes);
	return true;
}

static const struct gpu_private_ops donated_ops = {
	.source_page = donated_source, .hide_page = donated_hide,
	.restore_page = donated_restore, .clear_page = donated_clear,
	.table_pa = table_address, .clean = table_clean,
	.prepare_as = prepare_private, .extend_as = extend_private, .write_page = donated_write,
	.sync_page_for_device = data_sync, .detach_as = detach_private,
	.sync_page_for_cpu = data_return, .read_page = donated_read,
	.flush_as = flush_private, .cache_barrier = drain_barrier,
	.protected_mapping_summary = true
};

static unsigned int nc_data_index(const void *owner, unsigned long ipa, unsigned long pa)
{
	assert(owner == &client_a || owner == &client_b);
	unsigned int client = owner == &client_a ? 0U : 1U;

	assert(ipa >= 0x400000UL && ipa < 0x402000UL && (ipa & 4095UL) == 0UL);
	assert(pa == ipa + (client == 0U ? 0x40000000UL : 0x80000000UL));
	return client * 2U + (unsigned int)((ipa - 0x400000UL) / 4096UL);
}

static bool nc_data_hide(const void *owner, unsigned long ipa, unsigned long pa)
{
	unsigned int index = nc_data_index(owner, ipa, pa);
	unsigned char *visible = &nc_data_visibility[index / 2U][index % 2U];

	assert(*visible != 1U);
	*visible = 1U;
	return true;
}

static bool nc_data_restore(const void *owner, unsigned long ipa, unsigned long pa)
{
	unsigned int index = nc_data_index(owner, ipa, pa);
	unsigned char *visible = &nc_data_visibility[index / 2U][index % 2U];

	assert(*visible == 1U);
	*visible = 2U;
	return true;
}

static bool nc_data_restore_wb(const void *owner, unsigned long ipa, unsigned long pa)
{
	assert(nc_data_restore(owner, ipa, pa));
	unsigned int index = nc_data_index(owner, ipa, pa);

	nc_data_visibility[index / 2U][index % 2U] = 0U;
	return true;
}

static bool nc_data_cache(unsigned long pa)
{
	assert((pa >= 0x40400000UL && pa < 0x40402000UL) ||
		(pa >= 0x80400000UL && pa < 0x80402000UL));
	return true;
}

static struct gpu_private_ops nc_data_ops(void)
{
	struct gpu_private_ops ops = donated_ops;

	ops.hide_page = nc_data_hide;
	ops.restore_page = nc_data_restore_wb;
	ops.restore_page_uncached = nc_data_restore;
	ops.sync_page_for_device = nc_data_cache;
	ops.clear_page = nc_data_cache;
	return ops;
}

static bool drain_nc_client(unsigned int client)
{
	return domain_case != 0U || (drain_case != 0U && (drain_case != 2U || client != 0U));
}

static void destroy_prepared_bo(const void *owner, unsigned long bo,
		struct gpu_private_result *result)
{
	if (drain_nc_client(owner == &client_a ? 0U : 1U)) {
		struct gpu_private_ops ops = nc_data_ops();

		gpu_private_bo_release(&ops, owner, bo, result);
	} else {
		gpu_private_bo_destroy(owner, bo, result);
	}
}

static void drain_corrupt_controls(unsigned int scenario)
{
	uint32_t *point = NULL, value = 1U;
	uint32_t *cs = model_groups[launch_csg].cs_output[launch_queue];

	assert(drain_fault == NULL);
	switch (scenario) {
	case 1U: point = (void *)(uintptr_t)complete_read_pa[0]; value = 256U; break;
	case 2U: point = (void *)(uintptr_t)complete_read_pa[1]; value = 0U; break;
	case 3U: point = (void *)(uintptr_t)(complete_read_pa[2] + launch_queue * 16U); value = 0U; break;
	case 4U: point = (void *)(uintptr_t)(complete_read_pa[2] + launch_queue * 16U); value = 2U; break;
	case 5U: point = (void *)(uintptr_t)(complete_read_pa[2] + launch_queue * 16U + 8U); break;
	case 6U: point = &cs[23]; break;
	case 7U: point = &cs[24]; break;
	case 8U: point = &cs[32]; break;
	case 9U: point = &cs[33]; break;
	case 10U: point = model_groups[launch_csg].cs_input[launch_queue]; value = 0U; break;
	case 11U: point = &cs[0]; value = *point ^ (1U << 26U); break;
	case 12U: point = &model_groups[launch_csg].input[20]; value = *point ^ 1U; break;
	case 13U: point = &model_glb_out[4]; break;
	case 14U: point = &model_glb_in[2]; value = *point ^ (1U << launch_csg); break;
	case 15U: point = &model_groups[launch_csg].input[2]; value = *point ^ (1U << launch_queue); break;
	case 16U: point = model_groups[launch_csg].cs_output[0]; break;
	case 17U: point = (void *)(uintptr_t)(complete_read_pa[0] + 8U); value = 128U; break;
	case 18U: point = &registers[0x2400U / 4U]; value = *point ^ 0x1000U; break;
	default: assert(false);
	}
	drain_fault = point;
	drain_fault_saved = *point;
	*point = value;
}

static uint64_t software_leaf(unsigned long root, unsigned long va)
{
	unsigned long address = root;
	uint64_t pte = 0UL;

	for (unsigned int level = 0U; level < 4U; level++) {
		assert(address >= TABLE_BASE && address < TABLE_BASE + GPU_PRIVATE_TABLES * 4096UL);
		const uint64_t *table = (const uint64_t *)(table_base + address - TABLE_BASE);

		pte = table[(va >> (39U - level * 9U)) & 511UL];
		if (pte == 0UL)
			return 0UL;
		assert((pte & 3UL) == 3UL);
		address = pte & 0x0000fffffffff000UL;
	}
	return pte;
}

static unsigned long donate_arena(void)
{
	struct gpu_private_result result;
	unsigned long object, ipas[GPU_PRIVATE_BATCH];

	memset(donated_pages, 0xa5, sizeof(donated_pages));
	for (unsigned int i = 0U; i < CONTROL_TEST_PAGES; i++)
		donated_visible[i] = true;
	gpu_private_control_create(&service, sizeof(donated_pages), &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	object = result.value[0];
	for (unsigned int offset = 0U; offset < CONTROL_TEST_PAGES; offset += GPU_PRIVATE_BATCH) {
		unsigned int count = CONTROL_TEST_PAGES - offset;

		if (count > GPU_PRIVATE_BATCH)
			count = GPU_PRIVATE_BATCH;
		for (unsigned int i = 0U; i < count; i++)
			ipas[i] = CONTROL_TEST_IPA + (offset + i) * 4096UL;
		gpu_private_control_append(&donated_ops, &service, object, offset * 4096UL,
			ipas, count, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
	}
	gpu_firmware_control_bind(&fw_ops, &donated_ops, &stranger, object, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_control_bind(&fw_ops, &donated_ops, &service, object, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == sizeof(donated_pages));
	assert(result.value[1] == CONTROL_TEST_PAGES && result.value[2] == 0UL && result.value[3] == 0UL);
	return object;
}

static void group_backend_integration(unsigned long root, unsigned long contexts[2])
{
	struct gpu_private_result result;
	struct gpu_firmware_group_resources resources[2];
	const void *owners[2] = { &client_a, &client_b };
	unsigned long groups[2];
	unsigned long roots[2];
	unsigned int before = writes;

	for (unsigned int i = 0U; i < 2U; i++) {
		gpu_private_context_create(&private_ops, owners[i], &service, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		contexts[i] = result.value[0];
		roots[i] = latest_table_pa;
		gpu_firmware_group_create(&fw_ops, &donated_ops, &service,
			owners[i], contexts[i], 1UL, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[1] == 1UL);
		assert(result.value[2] == 0x40000UL && result.value[3] == 66UL);
		groups[i] = result.value[0];
		struct gpu_firmware_queue_config queue = { .ring_bytes = 65536U, .priority = i };

		gpu_firmware_group_configure(&donated_ops, &service, owners[i], groups[i], &queue, 1UL, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[1] == 17UL);
		assert(gpu_firmware_group_resources(&service, owners[i], groups[i], &resources[i]));
		/* Native Panthor restricts MCU suspend/ring-I/O allocations to this
		 * shared window. A valid AS0 PTE outside it is insufficient.
		 */
		assert(resources[i].suspend_va >= 0x04000000U &&
			(uint64_t)resources[i].output_va[0] + 4096U <= 0x08000000U);
		unsigned int first = (resources[i].suspend_va - GPU_FIRMWARE_CONTROL_VA) / 4096U;

		for (unsigned int p = 0U; p < 66U; p++) {
			uint64_t pte = *firmware_leaf(root, resources[i].suspend_va + p * 4096UL);

			assert((pte & 0x000000fffffff000UL) == (uintptr_t)donated_pages[first + p]);
			assert(!donated_visible[first + p]);
			for (unsigned int b = 0U; b < 4096U; b++)
				assert(donated_pages[first + p][b] == 0U);
		}
		first = (resources[i].ring_va[0] - GPU_PRIVATE_CONTROL_GPU_VA) / 4096UL;
		for (unsigned int p = 0U; p < 17U; p++) {
			uint64_t leaf = software_leaf(roots[i], resources[i].ring_va[0] + p * 4096UL);

			assert((leaf & 0x0000fffffffff000UL) == (uintptr_t)donated_pages[first + p]);
			assert((leaf & (3UL << 53U)) == (3UL << 53U) && !donated_visible[first + p]);
			assert(((leaf & (1UL << 7U)) != 0UL) == (p < 16U));
		}
	}
	assert(software_leaf(roots[0], resources[1].ring_va[0]) == 0UL &&
		software_leaf(roots[1], resources[0].ring_va[0]) == 0UL);
	assert(resources[0].output_va[0] + 4096U <= resources[1].suspend_va);
	gpu_firmware_group_validate(&service, &client_a, contexts[0], groups[0], 1UL, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_GROUP_RESERVED);
	gpu_firmware_group_validate(&service, &client_b, contexts[0], groups[0], 1UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_group_validate(&service, &client_a, contexts[1], groups[0], 1UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_group_validate(&service, &client_a, contexts[0], groups[0], 2UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	assert(writes == before); /* Import validation never rings a task doorbell. */
	gpu_firmware_group_inspect(&service, &client_b, groups[0], &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_context_destroy(&private_ops, &client_a, contexts[0], &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_firmware_group_destroy(&donated_ops, &client_a, groups[0], &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	assert(software_leaf(roots[0], resources[0].ring_va[0]) == 0UL);
	gpu_firmware_group_inspect(&service, &client_a, groups[0], &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	/* B remains held across actual trusted reset in the surrounding test. */
	assert(writes == before && firmware_doorbells == 1U);
	puts("GPU_GROUP_BACKEND_INTEGRATION=PASS authenticated Client contexts, disjoint suspend/queue IO extents from actual installed AS0 model root, CPU-hidden pages, scrub, context holds, stale handles, no added MMIO writes or task doorbells; MODEL_ONLY");
}

/* Full preparation core against the actual platform MMIO backend and protected
 * donated backing. All synthetic MCU results remain explicitly MODEL_ONLY. */
static unsigned long prepared_bos[2], last_prepared_task, prepared_alias_context;
static unsigned long heap_test_bos[2];
static unsigned long heap_group_handle;
static unsigned int heap_return_pages;
static bool heap_return_old[2], heap_return_new[GPU_PRIVATE_BATCH + 1U];
static unsigned long prepared_unpublished_task;

static uint64_t words64(const uint32_t *words, unsigned int index)
{
	return words[index] | ((uint64_t)words[index + 1U] << 32U);
}

static bool unexpected_quiesced_activation(unsigned long context, unsigned long root, unsigned int slot)
{
	(void)context;
	(void)root;
	(void)slot;
	assert(false && "quiesced context must reject legacy activation before backend");
	return false;
}

static void retire_boundary_fault(unsigned long context, unsigned long group,
		unsigned long token, unsigned long client_root, unsigned int client)
{
	const void *owner = client == 0U ? &client_a : &client_b;
	const void *caller = &service, *submitted_owner = owner;
	unsigned long submitted_token = token;
	unsigned int as = model_groups[client].input[20];
	uint32_t *fault = NULL, *fault_high = NULL, saved = 0U, saved_high = 0U, changed = 1U;
	unsigned int before = writes, controls = control_writes;
	unsigned int syncs = data_syncs, returns = cpu_returns;
	struct gpu_private_result result;

	switch (retire_boundary_case) {
	case 1U: case 19U: fault = &registers[(0x2400U + as * 0x40U) / 4U]; changed = 0x1000U; break;
	case 2U: fault = &registers[(0x2408U + as * 0x40U) / 4U]; break;
	case 3U: fault = &registers[(0x2430U + as * 0x40U) / 4U]; break;
	case 4U: case 22U: fault = &registers[0x2400U / 4U]; changed = 0x1000U; break;
	case 5U:
		fault = &registers[0x100U / 4U]; changed = *fault;
		fault_high = &registers[0x104U / 4U]; saved_high = *fault_high;
		*fault_high = 0U;
		break;
	case 6U: fault = &model_glb_out[0]; changed = 2U; break;
	case 7U: case 20U: fault = &model_glb_out[4]; break;
	case 8U: fault = &model_groups[client].output[0]; changed = 1U << 5U; break;
	case 9U: fault = &model_groups[client].input[0]; changed = 2U; break;
	case 10U: fault = &model_groups[client].output[2]; changed = 1U << 1U; break;
	case 11U: fault = &model_groups[client].input[20]; break;
	case 12U: fault = &model_groups[client].cs_output[1][32]; break;
	case 13U: fault = &model_groups[client].cs_output[0][0]; changed = 1U << 27U; break;
	case 14U: case 21U: fault = &model_groups[client].cs_input[1][0]; break;
	case 15U:
		fault = &registers[0x24c0U / 4U]; changed = (uint32_t)client_root;
		fault_high = &registers[0x24c4U / 4U]; saved_high = *fault_high;
		*fault_high = (uint32_t)(client_root >> 32U);
		break;
	case 16U: caller = &stranger; break;
	case 17U: submitted_owner = client == 0U ? &client_b : &client_a; break;
	case 18U: submitted_token++; break;
	default: assert(false);
	}
	if (fault != NULL) {
		saved = *fault;
		*fault ^= changed;
	}
	uint32_t csg_before[0x58U / 4U], cs_before[2][0x60U / 4U];

	memcpy(csg_before, model_groups[client].input, sizeof(csg_before));
	for (unsigned int q = 0U; q < 2U; q++)
		memcpy(cs_before[q], model_groups[client].cs_input[q], sizeof(cs_before[q]));
	retire_expected_count = retire_clears = 0U;
	track_launch = false;
	track_retire = true; /* No physical clear may precede rejection. */
	gpu_firmware_task_retire(&fw_ops, &donated_ops, caller, submitted_owner,
		submitted_token, &result);
	track_retire = false;
	assert(result.status == (retire_boundary_case >= 16U && retire_boundary_case <= 18U ?
		GPU_PRIVATE_INPUT : GPU_PRIVATE_STATE));
	assert(!retire_clears && control_writes == controls && writes == before &&
		data_syncs == syncs && cpu_returns == returns);
	for (unsigned int i = 0U; i < 4U; i++) assert(result.value[i] == 0UL);
	assert(memcmp(csg_before, model_groups[client].input, sizeof(csg_before)) == 0);
	for (unsigned int q = 0U; q < 2U; q++)
		assert(memcmp(cs_before[q], model_groups[client].cs_input[q], sizeof(cs_before[q])) == 0);
	gpu_firmware_group_inspect(&service, owner, group, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] ==
		(retire_boundary_case >= 16U && retire_boundary_case <= 18U ?
		GPU_FIRMWARE_GROUP_QUIESCED : GPU_FIRMWARE_GROUP_QUARANTINED));
	gpu_firmware_task_cancel(owner, token, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_private_unmap(&private_ops, owner, context, 0x100000UL, 2UL, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	destroy_prepared_bo(owner, prepared_bos[client], &result);
	assert(result.status == GPU_PRIVATE_STATE);
	if (fault != NULL) *fault = saved; /* Model reset can now audit teardown. */
	if (fault_high != NULL) *fault_high = saved_high;
	track_complete = track_stop = track_launch = false;
	printf("GPU_RETIRE_BOUNDARY_FAULT=PASS case=%u client=%u zero scrub/publication/release before rejection; MODEL_ONLY\n",
		retire_boundary_case, client);
}

static void task_retire_backend(unsigned long context, unsigned long group,
		unsigned long token, unsigned long client_root, unsigned int client,
		unsigned int scenario)
{
	const void *owners[2] = { &client_a, &client_b };
	const void *owner = owners[client];
	struct gpu_private_result result;
	unsigned int before = writes, commands_before = as_count;
	unsigned int syncs_before = data_syncs, returns_before = cpu_returns;
	unsigned int as = model_groups[client].input[20], calls = 0U;
	unsigned long root = words64(registers + 0x2400U / 4U, 0U);
	uint32_t *csg = model_groups[client].input;
	bool retired = scenario != 61U && scenario != 62U && scenario != 63U;

	if (retire_boundary_case != 0U) {
		retire_boundary_fault(context, group, token, client_root, client);
		return;
	}
	if (scenario >= 66U) {
		struct gpu_firmware_group_resources resource;
		unsigned int control_before = control_writes;

		resource.streams = 2U;
		for (unsigned int q = 0U; q < resource.streams; q++)
			resource.input_va[q] = (uint32_t)words64(model_groups[client].cs_input[q], 12U);
		retire_expected_count = retire_clears = 0U;
		track_launch = false;
		track_retire = true; /* Any scrub of retained state is a regression. */
		mmio_reads = firmware_checks = shader_checks = 0U;
		gpu_firmware_task_retire(&fw_ops, &donated_ops, &service, owner, token, &result);
		track_retire = false;
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[2] == 0U &&
			!retire_clears && control_writes == control_before);
		assert(mmio_reads == 75U && firmware_checks == 2U && shader_checks == 2U);
		printf("GPU_RETIRE_BOUNDARY=PASS scenario=%u client=%u reads=%u config_checks=%u no scrub, fresh full check before release; MODEL_ONLY\n",
			scenario, client, mmio_reads, shader_checks);
		for (unsigned int q = 0U; q < resource.streams; q++) {
			unsigned int page = (resource.input_va[q] - GPU_FIRMWARE_CONTROL_VA) / 4096U;

			assert(*(uint64_t *)(donated_pages[page] + 64U) == 0UL);
		}
		gpu_firmware_task_complete(&fw_ops, &donated_ops, &service, owner, token, &result);
		assert(result.status == GPU_PRIVATE_INPUT);
		/* A subsequent submission must RESUME, retaining monotonic ring IO
		 * and leaving the old protected wrapper behind its consumer cursor.
		 */
		gpu_firmware_task_stage(&private_ops, &service, owner, group, 1UL, 0x100ff8UL, 16UL, 8UL, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		unsigned long next = result.value[0];

		gpu_firmware_task_prepare(&fw_ops, &donated_ops, &service, owner, context, group, next, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		unsigned int page = (resource.input_va[1] - GPU_FIRMWARE_CONTROL_VA) / 4096U;

		assert(*(uint64_t *)donated_pages[page] == 256UL &&
			*(uint64_t *)(donated_pages[page] + 8U) == 128UL);
		sync_expected_base = return_expected_base;
		sync_expected_pages = return_expected_pages;
		memset(synced_data, 0, sizeof(synced_data));
		do {
			gpu_firmware_task_ready(&fw_ops, &donated_ops, &service, owner, next, &result);
		} while (result.status == GPU_PRIVATE_INCOMPLETE);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		launch_case = 13U;
		launch_cleans = 0U;
		track_stop = track_complete = false;
		track_launch = true;
		gpu_firmware_task_start(&fw_ops, &donated_ops, &service, owner, context, group, next, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && (csg[0] & 7U) == 3U);
		launch_cleans = 0U;
		track_stop = true;
		stop_case = 33U;
		gpu_firmware_task_quiesce(&fw_ops, &donated_ops, &service, owner, context, group, next, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		track_stop = track_launch = false;
		printf("GPU_TASK_PERSISTENT_CSG=PASS scenario=%u client=%u protected context retained, monotonic IO, RESUME not fresh START, old token invalid; MODEL_ONLY\n", scenario, client);
		return;
	}
	retire_case = scenario;
	retire_clears = retire_expected_count = 0U;
	for (unsigned int page = 0U; page < 0x40000U / 4096U + 4U; page++) {
		unsigned long va = words64(csg, 16U) + page * 4096UL;

		retire_expected_pa[retire_expected_count++] = *firmware_leaf(root, va) & UINT64_C(0x000000fffffff000);
	}
	for (unsigned int q = 0U; q < 2U; q++) {
		uint32_t *cs = model_groups[client].cs_input[q];

		for (unsigned int page = 0U; page < cs[6] / 4096U; page++)
			retire_expected_pa[retire_expected_count++] = software_leaf(client_root,
				words64(cs, 4U) + page * 4096UL) & UINT64_C(0x000000fffffff000);
	}
	retire_expected_pa[retire_expected_count++] = quiesce_sync_pa[client];
	for (unsigned int i = 0U; i < retire_expected_count; i++)
		memset((void *)(uintptr_t)retire_expected_pa[i], 0xa5, 4096U);
	for (unsigned int bad = 0U; bad < 4U; bad++) {
		gpu_firmware_task_retire(&fw_ops, &donated_ops, bad == 0U ? &stranger : &service,
			bad == 1U ? &service : bad == 2U ? owners[1U - client] : owner,
			bad == 3U ? token + 1UL : token, &result);
		assert(result.status == GPU_PRIVATE_INPUT && retire_clears == 0U);
	}
	assert(!gpu_private_task_retire(&service, owner, context, token + 1UL));
	track_launch = false; /* Retirement has CS/CSG clears, not launch publication. */
	track_retire = true;
	do {
		unsigned int old_clears = retire_clears;

		gpu_firmware_task_retire(&fw_ops, &donated_ops, &service, owner, token, &result);
		assert(++calls <= (retire_expected_count / GPU_PRIVATE_BATCH) + 2U &&
			retire_clears - old_clears <= GPU_PRIVATE_BATCH);
	} while (result.status == GPU_PRIVATE_INCOMPLETE);
	track_retire = false;
	assert(result.status == (retired ? GPU_PRIVATE_SUCCESS : GPU_PRIVATE_STATE));
	assert(writes == before && as_count == commands_before &&
		data_syncs == syncs_before && cpu_returns == returns_before);
	if (!retired) {
		assert(retire_clears == (scenario == 61U ? 2U : retire_expected_count));
		for (unsigned int i = 0U; i < 4U; i++)
			assert(result.value[i] == 0UL);
		gpu_firmware_task_retire(&fw_ops, &donated_ops, &service, owner, token, &result);
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_firmware_task_cancel(owner, token, &result);
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_firmware_group_destroy(&donated_ops, owner, group, &result);
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_firmware_group_inspect(&service, owner, group, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_GROUP_QUARANTINED);
		destroy_prepared_bo(owner, prepared_bos[client], &result);
		assert(result.status == GPU_PRIVATE_STATE);
		goto done;
	}
	assert(result.value[0] == 1UL && result.value[1] == 1UL &&
		result.value[2] == retire_expected_count && result.value[3] == 0UL);
	assert(retire_clears == retire_expected_count);
	for (unsigned int page = 0U; page < retire_expected_count; page++)
		for (unsigned int byte = 0U; byte < 4096U; byte++)
			assert(((unsigned char *)(uintptr_t)retire_expected_pa[page])[byte] == 0U);
	for (unsigned int q = 0U; q < 2U; q++)
		for (unsigned int word = 0U; word < 0x60U / 4U; word++)
			assert(model_groups[client].cs_input[q][word] == 0U);
	for (unsigned int word = 0U; word < 0x58U / 4U; word++)
		assert(word == 0U ? (csg[word] & ~0x37U) == 0U :
			word == 2U ? csg[word] == model_groups[client].output[2] : csg[word] == 0U);
	gpu_firmware_task_retire(&fw_ops, &donated_ops, &service, owner, token, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_task_return(&fw_ops, &donated_ops, &service, owner, token, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_task_start(&fw_ops, &donated_ops, &service, owner, context, group, token, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_group_inspect(&service, owner, group, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_GROUP_RESERVED);
	gpu_private_query(owner, context, 0x100000UL, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] != 0UL &&
		result.value[1] == 0UL && result.value[2] == 0UL && result.value[3] == 0UL);
	if (scenario == 65U) {
		/* Retiring one published task must preserve another staged hold. */
		gpu_private_unmap(&private_ops, owner, context, 0x100000UL, 2UL, &result);
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_firmware_task_validate(&service, owner, context, group, prepared_unpublished_task, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		gpu_firmware_task_cancel(owner, prepared_unpublished_task, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
	}
	if (scenario == 64U) {
		gpu_firmware_group_destroy(&donated_ops, owner, group, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		gpu_private_unmap(&private_ops, owner, context, 0x100000UL, 2UL, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		destroy_prepared_bo(owner, prepared_bos[client], &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		prepared_bos[client] = 0UL;
	} else {
		unsigned long new_token;

		/* Reuse the group, exact AS and CSG without a whole-device reset. */
		gpu_firmware_task_stage(&private_ops, &service, owner, group, 1UL, 0x100ff8UL, 16UL, 8UL, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] != token);
		new_token = result.value[0];
		gpu_firmware_task_prepare(&fw_ops, &donated_ops, &service, owner, context, group, new_token, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && model_groups[client].input[20] == as);
		sync_expected_base = return_expected_base;
		sync_expected_pages = return_expected_pages;
		memset(synced_data, 0, sizeof(synced_data));
		do {
			gpu_firmware_task_ready(&fw_ops, &donated_ops, &service, owner, new_token, &result);
		} while (result.status == GPU_PRIVATE_INCOMPLETE);
		assert(result.status == GPU_PRIVATE_SUCCESS && data_syncs - syncs_before == return_expected_pages);
		launch_cleans = 0U;
		track_stop = false;
		track_launch = true;
		launch_case = 13U;
		gpu_firmware_task_start(&fw_ops, &donated_ops, &service, owner, context, group, new_token, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		launch_cleans = 0U;
		track_stop = true;
		stop_case = 33U;
		gpu_firmware_task_quiesce(&fw_ops, &donated_ops, &service, owner, context, group, new_token, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		track_stop = track_launch = false;
	}
 done:
	printf("GPU_TASK_RETIRE_BACKEND=PASS scenario=%u client=%u calls=%u scrubbed=%u exact identity, cache return before scrub, failure retains refs, old token invalid, group/AS/CSG reuse or destruction; ABORT_ONLY MODEL_ONLY\n",
		scenario, client, calls, retire_clears);
}

static void task_return_backend(unsigned long context, unsigned long group,
		unsigned long token, unsigned long client_root, unsigned int client, unsigned int scenario)
{
	const void *owners[2] = { &client_a, &client_b };
	struct gpu_private_result result;
	unsigned int as = model_groups[client].input[20], at = (0x2400U + as * 0x40U) / 4U;
	unsigned int before = writes, commands_before = as_count;
	unsigned int syncs_before = data_syncs, control_before = control_writes;
	unsigned int initial_returns = cpu_returns, calls = 0U, previous_pages = 0U;
	bool returned = scenario == 48U || scenario == 50U || scenario == 55U ||
		scenario == 56U || scenario == 57U || scenario == 58U || scenario >= 60U;

	return_case = scenario;
	gpu_firmware_task_retire(&fw_ops, &donated_ops, &service, owners[client], token, &result);
	assert(result.status == GPU_PRIVATE_STATE && cpu_returns == initial_returns);
	return_expected_base = 0x400000UL + (client == 0U ? 0x40000000UL : 0x80000000UL);
	return_expected_pages = scenario == 50U ? GPU_PRIVATE_BATCH + 1UL : 2UL;
	memset(returned_data, 0, sizeof(returned_data));
	for (unsigned int bad = 0U; bad < 4U; bad++) {
		gpu_firmware_task_return(&fw_ops, &donated_ops,
			bad == 0U ? &stranger : &service,
			bad == 1U ? &service : bad == 2U ? owners[1U - client] : owners[client],
			bad == 3U ? token + 1UL : token, &result);
		assert(result.status == GPU_PRIVATE_INPUT && cpu_returns == initial_returns);
	}
	gpu_private_task_return(&donated_ops, &service, owners[client], context, token + 1UL, &result);
	assert(result.status == GPU_PRIVATE_STATE && cpu_returns == initial_returns);
	if (scenario == 49U)
		fail_cpu_return = cpu_returns + 2U;
	if (scenario == 54U)
		registers[at + 2U] = 1U; /* Disabled AS must have zero MEMATTR. */
	if (scenario == 59U)
		model_groups[client].output[0] |= 2U;
	if (scenario == 55U) {
		struct gpu_private_ops missing = donated_ops;

		missing.sync_page_for_cpu = NULL;
		gpu_firmware_task_return(&fw_ops, &missing, &service, owners[client], token, &result);
		assert(result.status == GPU_PRIVATE_STATE && cpu_returns == initial_returns);
	}
	do {
		unsigned int old_returns = cpu_returns;

		gpu_firmware_task_return(&fw_ops, &donated_ops, &service, owners[client], token, &result);
		assert(++calls <= GPU_PRIVATE_TABLES + 1U && cpu_returns - old_returns <= GPU_PRIVATE_BATCH);
		if (result.status == GPU_PRIVATE_INCOMPLETE) {
			assert(result.value[0] == 0UL && result.value[1] == 1UL && result.value[3] == 0UL);
			assert(result.value[2] >= previous_pages);
			previous_pages = (unsigned int)result.value[2];
			struct gpu_private_result refused;

			gpu_firmware_task_retire(&fw_ops, &donated_ops, &service, owners[client], token, &refused);
			assert(refused.status == GPU_PRIVATE_STATE);
		}
	} while (result.status == GPU_PRIVATE_INCOMPLETE);
	assert(result.status == (returned ? GPU_PRIVATE_SUCCESS : GPU_PRIVATE_STATE));
	if (returned) {
		assert(result.value[0] == 1UL && result.value[1] == 1UL &&
			result.value[2] == return_expected_pages && result.value[3] == 0UL);
		assert(cpu_returns - initial_returns == return_expected_pages &&
			calls >= (return_expected_pages + GPU_PRIVATE_BATCH - 1U) / GPU_PRIVATE_BATCH);
		for (unsigned int j = 0U; j < return_expected_pages; j++)
			assert(returned_data[j]);
	} else {
		for (unsigned int j = 0U; j < 4U; j++)
			assert(result.value[j] == 0UL);
		assert(cpu_returns - initial_returns == (scenario == 54U || scenario == 59U ? 0U : 2U));
	}
	if (scenario == 56U)
		registers[0x2000U / 4U] = 1U;
	if (scenario == 57U)
		registers[at] = 0x1000U;
	unsigned int final_returns = cpu_returns;
	bool replay_ok = returned && scenario != 56U && scenario != 57U;

	struct gpu_firmware_ops replay_ops = fw_ops;

	replay_ops.configuration = replay_configuration;
	replay_configuration_checks = 0U;
	firmware_checks = shader_checks = mmio_reads = 0U;
	gpu_firmware_task_return(&replay_ops, &donated_ops, &service, owners[client], token, &result);
	assert(result.status == (replay_ok ? GPU_PRIVATE_SUCCESS : GPU_PRIVATE_STATE));
	if (replay_ok) {
		assert(replay_configuration_checks == 0U && firmware_checks == 2U && shader_checks == 2U);
		printf("GPU_TASK_RETURN_REPLAY=PASS scenario=%u client=%u config_checks=%u backend_config_checks=%u reads=%u fresh STOP/AS, no physical callbacks or MMIO writes; MODEL_ONLY\n",
			scenario, client, replay_configuration_checks, shader_checks, mmio_reads);
	}
	assert(cpu_returns == final_returns && writes == before && as_count == commands_before && launch_cleans == 0U);
	gpu_firmware_task_start(&fw_ops, &donated_ops, &service, owners[client], context, group, token, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_firmware_task_cancel(owners[client], token, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_firmware_group_destroy(&donated_ops, owners[client], group, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	destroy_prepared_bo(owners[client], prepared_bos[client], &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_firmware_group_inspect(&service, owners[client], group, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] ==
		(replay_ok ? GPU_FIRMWARE_GROUP_QUIESCED : GPU_FIRMWARE_GROUP_QUARANTINED));
	assert(data_syncs == syncs_before && control_writes == control_before);
	printf("GPU_TASK_RETURN_BACKEND=PASS scenario=%u client=%u calls=%u pages=%u checked STOP/disabled AS before and after bounded private invalidation, replay without writes, refs retained; ABORT_ONLY MODEL_ONLY\n",
		scenario, client, calls, cpu_returns - initial_returns);
	if (scenario >= 60U)
		task_retire_backend(context, group, token, client_root, client, scenario);
}

static void task_reclaim_backend(unsigned long group,
		unsigned long token, unsigned int client)
{
	const void *owners[2] = { &client_a, &client_b };
	const void *owner = owners[client];
	struct gpu_private_result result;
	unsigned int before = writes, commands_before = as_count;
	unsigned int returns_before = cpu_returns, controls_before = control_writes;
	unsigned int as = model_groups[client].input[20], calls = 0U;
	bool success = reclaim_case <= 2U;

	return_expected_base = 0x400000UL + (client == 0U ? 0x40000000UL : 0x80000000UL);
	return_expected_pages = reclaim_case == 2U && client == 0U ? GPU_PRIVATE_BATCH + 1UL : 2UL;
	memset(returned_data, 0, sizeof(returned_data));
	for (unsigned int bad = 0U; bad < 4U; bad++) {
		gpu_firmware_task_reclaim(&fw_ops, &donated_ops,
			bad == 0U ? &stranger : &service,
			bad == 1U ? &service : bad == 2U ? owners[1U - client] : owner,
			bad == 3U ? token + 1UL : token, &result);
		assert(result.status == GPU_PRIVATE_INPUT && cpu_returns == returns_before &&
			writes == before && control_writes == controls_before);
	}
	if (reclaim_case == 3U)
		fail_cpu_return = cpu_returns + 2U;
	if (reclaim_case >= 4U && reclaim_case <= 6U)
		return_case = reclaim_case == 6U ? 54U : reclaim_case + 47U;
	if (reclaim_case >= 7U) {
		complete_boundary_case = reclaim_case - 6U;
		complete_boundary_inject(as);
		complete_boundary_case = 0U;
	}
	track_launch = false;
	track_retire = true; /* Successful execution must never scrub native state. */
	retire_clears = 0U;
	mmio_reads = shader_checks = 0U;
	do {
		unsigned int previous = cpu_returns;

		gpu_firmware_task_reclaim(&fw_ops, &donated_ops, &service, owner, token, &result);
		assert(++calls <= GPU_PRIVATE_TABLES + 1U && cpu_returns - previous <= GPU_PRIVATE_BATCH);
		if (result.status == GPU_PRIVATE_INCOMPLETE) {
			assert(result.value[0] == 0UL && result.value[1] == 1UL &&
				result.value[2] == 0UL && result.value[3] == 0UL);
			struct gpu_private_result refused;

			gpu_firmware_group_destroy(&donated_ops, owner, group, &refused);
			assert(refused.status == GPU_PRIVATE_STATE);
			destroy_prepared_bo(owner, prepared_bos[client], &refused);
			assert(refused.status == GPU_PRIVATE_STATE);
		}
	} while (result.status == GPU_PRIVATE_INCOMPLETE);
	track_retire = false;
	assert(result.status == (success ? GPU_PRIVATE_SUCCESS : GPU_PRIVATE_STATE));
	assert(writes == before && as_count == commands_before && !retire_clears &&
		control_writes == controls_before);
	if (success) {
		assert(result.value[0] == 1UL && result.value[1] == 1UL &&
			result.value[2] == 0UL && result.value[3] == 0UL);
		assert(cpu_returns - returns_before == return_expected_pages &&
			calls >= (return_expected_pages + GPU_PRIVATE_BATCH - 1UL) / GPU_PRIVATE_BATCH);
		for (unsigned int i = 0U; i < return_expected_pages; i++)
			assert(returned_data[i]);
		printf("GPU_TASK_RECLAIM_COST=PASS case=%u client=%u calls=%u reads=%u checks=%u; MODEL_ONLY\n",
			reclaim_case, client, calls, mmio_reads, shader_checks);
		gpu_firmware_task_reclaim(&fw_ops, &donated_ops, &service, owner, token, &result);
		assert(result.status == GPU_PRIVATE_INPUT);
		gpu_firmware_task_retire(&fw_ops, &donated_ops, &service, owner, token, &result);
		assert(result.status == GPU_PRIVATE_INPUT);
		gpu_firmware_group_inspect(&service, owner, group, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_GROUP_RESERVED);
		/* Exact native state is reusable; the retired token cannot authorize it. */
		gpu_firmware_task_stage(&private_ops, &service, owner, group, 1UL, 0x100ff8UL, 16UL, 8UL, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] != token);
		unsigned long next = result.value[0];

		gpu_firmware_task_cancel(owner, next, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
	} else {
		assert(cpu_returns - returns_before == (reclaim_case >= 7U ? 0U : 2U));
		gpu_firmware_group_destroy(&donated_ops, owner, group, &result);
		assert(result.status == GPU_PRIVATE_STATE);
		destroy_prepared_bo(owner, prepared_bos[client], &result);
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_firmware_task_retire(&fw_ops, &donated_ops, &service, owner, token, &result);
		assert(result.status == GPU_PRIVATE_STATE && writes == before &&
			control_writes == controls_before && !retire_clears);
	}
	/* Restore only injected model faults, after proving failed cleanup holds. */
	for (unsigned int i = 0U; i < 2U; i++) {
		if (complete_boundary_fault[i] != NULL)
			*complete_boundary_fault[i] = complete_boundary_saved[i];
		complete_boundary_fault[i] = NULL;
	}
	if (reclaim_case == 4U)
		registers[0x2000U / 4U] = 0U;
	if (reclaim_case == 5U)
		registers[(0x2400U + as * 0x40U) / 4U] = 0U;
	if (reclaim_case == 6U)
		model_groups[client].cs_output[launch_queue][32] = 0U;
	printf("GPU_TASK_RECLAIM=PASS case=%u client=%u success=%u bounded physical return and exact retirement; MODEL_ONLY\n",
		reclaim_case, client, success ? 1U : 0U);
}

static void task_quiesce_backend(unsigned long contexts[2], unsigned long groups[2],
		unsigned long tokens[2], unsigned int count, unsigned int scenario)
{
	const void *owners[2] = { &client_a, &client_b };
	struct gpu_private_result result;
	unsigned long root = registers[0x2400U / 4U] | ((unsigned long)registers[0x2404U / 4U] << 32U);

	for (unsigned int i = 0U; i < count; i++) {
		unsigned int syncs_before = data_syncs, control_before = control_writes;
		unsigned int before = writes, commands_before = as_count, returns_before = cpu_returns;
		uint32_t doorbell_before = model_glb_in[2];
		unsigned int as = model_groups[i].input[20], at = (0x2400U + as * 0x40U) / 4U;
		unsigned long client_root = registers[at] | ((unsigned long)registers[at + 1U] << 32U);
		bool stopped = scenario == 33U || scenario == 44U || scenario == 45U || scenario == 47U || scenario >= 48U;

		*(uint64_t *)(uintptr_t)quiesce_sync_pa[i] = UINT64_MAX;
		launch_csg = i;
		launch_queue = 1U;
		stop_case = scenario;
		if (scenario >= 48U) {
			gpu_firmware_task_return(&fw_ops, &donated_ops, &service, owners[i], tokens[i], &result);
			assert(result.status == GPU_PRIVATE_STATE && cpu_returns == returns_before);
		}
		launch_cleans = 0U;
		track_launch = track_stop = true;
		for (unsigned int bad = 0U; bad < 5U; bad++) {
			gpu_firmware_task_quiesce(&fw_ops, &donated_ops,
				bad == 0U ? &stranger : &service, bad == 1U ? owners[1U - i] : owners[i],
				bad == 2U ? contexts[i] + 1UL : contexts[i],
				bad == 3U ? groups[i] + 1UL : groups[i],
				bad == 4U ? tokens[i] + 1UL : tokens[i], &result);
			assert(result.status == GPU_PRIVATE_INPUT && writes == before && launch_cleans == 0U);
		}
		if (scenario == 38U)
			fail_as_command = 5U;
		if (scenario == 39U)
			fail_as_command = 1U;
		if (scenario == 40U)
			registers[0x2000U / 4U] = 1U;
		if (scenario == 41U)
			registers[at] ^= 0x1000U;
		gpu_firmware_task_quiesce(&fw_ops, &donated_ops, &service, owners[i],
			contexts[i], groups[i], tokens[i], &result);
		assert(result.status == (stopped ? GPU_PRIVATE_SUCCESS : GPU_PRIVATE_STATE));
		if (scenario == 40U || scenario == 41U)
			assert(writes == before && launch_cleans == 0U);
		if (stopped) {
			assert(result.value[0] == GPU_FIRMWARE_GROUP_QUIESCED && result.value[1] == 1UL &&
				result.value[2] == 0UL && result.value[3] == 0UL);
			assert(as_count == commands_before + 3U && as_commands[commands_before] == 2U &&
				as_commands[commands_before + 1U] == 5U && as_commands[commands_before + 2U] == 1U);
			assert(registers[at] == 0U && registers[at + 1U] == 0U &&
				registers[at + 2U] == 0U && registers[at + 3U] == 0U &&
				registers[at + 12U] == 1U && registers[at + 13U] == 0U);
			assert(model_glb_in[2] == (doorbell_before ^ (1U << i)));
			if (i + 1U < count)
				assert((model_groups[i + 1U].output[0] & 7U) == 1U && registers[at + 16U] != 0U);
		} else {
			for (unsigned int v = 0U; v < 4U; v++)
				assert(result.value[v] == 0UL);
			if (scenario == 34U || scenario == 35U || scenario == 36U || scenario == 37U ||
			    scenario == 40U || scenario == 41U || scenario == 42U || scenario == 43U || scenario == 46U)
				assert(as_count == commands_before);
			if (scenario == 39U)
				assert(registers[at] == 0U && as_count == commands_before + 3U); /* Partial UPDATE retained. */
		}
		if (scenario == 44U) {
			/* Some roots have zero low bits: corrupt the full 64-bit value. */
			registers[at] = (uint32_t)client_root;
			registers[at + 1U] = (uint32_t)(client_root >> 32U);
		}
		if (scenario == 45U)
			model_groups[i].output[0] ^= 2U;
		before = writes;
		launch_cleans = 0U;
		gpu_firmware_task_quiesce(&fw_ops, &donated_ops, &service, owners[i],
			contexts[i], groups[i], tokens[i], &result);
		bool replay_ok = scenario == 33U || scenario == 47U || scenario >= 48U;

		assert(result.status == (replay_ok ? GPU_PRIVATE_SUCCESS : GPU_PRIVATE_STATE));
		assert(writes == before && launch_cleans == 0U);
		gpu_firmware_task_start(&fw_ops, &donated_ops, &service, owners[i],
			contexts[i], groups[i], tokens[i], &result);
		assert(result.status == GPU_PRIVATE_STATE && writes == before);
		if (stopped) {
			struct gpu_private_ops guarded = donated_ops;

			guarded.activate = unexpected_quiesced_activation;
			guarded.synchronize = sync_private;
			gpu_private_context_activate(&guarded, &service, contexts[i], as, &result);
			assert(result.status == GPU_PRIVATE_STATE && writes == before);
			gpu_private_context_prepare(&donated_ops, &service, owners[i], contexts[i], root, &result);
			assert(result.status == GPU_PRIVATE_STATE && writes == before); /* Cannot reinstall disabled root. */
		}
		gpu_firmware_task_cancel(owners[i], tokens[i], &result);
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_firmware_group_destroy(&donated_ops, owners[i], groups[i], &result);
		assert(result.status == GPU_PRIVATE_STATE);
		destroy_prepared_bo(owners[i], prepared_bos[i], &result);
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_firmware_group_inspect(&service, owners[i], groups[i], &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] ==
			(replay_ok ? GPU_FIRMWARE_GROUP_QUIESCED : GPU_FIRMWARE_GROUP_QUARANTINED));
		assert(data_syncs == syncs_before && control_writes == control_before && !opencca_gpu_mmio_allowed(&service));
		if (scenario >= 48U)
			task_return_backend(contexts[i], groups[i], tokens[i], client_root, i, scenario);
		track_stop = track_launch = false;
	}
	printf("GPU_TASK_QUIESCE_BACKEND=PASS scenario=%u Clients=%u trusted STOP/TERMINATE ACK before FLUSH_MEM/UNMAPPED/UPDATE, distinct roots, forged completion ignored, exact identity, no restart/replay writes, backing/cache retained; ABORT_ONLY MODEL_ONLY\n", scenario, count);
}

static void task_finish_backend(unsigned long context, unsigned long group,
		unsigned long token, unsigned int client, unsigned int scenario)
{
	const void *owner = client == 0U ? (void *)&client_a : (void *)&client_b;
	const void *other = client == 0U ? (void *)&client_b : (void *)&client_a;
	struct gpu_private_result result;
	unsigned int test = finish_case, calls = 0U, pending_calls = 0U;
	unsigned int before = cpu_returns, written = writes, controls = control_writes;
	unsigned int as = model_groups[client].input[20];
	unsigned int at = (0x2400U + as * 0x40U) / 4U;
	uint32_t live_snapshot[sizeof(registers) / sizeof(registers[0])];
	unsigned long live_frequency = timer_frequency;
	unsigned int live_commands = as_count;
	bool live_fault = test >= 43U && client == 0U;
	bool large = client == 0U && (test == 2U || test == 9U || (test >= 25U && test <= 39U));
	bool success = test <= 3U || (test >= 40U && !live_fault) || (test == 9U && client != 0U) ||
		(test >= 25U && test <= 39U && client != 0U);

	return_expected_base = 0x400000UL + (client == 0U ? 0x40000000UL : 0x80000000UL);
	return_expected_pages = large ? GPU_PRIVATE_BATCH + 1UL : 2UL;
	memset(returned_data, 0, sizeof(returned_data));
	for (unsigned int bad = 0U; bad < 4U; bad++) {
		gpu_firmware_task_finish(&fw_ops, &donated_ops, bad == 0U ? &stranger : &service,
			bad == 1U ? &service : bad == 2U ? other : owner,
			bad == 3U ? token + 1UL : token, &result);
		assert(result.status == GPU_PRIVATE_INPUT && cpu_returns == before &&
			writes == written && control_writes == controls);
	}
	if (test == 5U) fail_cpu_return = cpu_returns + 2U;
	if (test >= 6U && test <= 8U) return_case = test == 8U ? 54U : test + 45U;
	if (test == 42U) {
		assert(alias_revoked && opencca_gpu_service_isolated(&service));
		assert(plat_opencca_gpu_pt_flush_live(words64(registers + at, 0U), as,
			words64(registers + 0x2400U / 4U, 0U)));
		unsigned int after_flush = writes;

		gpu_private_task_return(&donated_ops, &service, owner, context, token, &result);
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_private_task_returned(&service, owner, context, token, &result);
		assert(result.status == GPU_PRIVATE_STATE);
		assert(!gpu_private_task_retire(&service, owner, context, token));
		gpu_firmware_task_return(&fw_ops, &donated_ops, &service, owner, token, &result);
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_firmware_task_retire(&fw_ops, &donated_ops, &service, owner, token, &result);
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_firmware_task_reclaim(&fw_ops, &donated_ops, &service, owner, token, &result);
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_firmware_group_destroy(&donated_ops, owner, group, &result);
		assert(result.status == GPU_PRIVATE_STATE);
		destroy_prepared_bo(owner, prepared_bos[client], &result);
		assert(result.status == GPU_PRIVATE_STATE);
		assert(cpu_returns == before && control_writes == controls && writes == after_flush);
		assert((model_groups[client].input[0] & 7U) == 1U && words64(registers + at, 0U) != 0UL);
		printf("GPU_LIVE_FLUSH_NO_RECLAIM=PASS client=%u live flush cannot return CPU cache, retire, reclaim or destroy; normal real completion still required; MODEL_ONLY\n", client);
	}
	if (test >= 40U && test <= 41U) {
		gpu_firmware_task_complete(&fw_ops, &donated_ops, &service, owner, token, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		if (test == 41U) {
			do { gpu_firmware_task_return(&fw_ops, &donated_ops, &service, owner, token, &result); }
			while (result.status == GPU_PRIVATE_INCOMPLETE);
			assert(result.status == GPU_PRIVATE_SUCCESS);
		}
	}
	track_retire = true; retire_clears = 0U;
	if (live_fault) {
		memcpy(live_snapshot, registers, sizeof(live_snapshot));
		live_flush_corruption = test - 42U;
	}
	mmio_reads = shader_checks = 0U;
	do {
		unsigned int previous = cpu_returns;

		gpu_firmware_task_finish(&fw_ops, &donated_ops, &service, owner, token, &result);
		assert(++calls <= GPU_PRIVATE_TABLES + 3U && cpu_returns - previous <= GPU_PRIVATE_BATCH);
		if (result.status == GPU_PRIVATE_INCOMPLETE) {
			assert(!result.value[0] && result.value[1] == 1UL && !result.value[2] && result.value[3] <= 1UL);
			pending_calls++;
			if (!result.value[3]) {
				assert(test == 3U && cpu_returns == before && words64(registers + at, 0U) != 0UL);
				complete_case = 66U;
				status_cleans = complete_reads_this_call = 0U;
			} else if (large && test != 2U) {
				assert(cpu_returns > before && cpu_returns - before < return_expected_pages);
				/* A proof cannot survive a call boundary. Corrupt stopped
				 * hardware between slices and demand rejection before more data.
				 */
				complete_boundary_case = test == 9U ? 5U : test - 24U;
				complete_boundary_inject(as);
				complete_boundary_case = 0U;
			}
			struct gpu_private_result held;

			gpu_firmware_group_destroy(&donated_ops, owner, group, &held);
			assert(held.status == GPU_PRIVATE_STATE);
			destroy_prepared_bo(owner, prepared_bos[client], &held);
			assert(held.status == GPU_PRIVATE_STATE);
		}
	} while (result.status == GPU_PRIVATE_INCOMPLETE);
	track_retire = false;
	assert(result.status == (success ? GPU_PRIVATE_SUCCESS : GPU_PRIVATE_STATE));
	assert(!retire_clears && control_writes == controls);
	if (success) {
		assert(result.value[0] == 1UL && result.value[1] == 1UL && !result.value[2] && !result.value[3]);
		assert(cpu_returns - before == return_expected_pages);
		for (unsigned int i = 0U; i < return_expected_pages; i++) assert(returned_data[i]);
		if (test == 2U && client == 0U) assert(pending_calls);
		gpu_firmware_task_finish(&fw_ops, &donated_ops, &service, owner, token, &result);
		assert(result.status == GPU_PRIVATE_INPUT);
		gpu_firmware_task_reclaim(&fw_ops, &donated_ops, &service, owner, token, &result);
		assert(result.status == GPU_PRIVATE_INPUT);
		gpu_firmware_group_inspect(&service, owner, group, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_GROUP_RESERVED);
	} else {
		gpu_firmware_group_destroy(&donated_ops, owner, group, &result);
		assert(result.status == GPU_PRIVATE_STATE);
		destroy_prepared_bo(owner, prepared_bos[client], &result);
		assert(result.status == GPU_PRIVATE_STATE);
		if (test >= 10U && test <= 24U) assert(cpu_returns == before);
		if (large) assert(cpu_returns - before < return_expected_pages);
	}
	if (live_fault) {
		assert(cpu_returns == before && as_count == live_commands + 2U);
		assert(as_commands[live_commands] == 2U && as_commands[live_commands + 1U] == 5U);
		unsigned int failed_writes = writes;

		gpu_firmware_task_finish(&fw_ops, &donated_ops, &service, owner, token, &result);
		assert(result.status == GPU_PRIVATE_STATE && cpu_returns == before && writes == failed_writes);
		gpu_firmware_task_return(&fw_ops, &donated_ops, &service, owner, token, &result);
		assert(result.status == GPU_PRIVATE_STATE && cpu_returns == before && writes == failed_writes);
		assert(!gpu_private_task_retire(&service, owner, context, token));
		printf("GPU_LIVE_FLUSH_FAILURE_HOLDS=PASS scenario=%u real FINISH quarantines, CPU/backing/cache/AS/task holds retained, replay read-only; MODEL_ONLY\n", live_flush_corruption);
		/* Remove only test-double faults so the other Client can be checked.
		 * This does not clear the failed context's protected quarantine/holds.
		 */
		live_flush_corruption = 0U;
		memcpy(registers, live_snapshot, sizeof(live_snapshot));
		timer_frequency = live_frequency;
	}
	for (unsigned int i = 0U; i < 2U; i++) {
		if (complete_boundary_fault[i] != NULL) *complete_boundary_fault[i] = complete_boundary_saved[i];
		complete_boundary_fault[i] = NULL;
	}
	if (test == 6U) registers[0x2000U / 4U] = 0U;
	if (test == 7U) registers[at] = 0U;
	if (test == 8U) model_groups[client].cs_output[launch_queue][32] = 0U;
	printf("GPU_TASK_FINISH=PASS case=%u client=%u scenario=%u success=%u calls=%u pending=%u reads=%u checks=%u; MODEL_ONLY\n",
		test, client, scenario, success ? 1U : 0U, calls, pending_calls, mmio_reads, shader_checks);
	(void)context;
}

/* Exercise the internal trusted consumer; no Guest operation exposes DRAIN. */
static void task_drain_backend(unsigned long context, unsigned long group,
		unsigned long token, unsigned int client)
{
	const void *owner = client == 0U ? (void *)&client_a : (void *)&client_b;
	const void *other = client == 0U ? (void *)&client_b : (void *)&client_a;
	struct gpu_private_ops ops = donated_ops;
	struct gpu_private_result r;
	struct gpu_private_command_range range = { .start = 0x100ff8UL, .bytes = 16UL };
	unsigned int test = client == 0U ? drain_case : 1U;
	unsigned int as = model_groups[client].input[20], at = (0x2400U + as * 0x40U) / 4U;
	unsigned int initial_returns = cpu_returns, initial_data = data_syncs, controls = control_writes;
	unsigned int initial_flushes = drain_flushes, initial_commands = as_count;
	unsigned int initial_writes = writes, initial_reads = control_reads;
	uint32_t saved_registers[sizeof(registers) / sizeof(registers[0])];
	unsigned long frequency = timer_frequency;
	unsigned long root = words64(registers + at, 0U);
	bool success = test == 1U || test == 59U || test == 61U;
	bool pending = test >= 3U && test <= 5U;

	memcpy(saved_registers, registers, sizeof(saved_registers));
	for (unsigned int bad = 0U; bad < 4U; bad++) {
		gpu_firmware_task_drain(&fw_ops, &ops, bad == 0U ? &stranger : &service,
			bad == 1U ? &service : bad == 2U ? other : owner,
			bad == 3U ? token + 1UL : token, &r);
		assert(r.status == GPU_PRIVATE_INPUT && writes == initial_writes && control_reads == initial_reads);
	}
	complete_case = test == 3U ? 73U : test == 4U ? 70U : test == 5U ? 71U :
		test == 6U ? 74U : test == 7U ? 68U : test == 8U ? 78U : 66U;
	if (test == 9U) ops.flush_as = NULL;
	if (test == 10U) fail_as_command = 5U;
	if (test == 11U) drain_barrier_failure = true;
	if (test >= 12U && test <= 40U) live_flush_corruption = test - 11U;
	if (test >= 41U && test <= 58U) drain_post_corruption = test - 40U;
	gpu_firmware_task_drain(&fw_ops, &ops, &service, owner, token, &r);
	assert(r.status == (success ? GPU_PRIVATE_SUCCESS : pending ? GPU_PRIVATE_INCOMPLETE : GPU_PRIVATE_STATE));
	assert(cpu_returns == initial_returns && data_syncs == initial_data && control_writes == controls);
	assert((model_groups[client].input[0] & 7U) == 1U); /* Never SUSPEND. */
	unsigned int added_commands = as_count - initial_commands;

	assert(added_commands == 0U || added_commands == 2U);
	if (added_commands != 0U) {
		assert(as_commands[initial_commands] == 2U && as_commands[initial_commands + 1U] == 5U);
	}
	if (test == 2U || test == 9U)
		assert(writes == initial_writes && control_reads == initial_reads && drain_flushes == initial_flushes);
	if (pending || (test >= 6U && test <= 8U))
		assert(drain_flushes == initial_flushes);
	if (success) {
		assert(r.value[0] == 1UL && r.value[1] == 1UL && r.value[2] == 2UL && !r.value[3]);
		assert(drain_flushes == initial_flushes + 1U && words64(registers + at, 0U) == root);
		assert(gpu_private_task_live_eligible(&ops, &service, owner, context, token));
		assert(!gpu_private_task_hold_batch(&ops, &service, owner, context, &range, 1U));
		assert(!gpu_private_task_put(owner, context));
		assert(!gpu_private_task_put_live(&ops, &service, owner, context, token));
		assert(gpu_private_task_hold_live(&ops, &service, owner, context, token, &range, 1U));
		assert(gpu_private_task_put_live(&ops, &service, owner, context, token));
		/* A replay must request fresh STATUS and reflush, not reuse proof. */
		status_cleans = complete_reads_this_call = 0U;
		unsigned int replay_writes = writes;

		gpu_firmware_task_drain(&fw_ops, &ops, &service, owner, token, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS && writes > replay_writes && drain_flushes == initial_flushes + 2U);
		if (test == 61U) {
			struct gpu_private_ops missing = ops;

			missing.flush_as = NULL;
			unsigned int previous_writes = writes;
			gpu_firmware_task_drain(&fw_ops, &missing, &service, owner, token, &r);
			assert(r.status == GPU_PRIVATE_STATE && writes == previous_writes);
			assert(!gpu_private_task_hold_live(&ops, &service, owner, context, token, &range, 1U));
		}
		if (test == 59U) {
			complete_case = 70U;
			status_cleans = complete_reads_this_call = 0U;
			gpu_firmware_task_drain(&fw_ops, &ops, &service, owner, token, &r);
			assert(r.status == GPU_PRIVATE_INCOMPLETE && drain_flushes == initial_flushes + 2U);
			assert(!gpu_private_task_hold_live(&ops, &service, owner, context, token, &range, 1U));
			complete_case = 66U;
			status_cleans = complete_reads_this_call = 0U;
			gpu_firmware_task_drain(&fw_ops, &ops, &service, owner, token, &r);
			assert(r.status == GPU_PRIVATE_SUCCESS && drain_flushes == initial_flushes + 3U);
		}
	} else {
		assert(!gpu_private_task_hold_live(&ops, &service, owner, context, token, &range, 1U));
	}
	/* Draining never authorizes externally visible completion or reclamation. */
	gpu_firmware_task_return(&fw_ops, &ops, &service, owner, token, &r);
	assert(r.status == GPU_PRIVATE_STATE);
	gpu_firmware_task_retire(&fw_ops, &ops, &service, owner, token, &r);
	assert(r.status == GPU_PRIVATE_STATE);
	gpu_firmware_task_reclaim(&fw_ops, &ops, &service, owner, token, &r);
	assert(r.status == GPU_PRIVATE_STATE);
	gpu_firmware_group_destroy(&ops, owner, group, &r);
	assert(r.status == GPU_PRIVATE_STATE);
	destroy_prepared_bo(owner, prepared_bos[client], &r);
	assert(r.status == GPU_PRIVATE_STATE);
	assert(cpu_returns == initial_returns && control_writes == controls);
	if (success) {
		/* The unchanged real FINISH can still stop, detach and retire it. */
		status_cleans = complete_reads_this_call = 0U;
		track_retire = true; retire_clears = 0U;
		do { gpu_firmware_task_finish(&fw_ops, &ops, &service, owner, token, &r); }
		while (r.status == GPU_PRIVATE_INCOMPLETE);
		track_retire = false;
		assert(r.status == GPU_PRIVATE_SUCCESS && !retire_clears && cpu_returns == initial_returns);
	}
	/* Undo only injected model faults for the independent second Client.
	 * Protected quarantine/task/BO references are left intact until reset.
	 */
	if (drain_fault != NULL) *drain_fault = drain_fault_saved;
	drain_fault = NULL;
	live_flush_corruption = drain_post_corruption = fail_as_command = 0U;
	drain_barrier_failure = false;
	memcpy(registers, saved_registers, sizeof(saved_registers));
	if (success) registers[at] = registers[at + 1U] = 0U; /* Real FINISH detached this AS. */
	timer_frequency = frequency;
	printf("GPU_TASK_DRAIN=PASS case=%u client=%u success=%u pending=%u actual STATUS/idle/flush/postcheck, unchanged external completion; MODEL_ONLY\n",
		test, client, success, pending);
}

/* Advance only the protected INSERTs actually published by the RMM.
 * This double never manufactures a Client-selected completion or reset root.
 */
static void model_domain_ack(void)
{
	unsigned long root = words64(registers + 0x2400U / 4U, 0U);

	for (unsigned int g = 0U; g < model_group_count; g++) {
		uint32_t *in = model_groups[g].input, *out = model_groups[g].output;
		uint32_t parent = 1U << g;

		if (((model_glb_in[2] ^ model_glb_out[2]) & parent) == 0U)
			continue;
		bool status = ((in[0] ^ out[0]) & (1U << 5U)) != 0U;
		bool stopped = (in[0] & 7U) == 2U || (in[0] & 7U) == 0U;

		assert(in[20] != 0U && words64(registers + (0x2400U + in[20] * 0x40U) / 4U, 0U) != 0UL);
		for (unsigned int q = 0U; q < 2U; q++) {
			uint32_t *cs_in = model_groups[g].cs_input[q], *cs_out = model_groups[g].cs_output[q];
			uint64_t input_va = words64(cs_in, 12U), output_va = words64(cs_in, 14U);

			assert(input_va != 0UL && output_va != 0UL);
			uint64_t *input = (void *)(uintptr_t)(*firmware_leaf(root, input_va) & UINT64_C(0x000000fffffff000));
			uint64_t *output = (void *)(uintptr_t)(*firmware_leaf(root, output_va) & UINT64_C(0x000000fffffff000));
			if (status) {
				output[0] = input[0];
				if (input[0] != 0UL) {
					unsigned long client_root = words64(registers + (0x2400U + in[20] * 0x40U) / 4U, 0U);
					uint64_t ring_va = words64(cs_in, 4U);
					uint64_t offset = (input[0] - 128U) & (cs_in[6] - 1U);
					uint64_t ring_pa = software_leaf(client_root, ring_va + offset) & UINT64_C(0x000000fffffff000);
					const uint64_t *wrapper = (void *)(uintptr_t)(ring_pa + offset % 4096U);
					uint64_t sync_va = wrapper[6] & UINT64_C(0x0000ffffffffffff);
					uint64_t sync_pa = software_leaf(client_root, sync_va) & UINT64_C(0x000000fffffff000);
					uint64_t *sync = (void *)(uintptr_t)(sync_pa + sync_va % 4096U);

					sync[0] = input[0] / 128U;
					sync[1] = 0UL;
				}
				cs_out[23] = cs_out[24] = 0U;
			}
			if (!stopped) cs_out[0] = cs_in[0];
		}
		out[0] = in[0];
		out[2] = in[2];
		model_glb_out[2] = (model_glb_out[2] & ~parent) | (model_glb_in[2] & parent);
	}
}


#ifdef GPU_DOMAIN_RSI_TEST
#include "opencca_gpu_domain_rsi_test.h"
#endif

/* Public operations must reject an externally retired token without touching
 * hardware or releasing even one internal anchor/BO reference. */
static void domain_old_token(const void *owner, unsigned long context,
		unsigned long group, unsigned long token)
{
	struct gpu_private_result r;
	struct gpu_firmware_task_resources resources;
	unsigned int written = writes, controls = control_writes, reads = control_reads;

	assert(!gpu_firmware_task_resources(&service, owner, token, &resources));
	for (unsigned int op = 0U; op < 17U; op++) {
		switch (op) {
		case 0U: gpu_firmware_task_validate(&service, owner, context, group, token, &r); break;
		case 1U: gpu_firmware_task_prepare(&fw_ops, &donated_ops, &service, owner, context, group, token, &r); break;
		case 2U: gpu_firmware_task_prepare_launch(&fw_ops, &donated_ops, &service, owner, context, group, token, &r); break;
		case 3U: gpu_firmware_task_ready(&fw_ops, &donated_ops, &service, owner, token, &r); break;
		case 4U: gpu_firmware_task_ready_publish(&fw_ops, &donated_ops, &service, owner, token, &r); break;
		case 5U: gpu_firmware_task_ready_launch(&fw_ops, &donated_ops, &service, owner, token, &r); break;
		case 6U: gpu_firmware_task_publish(&fw_ops, &donated_ops, &service, owner, token, 1UL, &r); break;
		case 7U: gpu_firmware_task_start(&fw_ops, &donated_ops, &service, owner, context, group, token, &r); break;
		case 8U: gpu_firmware_task_quiesce(&fw_ops, &donated_ops, &service, owner, context, group, token, &r); break;
		case 9U: gpu_firmware_task_complete(&fw_ops, &donated_ops, &service, owner, token, &r); break;
		case 10U: gpu_firmware_task_progress(&fw_ops, &donated_ops, &service, owner, token, &r); break;
		case 11U: gpu_firmware_task_return(&fw_ops, &donated_ops, &service, owner, token, &r); break;
		case 12U: gpu_firmware_task_retire(&fw_ops, &donated_ops, &service, owner, token, &r); break;
		case 13U: gpu_firmware_task_reclaim(&fw_ops, &donated_ops, &service, owner, token, &r); break;
		case 14U: gpu_firmware_task_finish_domain(&fw_ops, &donated_ops, &service, owner, token, &r); break;
		case 15U: gpu_firmware_task_cancel_staged(&donated_ops, owner, token, &r); break;
		case 16U: gpu_firmware_task_heap_event(&fw_ops, &donated_ops, &service, owner, token, &r); break;
		default: assert(false);
		}
		assert(r.status == GPU_PRIVATE_INPUT && writes == written &&
			control_writes == controls && control_reads == reads);
	}
}

static void domain_bind_model(void)
{
	unsigned long root = words64(registers + 0x2400U / 4U, 0U);

	for (unsigned int g = 0U; g < model_group_count; g++) {
		unsigned long va = words64(model_groups[g].cs_input[1], 12U);

		if (va != 0UL && (*firmware_leaf(root, va) & UINT64_C(0x000000fffffff000)) == complete_read_pa[0]) {
			launch_csg = g;
			return;
		}
	}
	assert(false);
}

static void task_domain_adversarial(unsigned long context, unsigned long group,
		unsigned long token, unsigned int client)
{
	const void *owner = client == 0U ? (void *)&client_a : (void *)&client_b;
	struct gpu_private_result r;
	struct gpu_firmware_task_command commands[2] = {
		{ .start = 0x100000UL, .bytes = 64U, .queue = 1U },
		{ .start = 0x100040UL, .bytes = 64U, .queue = 1U }
	};
	unsigned int scenario = domain_case;
	unsigned int as = model_groups[launch_csg].input[20];
	unsigned int at = (0x2400U + as * 0x40U) / 4U;
	unsigned long root = words64(registers + at, 0U);
	uint64_t *input = (void *)(uintptr_t)complete_read_pa[0];

	domain_active = true;
	gpu_firmware_task_finish_domain(&fw_ops, &donated_ops, &service, owner, token, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS && r.value[0] == 1UL && words64(registers + at, 0U) == root);
	domain_old_token(owner, context, group, token);
#ifdef GPU_DOMAIN_RSI_TEST
	unsigned int previous = writes;
	domain_disconnected = true;
	domain_rsi_stage(&fw_ops, &donated_ops, &service, owner, group, commands, 2U,
		GPU_PRIVATE_TASK_DEFERRED, &r);
	assert(r.status == GPU_PRIVATE_INPUT && writes == previous);
	domain_disconnected = false;
	domain_input_fault = true;
	domain_rsi_stage(&fw_ops, &donated_ops, &service, owner, group, commands, 2U,
		GPU_PRIVATE_TASK_DEFERRED, &r);
	assert(r.status == GPU_PRIVATE_INPUT && writes == previous);
	domain_input_fault = false;
	domain_rsi_call(&service, GPU_PRIVATE_TASK_FINISH, token, client == 0U ? 7UL : 8UL,
		0, 0, 0, 0, &r);
	assert(r.status == GPU_PRIVATE_INPUT && writes == previous);
#endif
	if (scenario >= 21U && scenario <= 24U) {
		unsigned int before = writes;
		unsigned long prot = GPU_PRIVATE_READ | GPU_PRIVATE_CACHE;
#ifdef GPU_DOMAIN_RSI_TEST
		unsigned long op = scenario == 21U ? GPU_PRIVATE_MAP_AUTHORIZE :
			scenario == 22U ? GPU_PRIVATE_SERVICE_UNMAP : scenario == 23U ?
			GPU_PRIVATE_GROUP_CREATE : GPU_PRIVATE_GROUP_CONFIGURE;
		if (scenario == 21U) {
			domain_rsi_call(owner, op, context, prepared_bos[client], 0, 0x200000UL, 1, prot, &r);
			assert(r.status == GPU_PRIVATE_SUCCESS && words64(registers + at, 0U) == 0UL);
			unsigned long grant = r.value[0];

			domain_rsi_call(&service, GPU_PRIVATE_SERVICE_MAP, context, client == 0U ? 7UL : 8UL,
				grant, 0, 0x200000UL, (1UL << 8U) | prot, &r);
		} else if (scenario == 22U) {
			domain_rsi_call(&service, op, context, client == 0U ? 7UL : 8UL, 0x100000UL, 2, 0, 0, &r);
		} else if (scenario == 23U) {
			domain_rsi_call(owner, op, context, 7, 2, 0, 0, 0, &r);
		} else {
			struct gpu_firmware_queue_config queues[2] = {{.ring_bytes = 4096U}, {.ring_bytes = 4096U}};

			domain_rsi_call(owner, op, group, (unsigned long)(uintptr_t)queues, 7, 2, 0, 0, &r);
		}
#else
		gpu_firmware_context_yield(&fw_ops, &donated_ops, owner, context, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS);
		if (scenario == 21U) {
			gpu_private_map_authorize(owner, context, prepared_bos[client], 0, 0x200000UL, 1, prot, &r);
			assert(r.status == GPU_PRIVATE_SUCCESS);
			gpu_private_service_map(&donated_ops, &service, owner, context, r.value[0], 0, 0x200000UL, 1, prot, &r);
		} else if (scenario == 22U) {
			gpu_private_service_unmap(&donated_ops, &service, owner, context, 0x100000UL, 2, &r);
		} else if (scenario == 23U) {
			gpu_firmware_group_create(&fw_ops, &donated_ops, &service, owner, context, 2, &r);
		}
#endif
		assert(words64(registers + at, 0U) == 0UL && writes > before);
		if (scenario != 24U) assert(r.status == GPU_PRIVATE_SUCCESS);
		goto done;
	}
	if (scenario == 20U) {
		if (client == 0U) {
			domain_idle_group = group;
			goto done; /* Remains an idle, internal-only domain. */
		}
		gpu_firmware_context_yield(&fw_ops, &donated_ops, owner, context, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS && words64(registers + at, 0U) == 0UL);
		gpu_firmware_task_stage_domain(&fw_ops, &donated_ops, &service, owner, group,
			commands, 2U, GPU_PRIVATE_TASK_DEFERRED, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS);
		unsigned long next = r.value[0];

		gpu_firmware_task_prepare_launch(&fw_ops, &donated_ops, &service, owner, context, group, next, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS);
		domain_bind_model();
		gpu_firmware_group_inspect(&service, &client_a, domain_idle_group, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS && r.value[0] == GPU_FIRMWARE_GROUP_RESERVED);
		/* Real cold admission stopped the other idle Client domain before
		 * reusing its CSG/AS, rather than assigning a live slot twice. */
		goto done;
	}
	if (scenario >= 15U && scenario <= 19U) {
		unsigned int before = writes;
#ifdef GPU_DOMAIN_RSI_TEST
		unsigned long op = scenario == 15U ? GPU_PRIVATE_UNMAP : scenario == 16U ?
			GPU_PRIVATE_UNMAP_BO : scenario == 17U ? GPU_PRIVATE_CONTEXT_DESTROY :
			scenario == 18U ? GPU_PRIVATE_GROUP_DESTROY : GPU_PRIVATE_MAP;
		unsigned long a = scenario == 15U ? 0x100000UL : scenario == 16U || scenario == 19U ? prepared_bos[client] : 0UL;
		unsigned long b = scenario == 15U ? 2UL : 0UL;
		domain_rsi_call(owner, op, scenario == 18U ? group : context, a, b, 0, 0, 0, &r);
#else
		gpu_firmware_context_yield(&fw_ops, &donated_ops, owner, context, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS);
		if (scenario == 15U) gpu_private_unmap(&donated_ops, owner, context, 0x100000UL, 2UL, &r);
		if (scenario == 16U) gpu_private_unmap_bo(&donated_ops, owner, context, prepared_bos[client], 0, 0, 0, &r);
		if (scenario == 17U) gpu_private_context_destroy(&donated_ops, owner, context, &r);
		if (scenario == 18U) gpu_firmware_group_destroy(&donated_ops, owner, group, &r);
		if (scenario == 19U) gpu_private_map(&donated_ops, owner, context, prepared_bos[client], 0, 0, 0, 0, &r);
#endif
		assert(words64(registers + at, 0U) == 0UL && writes > before && !cpu_returns);
		/* CONTEXT_DESTROY still rejects live mappings/groups; malformed
		 * MAP/UNMAP_BO still rejects its own arguments after trusted yield. */
		if (scenario == 15U || scenario == 18U) assert(r.status == GPU_PRIVATE_SUCCESS);
		if (scenario == 17U || scenario == 19U) assert(r.status != GPU_PRIVATE_SUCCESS);
		goto done;
	}
	unsigned int before = writes, controls = control_writes;
	/* Invalid identity/command requests must not turn into a trusted yield. */
	for (unsigned int bad = 0U; bad < 4U; bad++) {
		commands[0].pad = bad == 2U ? 1U : 0U;
		gpu_firmware_task_stage_domain(&fw_ops, &donated_ops, bad == 0U ? &stranger : &service,
			bad == 1U ? &stranger : owner, group, commands, 2U,
			bad == 3U ? 2UL : GPU_PRIVATE_TASK_DEFERRED, &r);
		assert(r.status == GPU_PRIVATE_INPUT && writes == before && control_writes == controls);
	}
	commands[0].pad = 0U;
	if (scenario == 13U) commands[0].queue = commands[1].queue = 0U; /* New active queue. */
	unsigned long flags = scenario == 14U ? 0UL : GPU_PRIVATE_TASK_DEFERRED;
	gpu_firmware_task_stage_domain(&fw_ops, &donated_ops, &service, owner, group, commands, 2U, flags, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	unsigned long next = r.value[0];

	if (scenario == 13U || scenario == 14U) {
		/* These commands cannot append to the running domain. Yield before
		 * ordinary staging, with the old AS disabled and original leases put. */
		assert(words64(registers + at, 0U) == 0UL && writes > before);
		gpu_firmware_group_inspect(&service, owner, group, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS && r.value[0] == GPU_FIRMWARE_GROUP_RESERVED);
		if (scenario == 13U) {
			gpu_firmware_task_prepare_launch(&fw_ops, &donated_ops, &service, owner, context, group, next, &r);
			assert(r.status == GPU_PRIVATE_SUCCESS);
			domain_bind_model();
			do { gpu_firmware_task_ready_launch(&fw_ops, &donated_ops, &service, owner, next, &r); }
			while (r.status == GPU_PRIVATE_INCOMPLETE);
			assert(r.status == GPU_PRIVATE_SUCCESS);
			gpu_firmware_task_finish_domain(&fw_ops, &donated_ops, &service, owner, next, &r);
			assert(r.status == GPU_PRIVATE_SUCCESS);
			gpu_firmware_context_yield(&fw_ops, &donated_ops, owner, context, &r);
			assert(r.status == GPU_PRIVATE_SUCCESS);
		} else {
			gpu_firmware_task_cancel_staged(&donated_ops, owner, next, &r);
			assert(r.status == GPU_PRIVATE_SUCCESS);
		}
		goto done;
	}
	before = writes;
	gpu_firmware_context_yield(&fw_ops, &donated_ops, owner, context, &r);
	assert(r.status == GPU_PRIVATE_STATE && writes == before);
	gpu_firmware_group_yield(&fw_ops, &donated_ops, owner, group, &r);
	assert(r.status == GPU_PRIVATE_STATE && writes == before);
#ifdef GPU_DOMAIN_RSI_TEST
	/* A pending successor is not an idle domain. In particular, a rejected
	 * yield must not nevertheless create a grant that pins pending forever. */
	domain_rsi_call(owner, GPU_PRIVATE_MAP_AUTHORIZE, context, prepared_bos[client],
		0, 0x200000UL, 1, GPU_PRIVATE_READ | GPU_PRIVATE_CACHE, &r);
	assert(r.status == GPU_PRIVATE_STATE && !r.value[0] && writes == before);
#endif
	/* No second staged successor, and no Client claiming the Proxy role. */
	gpu_firmware_task_stage_domain(&fw_ops, &donated_ops, &service, owner, group, commands, 2U, flags, &r);
	assert(r.status == GPU_PRIVATE_STATE && writes == before);
	if (scenario == 2U) {
		gpu_firmware_task_cancel_staged(&donated_ops, owner, next, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS);
		gpu_firmware_context_yield(&fw_ops, &donated_ops, owner, context, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS && words64(registers + at, 0U) == 0UL);
		goto done;
	}
	uint64_t insert = input[0], origin = input[1];
	if (scenario == 3U || scenario == 4U) fail_control_write = control_writes + scenario - 2U;
	if (scenario >= 5U && scenario <= 9U) domain_write_fault = scenario - 4U;
	if (scenario >= 25U && scenario <= 45U) domain_write_fault = scenario - 19U;
	/* Cross-call certificate reuse must reject corruption before writing a
	 * successor, including roots changing after the last snapshot copy. */
	if (scenario >= 46U && scenario <= 63U) drain_corrupt_controls(scenario - 45U);
	if (scenario >= 64U && scenario <= 66U) {
		domain_read_fault = scenario - 63U;
		domain_reads_until_fault = 3U;
	}
	if (scenario == 67U)
		gpu_private_task_clear_drained(&service, owner, context, token);
	unsigned int prepare_controls = control_writes, prepare_flushes = drain_flushes;
	assert(!gpu_private_task_is_drained(&donated_ops, &stranger, owner, context, token));
	assert(!gpu_private_task_is_drained(&donated_ops, &service, &stranger, context, token));
	assert(!gpu_private_task_is_drained(&donated_ops, &service, owner, context, next));
	gpu_firmware_task_prepare_launch(&fw_ops, &donated_ops, &service, owner, context, group, next, &r);
	if (scenario >= 25U) {
		if (scenario >= 46U)
			assert(control_writes == prepare_controls && drain_flushes == prepare_flushes);
		if (domain_write_fault != 0U || domain_read_fault != 0U)
			fprintf(stderr, "DOMAIN_HANDOFF_INJECTION case=%u client=%u write=%u read=%u status=%lu\n",
				scenario, client, domain_write_fault, domain_read_fault, r.status);
		assert(domain_write_fault == 0U && domain_read_fault == 0U);
	}
	if (scenario <= 9U || scenario >= 25U) {
		assert(r.status == GPU_PRIVATE_STATE);
		gpu_firmware_group_inspect(&service, owner, group, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS && r.value[0] == GPU_FIRMWARE_GROUP_QUARANTINED);
		assert(!gpu_private_task_is_drained(&donated_ops, &service, owner, context, token));
		if (drain_fault != NULL) *drain_fault = drain_fault_saved;
		drain_fault = NULL;
		assert(input[0] == insert && input[1] == origin && words64(registers + at, 0U) == root);
		gpu_firmware_task_cancel_staged(&donated_ops, owner, next, &r);
		assert(r.status == GPU_PRIVATE_STATE);
		gpu_firmware_context_yield(&fw_ops, &donated_ops, owner, context, &r);
		assert(r.status == GPU_PRIVATE_STATE);
		gpu_firmware_group_destroy(&donated_ops, owner, group, &r);
		assert(r.status == GPU_PRIVATE_STATE);
		destroy_prepared_bo(owner, prepared_bos[client], &r);
		assert(r.status == GPU_PRIVATE_STATE);
		goto done;
	}
	assert(r.status == GPU_PRIVATE_SUCCESS && input[0] == insert && input[1] == origin);
	before = writes;
	gpu_firmware_task_start(&fw_ops, &donated_ops, &service, owner, context, group, next, &r);
	assert(r.status == GPU_PRIVATE_STATE && writes == before);
	gpu_firmware_task_prepare_launch(&fw_ops, &donated_ops, &service, owner, context, group, next, &r);
	assert(r.status == GPU_PRIVATE_STATE && writes == before);
	if (scenario == 10U) {
		/* Client can disappear before READY: references cannot be cancelled,
		 * yielded or destroyed as though this preparation never happened. */
		gpu_firmware_task_cancel_staged(&donated_ops, owner, next, &r);
		assert(r.status == GPU_PRIVATE_STATE);
		gpu_firmware_context_yield(&fw_ops, &donated_ops, owner, context, &r);
		assert(r.status == GPU_PRIVATE_STATE && input[0] == insert);
		goto done;
	}
	if (scenario == 11U) fail_control_write = control_writes + 1U; /* Partial producer publication. */
	if (scenario == 12U) domain_write_fault = 1U; /* Root changes during producer publication. */
	do { gpu_firmware_task_ready_launch(&fw_ops, &donated_ops, &service, owner, next, &r); }
	while (r.status == GPU_PRIVATE_INCOMPLETE);
	assert(r.status == GPU_PRIVATE_STATE && input[1] == origin);
	if (drain_fault != NULL) *drain_fault = drain_fault_saved;
	drain_fault = NULL;
	gpu_firmware_task_cancel_staged(&donated_ops, owner, next, &r);
	assert(r.status == GPU_PRIVATE_STATE);
	gpu_firmware_context_yield(&fw_ops, &donated_ops, owner, context, &r);
	assert(r.status == GPU_PRIVATE_STATE);
	done:
	fail_control_write = domain_write_fault = domain_read_fault = domain_reads_until_fault = 0U;
	assert(!cpu_returns);
	domain_active = false;
	printf("GPU_TASK_DOMAIN_ADVERSARIAL=PASS case=%u client=%u old-token denial, readiness/lease retention and actual publication boundaries; MODEL_ONLY\n", scenario, client);
}

static void task_domain_backend(unsigned long context, unsigned long group,
		unsigned long token, unsigned int client)
{
	const void *owner = client == 0U ? (void *)&client_a : (void *)&client_b;
	struct gpu_private_result r;
	struct gpu_firmware_task_resources resources;
	struct gpu_firmware_task_command command = { .start = 0x100000UL, .bytes = 64U, .queue = 1U };
	unsigned int as = model_groups[launch_csg].input[20], at = (0x2400U + as * 0x40U) / 4U;
	unsigned int kept = 0U, yielded = 0U;

	if (domain_case != 1U) {
		task_domain_adversarial(context, group, token, client);
		return;
	}
	domain_active = true;
	/* An empty allocated group and rejected submissions are not competitors.
	 * After the bounded run, admit its real task and demand immediate yield.
	 * Client 0 uses the other owner; Client 1 uses another group of itself.
	 */
	const void *waiter_owner = &client_b;
	struct gpu_firmware_queue_config waiter_queue = { .ring_bytes = 4096U, .priority = 0U };
	struct gpu_firmware_task_command waiter_command = {0};

	gpu_private_context_create(&donated_ops, waiter_owner, &service, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	unsigned long waiter_context = r.value[0];

	gpu_firmware_group_create(&fw_ops, &donated_ops, &service, waiter_owner, waiter_context, 1UL, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	unsigned long waiter_group = r.value[0];

	gpu_firmware_group_configure(&donated_ops, &service, waiter_owner, waiter_group, &waiter_queue, 1UL, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	unsigned int rejected_writes = writes;
	for (unsigned int bad = 0U; bad < 3U; bad++) {
		waiter_command.pad = bad == 2U ? 1U : 0U;
		gpu_firmware_task_stage_domain(&fw_ops, &donated_ops, bad == 0U ? &stranger : &service,
			bad == 1U ? &client_a : waiter_owner, waiter_group, &waiter_command, 1U,
			GPU_PRIVATE_TASK_DEFERRED, &r);
		assert(r.status == GPU_PRIVATE_INPUT && writes == rejected_writes);
	}
	waiter_command.pad = 0U;
	for (unsigned int cycle = 0U; cycle < 96U; cycle++) {
		unsigned int before = as_count, controls = control_writes;
		gpu_firmware_task_finish_domain(&fw_ops, &donated_ops, &service, owner, token, &r);
		if (r.status != GPU_PRIVATE_SUCCESS)
			fprintf(stderr, "DOMAIN_FIXTURE client=%u cycle=%u status=%lu values=%lu/%lu/%lu/%lu req=%x ack=%x parent=%x/%x eligible=%u\n", client, cycle, r.status,
				r.value[0], r.value[1], r.value[2], r.value[3], model_groups[launch_csg].input[0], model_groups[launch_csg].output[0], model_glb_in[2], model_glb_out[2],
				gpu_private_task_live_eligible(&donated_ops, &service, owner, context, token));
		assert(r.status == GPU_PRIVATE_SUCCESS && r.value[0] == 1UL && r.value[1] == 1UL && !r.value[2] && !r.value[3]);
		assert(control_writes == controls && !cpu_returns);
		bool live = (model_groups[launch_csg].input[0] & 7U) != 2U;

		if (live) {
			assert(as_count == before + 2U && words64(registers + at, 0U) != 0UL);
			kept++;
		} else {
			assert(as_count == before + 3U && words64(registers + at, 0U) == 0UL);
			yielded++;
		}
		before = writes;
		/* Old handles remain unusable even while their internal lease lives. */
		assert(!gpu_firmware_task_resources(&service, owner, token, &resources));
		gpu_firmware_task_finish_domain(&fw_ops, &donated_ops, &service, owner, token, &r);
		assert(r.status == GPU_PRIVATE_INPUT);
		gpu_firmware_task_progress(&fw_ops, &donated_ops, &service, owner, token, &r);
		assert(r.status == GPU_PRIVATE_INPUT);
		gpu_firmware_task_cancel_staged(&donated_ops, owner, token, &r);
		assert(r.status == GPU_PRIVATE_INPUT && writes == before);
		bool delegate = live && (cycle & 1U) == 0U;
		gpu_firmware_task_stage_domain(&fw_ops, &donated_ops, &service, owner, group,
			&command, 1U, GPU_PRIVATE_TASK_DEFERRED | (delegate ? GPU_PRIVATE_TASK_DELEGATE : 0UL), &r);
		assert(r.status == GPU_PRIVATE_SUCCESS);
		unsigned long next = r.value[0];

		assert(next != token && gpu_firmware_task_resources(&service, owner, next, &resources));
		if (cycle == 0U) {
			gpu_firmware_task_cancel_staged(&donated_ops, owner, next, &r);
			assert(r.status == GPU_PRIVATE_SUCCESS);
			gpu_firmware_task_stage_domain(&fw_ops, &donated_ops, &service, owner, group,
				&command, 1U, GPU_PRIVATE_TASK_DEFERRED | (delegate ? GPU_PRIVATE_TASK_DELEGATE : 0UL), &r);
			assert(r.status == GPU_PRIVATE_SUCCESS);
			next = r.value[0];
		}
		uint64_t *input = (void *)(uintptr_t)complete_read_pa[0];
		uint64_t origin = input[1], insert = input[0];
		unsigned int before_prepare_flushes = drain_flushes, before_prepare_commands = as_count;
        if (delegate) {
            gpu_firmware_task_dispatch(&fw_ops, &donated_ops, &service, owner,
                context, group, next, &r);
            assert(r.status == GPU_PRIVATE_SUCCESS && r.value[0] == GPU_FIRMWARE_GROUP_STARTED &&
                r.value[1] == 1UL && !r.value[2] && !r.value[3]);
            assert(input[1] == origin && input[0] == insert + 128U &&
                drain_flushes == before_prepare_flushes && as_count == before_prepare_commands);
            unsigned int published = writes;
            gpu_firmware_task_dispatch(&fw_ops, &donated_ops, &service, owner,
                context, group, next, &r);
            assert(r.status == GPU_PRIVATE_STATE && writes == published);
            token = next;
            continue;
        }
		gpu_firmware_task_prepare_launch(&fw_ops, &donated_ops, &service, owner,
			context, group, next, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS);
		/* A cold resume may choose a different real CSG and AS. Bind the
		 * device double from actual protected IO mappings, not Client index.
		 */
		bool found = false;
		for (unsigned int g = 0U; g < model_group_count; g++) {
			unsigned long va = words64(model_groups[g].cs_input[1], 12U);
			unsigned long root = words64(registers + 0x2400U / 4U, 0U);

			if (va != 0UL && (*firmware_leaf(root, va) & UINT64_C(0x000000fffffff000)) == complete_read_pa[0]) {
				launch_csg = g;
				as = model_groups[g].input[20];
				at = (0x2400U + as * 0x40U) / 4U;
				found = true;
				break;
			}
		}
		assert(found);
		if (live) {
			assert(input[1] == origin && input[0] == insert);
			assert(drain_flushes == before_prepare_flushes && as_count == before_prepare_commands);
			assert(!gpu_private_task_is_drained(&donated_ops, &service, owner, context, token));
			assert(!gpu_private_task_is_drained(&donated_ops, &service, owner, context, next));
		}
		/* Until READY, neither a trusted selection nor a new token publishes. */
		before = writes;
		gpu_firmware_task_start(&fw_ops, &donated_ops, &service, owner, context, group, next, &r);
		assert(r.status == GPU_PRIVATE_STATE && writes == before);
		do { gpu_firmware_task_ready_launch(&fw_ops, &donated_ops, &service, owner, next, &r); }
		while (r.status == GPU_PRIVATE_INCOMPLETE);
		assert(r.status == GPU_PRIVATE_SUCCESS && r.value[0] == 1UL && !r.value[2]);
		if (live) assert(input[1] == origin && input[0] == insert + 128U);
		token = next;
	}
	/* Client 0 still competes with Client 1's running task. After Client 0
	 * retires, Client 1 is alone even though the empty group still exists.
	 */
	assert(kept == (client == 0U ? 84U : 93U) && yielded == (client == 0U ? 12U : 3U));
	gpu_firmware_task_stage_domain(&fw_ops, &donated_ops, &service, waiter_owner,
		waiter_group, &waiter_command, 1U, GPU_PRIVATE_TASK_DEFERRED, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	unsigned long waiting_token = r.value[0];
	unsigned int before_waiter_finish = as_count;

	gpu_firmware_task_finish_domain(&fw_ops, &donated_ops, &service, owner, token, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS && as_count == before_waiter_finish + 3U &&
		words64(registers + at, 0U) == 0UL); /* No 8/32-batch postponement. */
	domain_old_token(owner, context, group, token);
	gpu_firmware_task_cancel_staged(&donated_ops, waiter_owner, waiting_token, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	gpu_firmware_group_destroy(&donated_ops, waiter_owner, waiter_group, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	gpu_private_context_destroy(&donated_ops, waiter_owner, waiter_context, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	gpu_firmware_context_yield(&fw_ops, &donated_ops, owner, context, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS && words64(registers + at, 0U) == 0UL);
	gpu_firmware_group_inspect(&service, owner, group, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS && r.value[0] == GPU_FIRMWARE_GROUP_RESERVED);
	domain_active = false;
	printf("GPU_TASK_DOMAIN=PASS client=%u cycles=96 kept=%u forced_yield=%u quantum=solo32/shared8/waiter1, empty/rejected requests ignored, actual FINISH/Client READY/Proxy selection, monotonic ring wrap, frozen EXTRACT_INIT, old-token denial and trusted yield; MODEL_ONLY\n", client, kept, yielded);
}

#ifdef GPU_DOMAIN_RSI_TEST
#undef gpu_firmware_task_finish_domain
#undef gpu_firmware_task_stage_domain
#undef gpu_firmware_task_prepare_launch
#undef gpu_firmware_task_ready_launch
#undef gpu_firmware_task_dispatch
#undef gpu_firmware_task_cancel_staged
#endif

static void task_complete_backend(unsigned long contexts[2], unsigned long groups[2],
		unsigned long tokens[2], unsigned int count, unsigned int scenario)
{
	const void *owners[2] = { &client_a, &client_b };
	struct gpu_private_result result;
	unsigned long root = words64(registers + 0x2400U / 4U, 0U);

	for (unsigned int i = 0U; i < count; i++) {
		unsigned int as = model_groups[i].input[20], at = (0x2400U + as * 0x40U) / 4U;
		unsigned long client_root = words64(registers + at, 0U);
		unsigned int before = writes, commands_before = as_count, reads_before = control_reads;
		unsigned int data_before = data_syncs, control_before = control_writes;
		bool pending = (scenario >= 70U && scenario <= 73U) || scenario == 87U;
		bool completed = complete_boundary_case == 0U &&
			(scenario == 66U || pending || scenario == 82U || scenario == 83U || scenario == 92U);

		launch_csg = i;
		launch_queue = 1U;
		launch_cleans = status_cleans = complete_reads_this_call = 0U;
		track_launch = track_complete = true;
		track_stop = false;
		complete_case = scenario;
		stop_case = scenario == 88U ? 34U : 33U;
		complete_read_pa[0] = *firmware_leaf(root, words64(model_groups[i].cs_input[1], 12U)) & UINT64_C(0x000000fffffff000);
		complete_read_pa[1] = *firmware_leaf(root, words64(model_groups[i].cs_input[1], 14U)) & UINT64_C(0x000000fffffff000);
		complete_read_pa[2] = quiesce_sync_pa[i];
		*(uint64_t *)(uintptr_t)(complete_read_pa[2] + 16UL) = UINT64_MAX;
		for (unsigned int bad = 0U; bad < 4U; bad++) {
			gpu_firmware_task_complete(&fw_ops, &donated_ops, bad == 0U ? &stranger : &service,
				bad == 1U ? &service : bad == 2U ? owners[1U - i] : owners[i],
				bad == 3U ? tokens[i] + 1UL : tokens[i], &result);
			assert(result.status == GPU_PRIVATE_INPUT && writes == before && control_reads == reads_before);
		}
		if (scenario == 81U) {
			track_complete = false;
			track_stop = true;
			gpu_firmware_task_quiesce(&fw_ops, &donated_ops, &service, owners[i],
				contexts[i], groups[i], tokens[i], &result);
			assert(result.status == GPU_PRIVATE_SUCCESS);
			before = writes;
		}
		if (scenario == 87U)
			model_groups[i].input[0] ^= 1U << 5U;
		if (scenario == 92U) {
			struct gpu_private_ops missing = donated_ops;

			missing.read_page = NULL;
			gpu_firmware_task_complete(&fw_ops, &missing, &service, owners[i], tokens[i], &result);
			assert(result.status == GPU_PRIVATE_STATE && writes == before && control_reads == reads_before);
		}
		if (scenario == 93U)
			fail_as_command = 5U;
		if (domain_case != 0U) {
			task_domain_backend(contexts[i], groups[i], tokens[i], i);
			track_complete = track_launch = track_stop = false;
			continue;
		}
		if (drain_case != 0U) {
			task_drain_backend(contexts[i], groups[i], tokens[i], i);
			track_complete = track_launch = track_stop = false;
			continue;
		}
		if (finish_case != 0U) {
			task_finish_backend(contexts[i], groups[i], tokens[i], i, scenario);
			track_complete = track_launch = track_stop = false;
			continue;
		}
		mmio_reads = firmware_checks = shader_checks = 0U;
		gpu_firmware_task_complete(&fw_ops, &donated_ops, &service, owners[i], tokens[i], &result);
		if (scenario == 66U && complete_boundary_case == 0U)
			printf("GPU_COMPLETE_STOP_BOUNDARY=PASS client=%u reads=%u config_checks=%u initial real stop retained; MODEL_ONLY\n",
				i, mmio_reads, shader_checks);
		if (complete_boundary_case != 0U) {
			assert(result.status == GPU_PRIVATE_STATE && writes == before + 1U &&
				as_count == commands_before && complete_reads_this_call == 3U &&
				(model_groups[i].input[0] & 7U) == 1U);
			printf("GPU_COMPLETE_STOP_FAULT=PASS case=%u client=%u rejected after read before SUSPEND/AS writes; MODEL_ONLY\n",
				complete_boundary_case, i);
		}
		if (pending) {
			assert(result.status == GPU_PRIVATE_INCOMPLETE && result.value[0] == 0UL &&
				result.value[1] == 1UL && result.value[2] == 0UL && result.value[3] == 0UL);
			assert(as_count == commands_before && registers[at] == (uint32_t)client_root);
			gpu_firmware_task_return(&fw_ops, &donated_ops, &service, owners[i], tokens[i], &result);
			assert(result.status == GPU_PRIVATE_STATE);
			destroy_prepared_bo(owners[i], prepared_bos[i], &result);
			assert(result.status == GPU_PRIVATE_STATE);
			if (scenario == 87U)
				model_groups[i].output[0] = model_groups[i].input[0];
			complete_case = 66U;
			status_cleans = complete_reads_this_call = 0U;
			gpu_firmware_task_complete(&fw_ops, &donated_ops, &service, owners[i], tokens[i], &result);
		}
		assert(result.status == (completed ? GPU_PRIVATE_SUCCESS : GPU_PRIVATE_STATE));
		if (completed) {
			assert(result.value[0] == 1UL && result.value[1] == 1UL &&
				result.value[2] == 0UL && result.value[3] == 0UL);
			assert(as_count == commands_before + 3U && registers[at] == 0U && registers[at + 1U] == 0U);
			assert(complete_reads_this_call == 4U && status_cleans == 2U && launch_cleans == 0U);
			if (i + 1U < count) {
				unsigned int other_as = model_groups[i + 1U].input[20];

				assert((model_groups[i + 1U].output[0] & 7U) == 1U &&
					words64(registers + (0x2400U + other_as * 0x40U) / 4U, 0U) != 0UL);
			}
		} else {
			for (unsigned int v = 0U; v < 4U; v++)
				assert(result.value[v] == 0UL);
			if (scenario == 67U || scenario == 68U || scenario == 69U || scenario == 90U || scenario == 91U)
				assert(control_reads == reads_before && as_count == commands_before);
			/* Explicit abort can safely return its data, but cannot become a
			 * successful COMPLETE. Do not assume the first cache call only
			 * walks empty upper tables: sparse skipping may reach data now.
			 */
			if (scenario == 81U) {
				return_expected_base = 0x400000UL + (i == 0U ? 0x40000000UL : 0x80000000UL);
				return_expected_pages = 2UL;
				memset(returned_data, 0, sizeof(returned_data));
				unsigned int old_returns = cpu_returns;

				gpu_firmware_task_reclaim(&fw_ops, &donated_ops, &service, owners[i], tokens[i], &result);
				assert(result.status == GPU_PRIVATE_STATE && cpu_returns == old_returns);
			}
			gpu_firmware_task_return(&fw_ops, &donated_ops, &service, owners[i], tokens[i], &result);
			assert(result.status == (scenario == 81U ? GPU_PRIVATE_SUCCESS : GPU_PRIVATE_STATE));
			if (scenario == 81U) assert(returned_data[0] && returned_data[1]);
		}
		if (scenario == 82U)
			registers[at] = 0x1000U;
		if (scenario == 83U)
			model_groups[i].output[0] ^= 2U;
		unsigned int replay_writes = writes, replay_reads = control_reads;
		bool replay_ok = completed && scenario != 82U && scenario != 83U;

		launch_cleans = 0U;
		gpu_firmware_task_complete(&fw_ops, &donated_ops, &service, owners[i], tokens[i], &result);
		assert(result.status == (replay_ok ? GPU_PRIVATE_SUCCESS : GPU_PRIVATE_STATE));
		assert(writes == replay_writes && control_reads == replay_reads && launch_cleans == 0U);
		gpu_firmware_task_cancel(owners[i], tokens[i], &result);
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_firmware_group_destroy(&donated_ops, owners[i], groups[i], &result);
		assert(result.status == GPU_PRIVATE_STATE);
		destroy_prepared_bo(owners[i], prepared_bos[i], &result);
		assert(result.status == GPU_PRIVATE_STATE);
		assert(data_syncs == data_before && control_writes == control_before);
		if (replay_ok) {
			complete_reads_this_call = 0U;
			if (reclaim_case != 0U)
				task_reclaim_backend(groups[i], tokens[i], i);
			else
				task_return_backend(contexts[i], groups[i], tokens[i], client_root, i, scenario);
		}
		for (unsigned int f = 0U; f < 2U; f++) {
			if (complete_boundary_fault[f] != NULL)
				*complete_boundary_fault[f] = complete_boundary_saved[f];
			complete_boundary_fault[f] = NULL;
		}
		track_complete = track_launch = track_stop = false;
	}
	printf("GPU_TASK_COMPLETE_BACKEND=PASS scenario=%u Clients=%u own fresh STATUS ACK, protected queue/scoreboard/error snapshots, counter alone refused, SUSPEND/AS disable before success, Client identity, replay and failure holds; MODEL_ONLY\n",
		scenario, count);
}

static void task_start_backend(unsigned long contexts[2], unsigned long groups[2],
		unsigned long tokens[2], unsigned int count, unsigned int scenario)
{
	const void *owners[2] = { &client_a, &client_b };
	struct gpu_private_result result;
	unsigned int initial_doorbells = firmware_doorbells;
	unsigned int data_before = data_syncs, control_before = control_writes;

	for (unsigned int i = 0U; i < count; i++) {
		unsigned int before = writes;
		bool accepted = refresh_failure == 0U && (scenario == 13U || scenario == 22U || scenario == 23U || scenario == 30U || scenario >= 33U);
		uint32_t *csg = model_groups[i].input, *csg_out = model_groups[i].output;
		uint32_t *cs_out = model_groups[i].cs_output[1];
		unsigned int root_index = (0x2400U + csg[20] * 0x40U) / 4U;

		launch_case = scenario;
		launch_csg = i;
		launch_queue = 1U;
		launch_cleans = 0U;
		track_launch = true;
		/* Identity refusals cannot publish requests or poison a valid task. */
		for (unsigned int bad = 0U; bad < 5U; bad++) {
			gpu_firmware_task_start(&fw_ops, &donated_ops,
				bad == 0U ? &stranger : &service,
				bad == 1U ? owners[1U - i] : owners[i],
				bad == 2U ? contexts[i] + 1UL : contexts[i],
				bad == 3U ? groups[i] + 1UL : groups[i],
				bad == 4U ? tokens[i] + 1UL : tokens[i], &result);
			assert(result.status == GPU_PRIVATE_INPUT && writes == before && launch_cleans == 0U);
		}
		if (scenario >= 66U) {
			gpu_firmware_task_reclaim(&fw_ops, &donated_ops, &service, owners[i], tokens[i], &result);
			assert(result.status == GPU_PRIVATE_STATE && writes == before && control_reads == 0U);
			gpu_firmware_task_complete(&fw_ops, &donated_ops, &service, owners[i], tokens[i], &result);
			assert(result.status == GPU_PRIVATE_STATE && writes == before && control_reads == 0U);
		}
		if (scenario == 18U)
			registers[0x2000U / 4U] = 1U;
		if (scenario == 19U)
			registers[root_index] ^= 0x1000U;
		if (scenario == 24U)
			model_glb_out[4] = 1U;
		if (scenario == 26U)
			model_glb_out[2] ^= 1U << i;
		if (scenario == 27U)
			csg_out[2] ^= 2U;
		if (scenario == 28U)
			model_glb_out[0] ^= 2U;
		if (scenario == 29U)
			csg[20]++;
		if (scenario == 31U)
			cs_out[fatal_snapshot_case ? 33U : 32U] = 1U;
		if (scenario == 32U)
			model_groups[i].cs_output[0][0] = 1U;
		gpu_firmware_task_start(&fw_ops, &donated_ops, &service, owners[i],
			contexts[i], groups[i], tokens[i], &result);
		assert(result.status == (accepted ? GPU_PRIVATE_SUCCESS : GPU_PRIVATE_STATE));
		if (accepted) {
			assert(result.value[0] == GPU_FIRMWARE_GROUP_STARTED && result.value[1] == 1UL &&
				result.value[2] == 0UL && result.value[3] == 0UL);
			assert(firmware_doorbells == initial_doorbells + 2U * (i + 1U) && launch_cleans == 5U);
			assert(model_glb_in[2] == 0U);
			assert(model_glb_out[2] == model_glb_in[2]); /* Preserve the first Client's bit. */
		} else {
			for (unsigned int v = 0U; v < 4U; v++)
				assert(result.value[v] == 0UL); /* No AS/root/address leak on failures. */
			bool published = scenario <= 17U || scenario == 20U || scenario == 21U || scenario == 25U;

			assert(launch_cleans == (published ? (refresh_failure != 0U || scenario == 15U || scenario == 21U ? 5U : 3U) : 0U));
			assert(writes == before + (published && scenario != 16U ? (refresh_failure != 0U || scenario == 15U || scenario == 21U ? 2U : 1U) : 0U));
		}
		if (scenario == 22U)
			csg_out[0] = (csg_out[0] & ~7U) | 3U; /* Replay must check ALL state bits. */
		if (scenario == 23U)
			cs_out[0] |= 1U << 31U;
		if (scenario == 30U)
			registers[root_index] = registers[root_index + 1U] = 0U;
		before = writes;
		launch_cleans = 0U;
		gpu_firmware_task_start(&fw_ops, &donated_ops, &service, owners[i],
			contexts[i], groups[i], tokens[i], &result);
		assert(result.status == (refresh_failure == 0U && (scenario == 13U || scenario >= 33U) ? GPU_PRIVATE_SUCCESS : GPU_PRIVATE_STATE));
		assert(writes == before && launch_cleans == 0U);
		gpu_firmware_task_cancel(owners[i], tokens[i], &result);
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_firmware_group_destroy(&donated_ops, owners[i], groups[i], &result);
		assert(result.status == GPU_PRIVATE_STATE);
		destroy_prepared_bo(owners[i], prepared_bos[i], &result);
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_firmware_group_inspect(&service, owners[i], groups[i], &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] ==
			(refresh_failure == 0U && (scenario == 13U || scenario >= 33U) ? GPU_FIRMWARE_GROUP_STARTED : GPU_FIRMWARE_GROUP_QUARANTINED));
		assert(data_syncs == data_before && control_writes == control_before &&
			!opencca_gpu_mmio_allowed(&service));
		track_launch = false;
	}
	printf("GPU_TASK_START_BACKEND=PASS scenario=%u Clients=%u exact Client/context/group/token, ordered CS-CSG-global publication, fixed MMIO notify, START followed by fresh STATUS ACK/CS snapshot, replay without publication, uncertain backing retained; ACCEPTANCE_ONLY MODEL_ONLY\n",
		scenario, count);
	if (scenario >= 66U)
		task_complete_backend(contexts, groups, tokens, count, scenario);
	else if (scenario >= 33U)
		task_quiesce_backend(contexts, groups, tokens, count, scenario);
}

static void task_backend_integration(unsigned long root, unsigned long contexts[2],
		unsigned int scenario)
{
	struct gpu_private_result result;
	struct gpu_firmware_group_resources resources[2];
	struct gpu_firmware_task_resources task;
	const void *owners[2] = { &client_a, &client_b };
	unsigned long groups[2], tokens[2], ipas[GPU_PRIVATE_BATCH];
	unsigned long sibling_group = 0UL, sibling_token = 0UL;
	const unsigned long data_base = 0x400000UL;
	uint32_t *shared = (void *)(uintptr_t)(*firmware_leaf(root, 0x04000000UL) &
		UINT64_C(0x000000fffffff000));
	uint32_t *group_input[2], *group_output[2], *stream_input[2][2];
	unsigned int before, count = scenario == 0U || scenario == 13U || scenario == 33U || scenario == 48U || scenario == 60U || scenario == 66U ? 2U : 1U;

	gpu_firmware_task_cancel(&client_a, last_prepared_task, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_task_ready(&fw_ops, &donated_ops, &service, &client_a, last_prepared_task, &result);
	assert(result.status == GPU_PRIVATE_INPUT && data_syncs == 0U);
	for (unsigned int i = 0U; i < count; i++) {
		uint32_t *desc = (void *)((unsigned char *)shared + 4096U + i * shared[5]);
		struct gpu_firmware_queue_config queues[2] = {
			{ .ring_bytes = 4096U, .priority = 2U },
			{ .ring_bytes = 4096U, .priority = 7U }
		};

		group_input[i] = (void *)((unsigned char *)shared + desc[1] - 0x04000000U);
		group_output[i] = (void *)((unsigned char *)shared + desc[2] - 0x04000000U);
		for (unsigned int q = 0U; q < 2U; q++) {
			uint32_t *cs = (void *)((unsigned char *)desc + 64U + q * desc[6]);

			stream_input[i][q] = (void *)((unsigned char *)shared + cs[1] - 0x04000000U);
			/* Cached boot-time offsets must be used, not these mutated pointers. */
			cs[1] = cs[2] = UINT32_MAX;
		}
		desc[1] = desc[2] = UINT32_MAX;
		gpu_firmware_group_create(&fw_ops, &donated_ops, &service, owners[i],
			contexts[i], 2UL, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		groups[i] = result.value[0];
		if (i == 0U) heap_group_handle = groups[i];
		gpu_firmware_group_configure(&donated_ops, &service, owners[i], groups[i],
			queues, 2UL, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		assert(gpu_firmware_group_resources(&service, owners[i], groups[i], &resources[i]));
		unsigned int page_count = i == 0U && (scenario == 0U || scenario == 50U || reclaim_case == 2U || finish_case == 2U || finish_case == 9U || (finish_case >= 25U && finish_case <= 39U)) ? GPU_PRIVATE_BATCH + 1U : 2U;

		gpu_private_bo_create(owners[i], &service, page_count * 4096UL,
			GPU_PRIVATE_READ, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		prepared_bos[i] = result.value[0];
		for (unsigned int offset = 0U; offset < page_count; offset += GPU_PRIVATE_BATCH) {
			unsigned int pages = page_count - offset;

			if (pages > GPU_PRIVATE_BATCH)
				pages = GPU_PRIVATE_BATCH;
			for (unsigned int j = 0U; j < pages; j++)
				ipas[j] = data_base + (offset + j) * 4096UL;
			gpu_private_bo_append(&private_ops, owners[i], prepared_bos[i], offset * 4096UL, ipas, pages, &result);
			assert(result.status == GPU_PRIVATE_SUCCESS);
		}
		if (drain_nc_client(i)) {
			struct gpu_private_ops nc = nc_data_ops();

			do { gpu_private_bo_uncached(&nc, owners[i], prepared_bos[i], &result); }
			while (result.status == GPU_PRIVATE_INCOMPLETE);
			assert(result.status == GPU_PRIVATE_SUCCESS);
		}
		for (unsigned int offset = 0U; offset < page_count; offset += GPU_PRIVATE_BATCH) {
			unsigned int pages = page_count - offset;

			if (pages > GPU_PRIVATE_BATCH)
				pages = GPU_PRIVATE_BATCH;
			gpu_private_map(&private_ops, owners[i], contexts[i], prepared_bos[i], offset * 4096UL,
				0x100000UL + offset * 4096UL, pages, GPU_PRIVATE_READ | GPU_PRIVATE_CACHE, &result);
			assert(result.status == GPU_PRIVATE_SUCCESS);
		}

		if (scenario == 47U) {
			struct gpu_firmware_queue_config q = { .ring_bytes = 4096U, .priority = 0U };

			gpu_firmware_group_create(&fw_ops, &donated_ops, &service, &client_a, contexts[0], 1UL, &result);
			assert(result.status == GPU_PRIVATE_SUCCESS);
			sibling_group = result.value[0];
			gpu_firmware_group_configure(&donated_ops, &service, &client_a, sibling_group, &q, 1UL, &result);
			assert(result.status == GPU_PRIVATE_SUCCESS);
			gpu_firmware_task_stage(&private_ops, &service, &client_a, sibling_group, 0UL, 0x100000UL, 8UL, 0UL, &result);
			assert(result.status == GPU_PRIVATE_SUCCESS);
			sibling_token = result.value[0];
		}
		if (scenario == 65U) {
			gpu_firmware_task_stage(&private_ops, &service, owners[i], groups[i], 0UL,
				0x100000UL, 8UL, 0UL, &result);
			assert(result.status == GPU_PRIVATE_SUCCESS);
			prepared_unpublished_task = result.value[0];
		}
		gpu_firmware_task_stage(&private_ops, &service, owners[i], groups[i], 1UL,
			0x100ff8UL, 16UL, 7UL, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		tokens[i] = result.value[0];
		last_prepared_task = tokens[0];
	}

	gpu_firmware_task_ready(&fw_ops, &donated_ops, &service, &client_a, tokens[0], &result);
	assert(result.status == GPU_PRIVATE_STATE && data_syncs == 0U); /* Not prepared. */
	before = writes;
	for (unsigned int bad = 0U; bad < 5U; bad++) {
		gpu_firmware_task_prepare(&fw_ops, &donated_ops,
			bad == 0U ? &stranger : &service, bad == 1U ? &client_b : &client_a,
			bad == 2U ? contexts[1] : contexts[0],
			bad == 3U ? groups[0] + 1UL : groups[0],
			bad == 4U ? tokens[0] + 1UL : tokens[0], &result);
		assert(result.status == GPU_PRIVATE_INPUT);
	}
	assert(writes == before && control_writes == 0U);
	if (scenario == 3U || scenario == 4U)
		fail_control_write = scenario == 3U ? 1U : 2U;
	if (scenario == 5U)
		fail_as_command = 1U; /* Partial root/attributes followed by failed UPDATE. */
	if (scenario == 6U)
		group_output[0][0] = 1U; /* Unexplained live CSG: reject before any write. */
	if (scenario == 9U)
		registers[0x2440U / 4U] = 0xdead000U;
	if (scenario == 10U)
		registers[0x18U / 4U] &= ~2U;
	for (unsigned int i = 0U; i < count; i++) {
		gpu_firmware_task_prepare(&fw_ops, &donated_ops, &service, owners[i],
			contexts[i], groups[i], tokens[i], &result);
		if ((scenario >= 3U && scenario <= 6U) || scenario == 9U || scenario == 10U) {
			assert(result.status == GPU_PRIVATE_STATE);
			gpu_firmware_task_cancel(owners[i], tokens[i], &result);
			if (scenario == 6U) {
				assert(result.status == GPU_PRIVATE_SUCCESS && writes == before && control_writes == 0U);
				gpu_firmware_group_inspect(&service, owners[i], groups[i], &result);
				assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_GROUP_RESERVED);
			} else {
				assert(result.status == GPU_PRIVATE_STATE);
				gpu_firmware_group_destroy(&donated_ops, owners[i], groups[i], &result);
				assert(result.status == GPU_PRIVATE_STATE);
				gpu_firmware_group_inspect(&service, owners[i], groups[i], &result);
				assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_GROUP_QUARANTINED);
				before = writes;
				gpu_firmware_task_prepare(&fw_ops, &donated_ops, &service, owners[i],
					contexts[i], groups[i], tokens[i], &result);
				assert(result.status == GPU_PRIVATE_STATE && writes == before);
			}
			break;
		}
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_GROUP_PREPARED &&
			result.value[1] == 1UL && result.value[2] == 0UL && result.value[3] == 0UL);
		assert(gpu_firmware_task_resources(&service, owners[i], tokens[i], &task));
		gpu_firmware_task_start(&fw_ops, &donated_ops, &service, owners[i],
			contexts[i], groups[i], tokens[i], &result);
		assert(result.status == GPU_PRIVATE_STATE && firmware_doorbells == 1U);
		gpu_firmware_task_quiesce(&fw_ops, &donated_ops, &service, owners[i],
			contexts[i], groups[i], tokens[i], &result);
		assert(result.status == GPU_PRIVATE_STATE && firmware_doorbells == 1U);
		unsigned int first = (unsigned int)((resources[i].ring_va[1] - GPU_PRIVATE_CONTROL_GPU_VA) / 4096UL);

		assert(!donated_visible[first] && memcmp(donated_pages[first], task.instructions, sizeof(task.instructions)) == 0);
		for (unsigned int q = 0U; q < 2U; q++) {
			unsigned int io = (resources[i].input_va[q] - GPU_FIRMWARE_CONTROL_VA) / 4096U;
			const uint64_t *input = (void *)donated_pages[io];
			const uint32_t *cs = stream_input[i][q];

			assert(!donated_visible[io] && input[0] == (q == 1U ? 128U : 0U) && input[1] == 0U);
			assert(cs[0] == 0U && cs[1] == ((i + 1U) << 8U | (q == 1U ? 7U : 2U)));
			assert(cs[2] == 0U && cs[3] == 0U && words64(cs, 4U) == resources[i].ring_va[q] && cs[6] == 4096U);
			assert(words64(cs, 12U) == resources[i].input_va[q] && words64(cs, 14U) == resources[i].output_va[q]);
			for (unsigned int w = 16U; w < 24U; w++)
				assert(cs[w] == 0U); /* Instrumentation disabled. */
		}
		const uint32_t *csg = group_input[i];
		unsigned int as = i + 1U;
		unsigned long client_root = registers[(0x2400U + as * 0x40U) / 4U] |
			((unsigned long)registers[(0x2404U + as * 0x40U) / 4U] << 32U);

		assert(csg[0] == 0U && csg[1] == 0U && csg[2] == 0U && csg[3] == 0U);
		assert(words64(csg, 8U) == UINT64_C(0x10000000f) && words64(csg, 10U) == UINT64_C(0x10000000f));
		assert(csg[12] == 1U && csg[13] == (5U | (5U << 8U) | (1U << 16U)));
		assert(words64(csg, 16U) == resources[i].suspend_va && words64(csg, 18U) == 0UL && csg[20] == as && csg[21] == 0U);
		assert(client_root != 0UL && client_root != root);
		quiesce_sync_pa[i] = software_leaf(client_root, resources[i].sync_va) & UINT64_C(0x000000fffffff000);
		assert((software_leaf(client_root, 0x100000UL) & UINT64_C(0x000000fffffff000)) ==
			data_base + (i == 0U ? 0x40000000UL : 0x80000000UL));
		gpu_firmware_group_validate(&service, owners[i], contexts[i], groups[i], 2UL, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_GROUP_PREPARED);
		before = writes;
		unsigned int written = control_writes;

		if (scenario == 0U || scenario == 11U || scenario == 12U || scenario >= 13U) {
			unsigned int calls = 0U, previous_pages = 0U;

			gpu_firmware_task_ready(&fw_ops, &donated_ops, &service, &service, tokens[i], &result);
			assert(result.status == GPU_PRIVATE_INPUT); /* Proxy cannot assert readiness. */
			gpu_firmware_task_ready(&fw_ops, &donated_ops, &service, owners[1U - i], tokens[i], &result);
			assert(result.status == GPU_PRIVATE_INPUT);
			gpu_firmware_task_ready(&fw_ops, &donated_ops, &stranger, owners[i], tokens[i], &result);
			assert(result.status == GPU_PRIVATE_INPUT);
			sync_expected_base = data_base + (i == 0U ? 0x40000000UL : 0x80000000UL);
			sync_expected_pages = (scenario == 0U || scenario == 50U || reclaim_case == 2U || finish_case == 2U || finish_case == 9U || (finish_case >= 25U && finish_case <= 39U)) && i == 0U ? GPU_PRIVATE_BATCH + 1UL : 2UL;
			memset(synced_data, 0, sizeof(synced_data));
			unsigned int initial_syncs = data_syncs;
			unsigned long ready_pages = drain_nc_client(i) ? 0UL : sync_expected_pages;

			if (scenario == 11U)
				fail_data_sync = data_syncs + 2U;
			if (scenario == 12U)
				fault_after_data_sync = data_syncs + 1U;
			do {
				unsigned int old_syncs = data_syncs;

				gpu_firmware_task_ready(&fw_ops, &donated_ops, &service, owners[i], tokens[i], &result);
				assert(++calls <= GPU_PRIVATE_TABLES + 1U && data_syncs - old_syncs <= GPU_PRIVATE_BATCH);
				if (result.status == GPU_PRIVATE_INCOMPLETE) {
					assert(result.value[0] == 0UL && result.value[1] == 1UL && result.value[3] == 0UL);
					assert(result.value[2] >= previous_pages);
					previous_pages = (unsigned int)result.value[2];
					struct gpu_private_result refused;

					gpu_firmware_task_start(&fw_ops, &donated_ops, &service, owners[i],
						contexts[i], groups[i], tokens[i], &refused);
					assert(refused.status == GPU_PRIVATE_STATE && firmware_doorbells == 1U);
				}
			} while (result.status == GPU_PRIVATE_INCOMPLETE);
			assert(writes == before && control_writes == written && firmware_doorbells == 1U);
			if (scenario == 11U || scenario == 12U) {
				assert(result.status == GPU_PRIVATE_STATE && data_syncs == initial_syncs + 2U);
				assert(result.value[0] == 0UL && result.value[1] == 0UL && result.value[2] == 0UL && result.value[3] == 0UL);
				gpu_firmware_group_inspect(&service, owners[i], groups[i], &result);
				assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_GROUP_QUARANTINED);
			} else {
				assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == 1UL && result.value[1] == 1UL &&
					result.value[2] == ready_pages && result.value[3] == 0UL);
				assert(data_syncs - initial_syncs == ready_pages &&
				calls >= (ready_pages + GPU_PRIVATE_BATCH - 1U) / GPU_PRIVATE_BATCH);
				for (unsigned int j = 0U; j < ready_pages; j++)
					assert(synced_data[j]);
				gpu_firmware_task_ready(&fw_ops, &donated_ops, &service, owners[i], tokens[i], &result);
				assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == 1UL &&
					data_syncs - initial_syncs == ready_pages);
				gpu_private_task_cache(&donated_ops, &service, owners[i], contexts[i], tokens[i] + 1UL, &result);
				assert(result.status == GPU_PRIVATE_STATE && data_syncs - initial_syncs == ready_pages);
			}
			printf("GPU_TASK_READY_BACKEND=PASS scenario=%u client=%u bounded calls=%u data callbacks=%u all private mapped pages, internal control excluded, Client-only ready, no doorbell, replay/failed-cache retention; MODEL_ONLY\n",
				scenario, i, calls, data_syncs - initial_syncs);
		}
		if (scenario == 7U)
			registers[0x2440U / 4U] = registers[0x2444U / 4U] = 0U;
		if (scenario == 8U)
			registers[0x2448U / 4U] ^= 1U;
		gpu_firmware_task_prepare(&fw_ops, &donated_ops, &service, owners[i], contexts[i], groups[i], tokens[i], &result);
		assert(result.status == (scenario == 7U || scenario == 8U || scenario == 11U || scenario == 12U ? GPU_PRIVATE_STATE : GPU_PRIVATE_SUCCESS));
		assert(writes == before && control_writes == written); /* Exact replay never republishes. */
		gpu_firmware_task_cancel(owners[i], tokens[i], &result);
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_firmware_group_destroy(&donated_ops, owners[i], groups[i], &result);
		assert(result.status == GPU_PRIVATE_STATE);
	}
	if (scenario == 47U) {
		before = writes;
		gpu_firmware_task_prepare(&fw_ops, &donated_ops, &service, &client_a,
			contexts[0], sibling_group, sibling_token, &result);
		assert(result.status == GPU_PRIVATE_STATE && writes == before);
		gpu_firmware_group_inspect(&service, &client_a, sibling_group, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_GROUP_RESERVED);
		puts("GPU_TASK_AS_SERIALIZATION=PASS second same-context CSG stays unpublished; no shared-AS detach while sibling published; MODEL_ONLY");
	}
	if (scenario == 0U) {
		/* A second context of the same Client may map a BO, but it must not
		 * perform CPU cache operations over backing handed to the first one.
		 */
		gpu_private_context_create(&private_ops, &client_a, &service, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		prepared_alias_context = result.value[0];
		assert(gpu_private_context_hold(&service, &client_a, prepared_alias_context));
		gpu_private_map(&private_ops, &client_a, prepared_alias_context, prepared_bos[0],
			0UL, 0x400000UL, 1U, GPU_PRIVATE_READ | GPU_PRIVATE_CACHE, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		assert(gpu_private_task_hold(&private_ops, &service, &client_a,
			prepared_alias_context, 0x400000UL, 8UL));
		gpu_private_context_prepare(&donated_ops, &service, &client_a,
			prepared_alias_context, root, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		unsigned int old_syncs = data_syncs, calls = 0U;

		do {
			gpu_private_task_cache(&donated_ops, &service, &client_a,
				prepared_alias_context, tokens[0] + 0x10000UL, &result);
			assert(++calls <= GPU_PRIVATE_TABLES + 1U && data_syncs == old_syncs);
		} while (result.status == GPU_PRIVATE_INCOMPLETE);
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_firmware_task_ready(&fw_ops, &donated_ops, &service, &client_a, tokens[0], &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == 1UL && data_syncs == old_syncs);
		puts("GPU_TASK_CACHE_ALIAS=PASS same-Client BO alias context rejected before data sync; original readiness preserved; MODEL_ONLY");
	}
	assert(firmware_doorbells == 1U && !opencca_gpu_mmio_allowed(&service));
	if (scenario == 10U)
		registers[0x18U / 4U] |= 2U; /* Restore synthetic read-only topology. */
	printf("GPU_TASK_PREPARE_BACKEND=PASS scenario=%u protected ring/IO, cached CS/CSG offsets, identity binding, actual AS roots/PTEs, STOP-only, replay without writes, partial retention; MODEL_ONLY\n", scenario);
	if (scenario >= 13U)
		task_start_backend(contexts, groups, tokens, count, scenario);
}

static bool heap_cpu_return(unsigned long pa)
{
	assert(track_complete && registers[0x2440U / 4U] == 0U && registers[0x2444U / 4U] == 0U);
	assert_model_nonexecuting(0U);
	assert(registers[0x2470U / 4U] == 1U && (model_groups[0].output[0] & 7U) == 2U);
	if (pa >= 0x40400000UL && pa < 0x40402000UL) {
		unsigned int i = (unsigned int)((pa - 0x40400000UL) / 4096UL);

		assert(!heap_return_old[i]);
		heap_return_old[i] = true;
	} else {
		assert(pa >= 0x41000000UL && (pa - 0x41000000UL) / 4096UL < heap_return_pages);
		unsigned int i = (unsigned int)((pa - 0x41000000UL) / 4096UL);

		assert(!heap_return_new[i]);
		heap_return_new[i] = true;
	}
	cpu_returns++;
	return true;
}

static void heap_finish(unsigned long token, unsigned int pages)
{
	struct gpu_private_result r;
	unsigned long root = words64(registers + 0x2400U / 4U, 0U);
	struct gpu_private_ops memory = donated_ops;

	launch_csg = 0U;
	launch_queue = 1U;
	launch_cleans = status_cleans = complete_reads_this_call = 0U;
	complete_case = 66U;
	stop_case = 33U;
	track_launch = true;
	track_complete = true;
	track_stop = false;
	complete_read_pa[0] = *firmware_leaf(root, words64(model_groups[0].cs_input[1], 12U)) & UINT64_C(0x000000fffffff000);
	complete_read_pa[1] = *firmware_leaf(root, words64(model_groups[0].cs_input[1], 14U)) & UINT64_C(0x000000fffffff000);
	complete_read_pa[2] = quiesce_sync_pa[0];
	gpu_firmware_task_complete(&fw_ops, &memory, &service, &client_a, token, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS && r.value[0] == 1UL);
	assert(track_complete && !track_stop);
	assert_model_nonexecuting(launch_csg);
	track_launch = false;
	heap_return_pages = pages;
	memset(heap_return_old, 0, sizeof(heap_return_old));
	memset(heap_return_new, 0, sizeof(heap_return_new));
	cpu_returns = 0U;
	memory.sync_page_for_cpu = heap_cpu_return;
	do {
		gpu_firmware_task_return(&fw_ops, &memory, &service, &client_a, token, &r);
	} while (r.status == GPU_PRIVATE_INCOMPLETE);
	assert(r.status == GPU_PRIVATE_SUCCESS && r.value[2] == pages + 2UL && cpu_returns == pages + 2U);
	do {
		gpu_firmware_task_retire(&fw_ops, &memory, &service, &client_a, token, &r);
	} while (r.status == GPU_PRIVATE_INCOMPLETE);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	track_stop = track_complete = false;
}

static bool heap_reuse_sync(unsigned long pa)
{
	bool *seen;

	if (pa >= 0x40400000UL && pa < 0x40402000UL)
		seen = &heap_return_old[(pa - 0x40400000UL) / 4096UL];
	else {
		assert(pa >= 0x41000000UL && (pa - 0x41000000UL) / 4096UL < 32UL);
		seen = &heap_return_new[(pa - 0x41000000UL) / 4096UL];
	}
	assert(!*seen);
	*seen = true;
	data_syncs++;
	return true;
}

static void task_heap_backend(unsigned long root, unsigned long contexts[2], unsigned int scenario)
{
	struct gpu_private_result r, snapshot;
	const unsigned long va = 0x200000UL;
	unsigned long token, event, ipas[GPU_PRIVATE_BATCH];
	unsigned int pages = scenario == 1U || (scenario >= 19U && scenario <= 21U) ? 513U : 32U;
	unsigned int before, bells, synced;
	uint32_t *in, *out;
	uint32_t other_as[16], other_input[0x58U / 4U];

	/* Two actual RMM groups/tasks already prepared, ready and started. */
	task_backend_integration(root, contexts, 13U);
	token = last_prepared_task;
	in = model_groups[0].cs_input[1];
	out = model_groups[0].cs_output[1];
	memcpy(other_as, registers + 0x2480U / 4U, sizeof(other_as));
	memcpy(other_input, model_groups[1].input, sizeof(other_input));
	before = writes;
	bells = firmware_doorbells;
	for (unsigned int bad = 0U; bad < 4U; bad++) {
		gpu_firmware_task_heap_event(&fw_ops, &donated_ops, bad == 0U ? &stranger : &service,
			bad == 1U ? &client_b : bad == 2U ? &service : &client_a,
			bad == 3U ? token + 1UL : token, &r);
		assert(r.status == GPU_PRIVATE_INPUT && writes == before);
	}
	out[0] |= 1U << 26U;
	out[48] = 5U;
	out[49] = 3U;
	out[51] = 1U;
	out[52] = 0x100000U;
	out[53] = 0U;
	if (scenario == 3U) out[49] = 5U;
	if (scenario == 4U) out[53] = 0x10000U;
	if (scenario == 5U) {
		model_groups[0].cs_output[0][0] |= 1U << 26U;
		model_groups[0].cs_output[0][48] = 5U;
		model_groups[0].cs_output[0][49] = 3U;
		model_groups[0].cs_output[0][51] = 1U;
		model_groups[0].cs_output[0][52] = 0x100000U;
	}
	if (scenario == 6U) out[0] &= ~(1U << 26U);
	if (scenario == 7U) { in[0] |= 1U << 26U; out[0] &= ~(1U << 26U); }
	if (scenario == 8U) in[0] |= 1U << 26U;
	gpu_firmware_task_heap_event(&fw_ops, &donated_ops, &service, &client_a, token, &snapshot);
	assert(writes == before && firmware_doorbells == bells);
	if (scenario >= 3U && scenario <= 5U) {
		assert(snapshot.status == GPU_PRIVATE_STATE);
		goto done;
	}
	if (scenario == 6U || scenario == 8U) {
		assert(snapshot.status == GPU_PRIVATE_SUCCESS);
		for (unsigned int i = 0U; i < 4U; i++) assert(snapshot.value[i] == 0UL);
		goto done;
	}
	assert(snapshot.status == GPU_PRIVATE_SUCCESS && snapshot.value[0] != 0UL);
	assert(snapshot.value[1] == 0x100000UL && snapshot.value[2] == (4UL | (2UL << 32U)) && snapshot.value[3] == 1UL);
	event = snapshot.value[0];
	gpu_firmware_task_heap_event(&fw_ops, &donated_ops, &service, &client_a, token, &r);
	assert(memcmp(&r, &snapshot, sizeof(r)) == 0 && writes == before);
	gpu_firmware_task_complete(&fw_ops, &donated_ops, &service, &client_a, token, &r);
	assert(r.status == GPU_PRIVATE_INCOMPLETE && writes == before); /* No event is a fence. */
	if (scenario == 9U) {
		gpu_firmware_task_heap_grow(&fw_ops, &donated_ops, &service, &client_a, token, event + 1UL, 0UL, 0UL, &r);
		assert(r.status == GPU_PRIVATE_INPUT && writes == before);
	}
	if (scenario != 2U) {
		const void *owner = scenario == 10U ? &client_b : &client_a;
		gpu_private_bo_create(owner, &service, pages * 4096UL, 3UL, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS);
		heap_test_bos[scenario == 10U ? 1U : 0U] = r.value[0];
		for (unsigned int offset = 0U; offset < pages; offset += GPU_PRIVATE_BATCH) {
			unsigned int count = pages - offset;
			if (count > GPU_PRIVATE_BATCH) count = GPU_PRIVATE_BATCH;
			for (unsigned int i = 0U; i < count; i++) ipas[i] = 0x1000000UL + (offset + i) * 4096UL;
			gpu_private_bo_append(&private_ops, owner, heap_test_bos[scenario == 10U ? 1U : 0U],
				offset * 4096UL, ipas, count, &r);
			assert(r.status == GPU_PRIVATE_SUCCESS);
		}
	}
	sync_expected_base = 0x41000000UL;
	sync_expected_pages = pages;
	memset(synced_data, 0, sizeof(synced_data));
	data_syncs = 0U;
	heap_cleans = 0U;
	heap_case = scenario;
	track_heap = true;
	if (scenario == 12U) fail_data_sync = 2U;
	if (scenario == 13U) fail_as_command = 4U;
	if (scenario == 18U) out[52] += 4096U;
	if (scenario == 22U) {
		out[49]++;
		out[51]++; /* Legitimate fragment progress, same outstanding event. */
		gpu_firmware_task_heap_event(&fw_ops, &donated_ops, &service, &client_a, token, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS && r.value[0] == event &&
			r.value[2] == (3UL | (2UL << 32U)) && writes == before);
	}
	gpu_firmware_task_heap_grow(&fw_ops, &donated_ops, &service, &client_a, token, event,
		scenario == 10U ? heap_test_bos[1] : heap_test_bos[0],
		scenario == 2U ? 0UL : scenario == 11U ? 0x100000UL : va, &r);
	if (scenario == 10U || scenario == 11U || scenario == 18U) {
		assert(r.status == GPU_PRIVATE_STATE && writes == before && data_syncs == 0U && !heap_cleans);
		goto done;
	}
	if (scenario == 12U || scenario == 13U || (scenario >= 14U && scenario <= 17U)) {
		assert(r.status == GPU_PRIVATE_STATE);
		unsigned int old_writes = writes;
		synced = data_syncs;
		gpu_firmware_task_heap_grow(&fw_ops, &donated_ops, &service, &client_a, token, event,
			heap_test_bos[0], va, &r);
		assert(r.status == GPU_PRIVATE_STATE && writes == old_writes && data_syncs == synced);
		gpu_private_bo_destroy(&client_a, heap_test_bos[0], &r);
		assert(r.status == GPU_PRIVATE_STATE);
		goto done;
	}
	if (pages == 513U) {
		assert(r.status == GPU_PRIVATE_INCOMPLETE && r.value[0] == 0UL && r.value[1] == event && r.value[2] == 512UL && r.value[3] == 1UL);
		assert(data_syncs == 512U && !heap_cleans && firmware_doorbells == bells);
		if (scenario == 19U) out[52] += 4096U;
		if (scenario == 20U || scenario == 21U) {
			unsigned int old_writes = writes;
			gpu_firmware_task_heap_grow(&fw_ops, &donated_ops, &service, &client_a, token, event,
				scenario == 20U ? heap_test_bos[0] + 0x10000UL : heap_test_bos[0],
				scenario == 21U ? va + 4096UL : va, &r);
			assert(r.status == GPU_PRIVATE_INPUT && writes == old_writes && data_syncs == 512U);
		}
		gpu_firmware_task_heap_grow(&fw_ops, &donated_ops, &service, &client_a, token, event, heap_test_bos[0], va, &r);
		if (scenario == 19U) {
			assert(r.status == GPU_PRIVATE_STATE && data_syncs == 512U && !heap_cleans);
			gpu_private_bo_destroy(&client_a, heap_test_bos[0], &r);
			assert(r.status == GPU_PRIVATE_STATE);
			goto done;
		}
	}
	unsigned int expected = scenario == 2U ? 0U : pages;
	assert(r.status == GPU_PRIVATE_SUCCESS && r.value[0] == 1UL && r.value[1] == event && r.value[2] == expected && r.value[3] == 1UL);
	assert(data_syncs == expected && heap_cleans == 3U && firmware_doorbells == bells + 1U);
	assert(words64(in, 8U) == (scenario == 2U ? 0UL : va | pages) && words64(in, 10U) == words64(in, 8U));
	for (unsigned int i = 0U; i < expected; i++) assert(hardware_leaf(1U, va + i * 4096UL) == 0x41000000UL + i * 4096UL);
	unsigned int old_writes = writes;
	gpu_firmware_task_heap_grow(&fw_ops, &donated_ops, &service, &client_a, token, event,
		heap_test_bos[0], scenario == 2U ? 0UL : va, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS && r.value[2] == expected && writes == old_writes && heap_cleans == 3U);
	gpu_firmware_task_heap_event(&fw_ops, &donated_ops, &service, &client_a, token, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS && r.value[0] == 0UL);
	if (scenario == 23U) {
		out[0] ^= 1U << 26U;
		out[48]++;
		gpu_firmware_task_heap_event(&fw_ops, &donated_ops, &service, &client_a, token, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS && r.value[0] > event);
		unsigned long next_event = r.value[0];
		gpu_firmware_task_heap_grow(&fw_ops, &donated_ops, &service, &client_a, token, event, 0UL, 0UL, &r);
		assert(r.status == GPU_PRIVATE_INPUT);
		heap_cleans = 0U;
		gpu_firmware_task_heap_grow(&fw_ops, &donated_ops, &service, &client_a, token, next_event, 0UL, 0UL, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS && words64(in, 8U) == 0UL && firmware_doorbells == bells + 2U);
	}
	track_heap = false;
	heap_finish(token, expected);
	if (scenario == 24U || scenario == 25U) {
		struct gpu_private_ops memory = donated_ops;
		unsigned int queue = scenario == 25U ? 0U : 1U;

		assert((out[0] & (1U << 26U)) != 0U && (in[0] & (1U << 26U)) == 0U);
		if (scenario == 25U) {
			struct gpu_firmware_queue_config config = {.ring_bytes = 4096U, .priority = 2U};

			gpu_firmware_group_destroy(&donated_ops, &client_a, heap_group_handle, &r);
			assert(r.status == GPU_PRIVATE_SUCCESS);
			gpu_firmware_group_create(&fw_ops, &donated_ops, &service, &client_a, contexts[0], 1UL, &r);
			assert(r.status == GPU_PRIVATE_SUCCESS);
			heap_group_handle = r.value[0];
			gpu_firmware_group_configure(&donated_ops, &service, &client_a, heap_group_handle, &config, 1UL, &r);
			assert(r.status == GPU_PRIVATE_SUCCESS);
		}
		gpu_firmware_task_stage(&private_ops, &service, &client_a, heap_group_handle,
			queue, 0x100ff8UL, 16UL, 8UL, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS);
		unsigned long next = r.value[0];

		gpu_firmware_task_prepare(&fw_ops, &donated_ops, &service, &client_a,
			contexts[0], heap_group_handle, next, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS && (in[0] & (1U << 26U)) != 0U);
		assert(model_groups[0].input[2] == model_groups[0].output[2]);
		memory.sync_page_for_device = heap_reuse_sync;
		memset(heap_return_old, 0, sizeof(heap_return_old));
		memset(heap_return_new, 0, sizeof(heap_return_new));
		data_syncs = 0U;
		do {
			gpu_firmware_task_ready(&fw_ops, &memory, &service, &client_a, next, &r);
		} while (r.status == GPU_PRIVATE_INCOMPLETE);
		assert(r.status == GPU_PRIVATE_SUCCESS && data_syncs == 34U);
		launch_csg = 0U;
		launch_queue = queue;
		launch_case = 13U;
		launch_cleans = 0U;
		track_launch = true;
		gpu_firmware_task_start(&fw_ops, &memory, &service, &client_a,
			contexts[0], heap_group_handle, next, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS);
		track_launch = false;
		gpu_firmware_task_heap_event(&fw_ops, &memory, &service, &client_a, next, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS && r.value[0] == 0UL);
	}
done:
	track_heap = false;
	assert(memcmp(other_as, registers + 0x2480U / 4U, sizeof(other_as)) == 0);
	assert(memcmp(other_input, model_groups[1].input, sizeof(other_input)) == 0);
	printf("GPU_TASK_HEAP_BACKEND=PASS scenario=%u actual firmware/PT/platform source, event ownership, ACK-edge identity, new private pages, bounded extension, publication/replay/uncertainty, other Client unchanged; MODEL_ONLY\n", scenario);
}

static bool batch_read(unsigned long pa, size_t offset, void *data, size_t bytes)
{
	unsigned int index = donated_index(pa);

	assert(!donated_visible[index] && offset + bytes <= 4096U);
#ifdef GPU_DOMAIN_RSI_TEST
	if (domain_dispatch_active) assert(domain_policy_locked);
#endif
	assert(offset != 64U); /* Canonical history never reads donated pages. */
	assert(bytes == 16U);
	control_reads++;
	if (((batch_case == 8U || batch_case == 29U) && pa == batch_io[1][1]) ||
	    (batch_case == 51U && pa == batch_io[1][0]))
		return false;
	if (suspend_observe_active &&
	    words64(registers + (0x2400U + model_groups[0].input[20] * 0x40U) / 4U, 0U) == 0UL) {
		if (suspend_observe_case == 17U) model_glb_out[4] = 1U;
		if (suspend_observe_case == 19U) return false;
		if (suspend_observe_case == 21U) model_groups[0].cs_output[2][0] |= 1U << 26U;
		if (suspend_observe_case == 22U) model_groups[0].cs_input[0][0] |= 1U;
		if (suspend_observe_case == 23U) model_groups[0].output[0] = model_groups[0].input[0] ^ (1U << 5U);
		if (suspend_observe_case == 24U)
			registers[(0x2400U + model_groups[0].input[20] * 0x40U) / 4U] = 0x1000U;
	}
	memcpy(data, donated_pages[index] + offset, bytes);
	if (batch_case == 16U && pa == batch_sync && offset == 16U &&
	    (registers[(0x2400U + model_groups[0].input[20] * 0x40U) / 4U] |
	     registers[(0x2404U + model_groups[0].input[20] * 0x40U) / 4U]) == 0U)
		((uint32_t *)data)[2] = 7U; /* Recheck after STOP must still inspect q1. */
	return true;
}

static bool publish_notify(unsigned long root)
{
	return !(batch_publish && batch_case == 46U) && fw_ops.notify(root);
}

static bool task_publication_backend(const struct gpu_private_ops *ops,
		unsigned long context, unsigned long group, unsigned long token,
		unsigned int count, unsigned int scenario)
{
	struct gpu_firmware_ops firmware = fw_ops;
	struct gpu_private_result result;
	unsigned long full = (1UL << count) - 1UL;
	unsigned int before, written;
	uint64_t *in0 = (void *)(uintptr_t)batch_io[0][0];
	uint64_t *in1 = (void *)(uintptr_t)batch_io[1][0];

	firmware.notify = publish_notify;
	assert(in0[0] == 0UL && in1[0] == 0UL);
	before = firmware_doorbells; written = control_writes;
	if (scenario == 38U || scenario == 39U || scenario == 41U) {
		if (scenario == 41U) {
			gpu_firmware_task_publish(&firmware, ops, &service, &client_b, token, 2UL, &result);
			assert(result.status == GPU_PRIVATE_INPUT);
			gpu_firmware_task_publish(&firmware, ops, &service, &service, token, 2UL, &result);
			assert(result.status == GPU_PRIVATE_INPUT);
		}
		gpu_firmware_task_publish(&firmware, ops, scenario == 41U ? &client_b : &service,
			&client_a, token, scenario == 38U ? 1UL << count : 4UL, &result);
		assert(result.status == GPU_PRIVATE_INPUT && !result.value[0]);
		assert(firmware_doorbells == before && control_writes == written && !in0[0] && !in1[0]);
	}
	if (scenario == 43U) {
		in1[0] = 128UL; /* Unexpected old cursor: no repair or prefix write. */
		gpu_firmware_task_publish(&firmware, ops, &service, &client_a, token, 3UL, &result);
		assert(result.status == GPU_PRIVATE_STATE && !result.value[0] && control_writes == written);
		return false;
	}
	/* Empty START is harmless: Proxy cannot make a staged wrapper visible. */
	bool start_empty = scenario == 37U || (scenario >= 44U && scenario <= 51U);

	if (!start_empty) {
		gpu_firmware_task_publish(&firmware, ops, &service, &client_a, token, 2UL, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == 2UL &&
			result.value[1] == count && result.value[2] == 3UL && !result.value[3]);
		assert(in0[0] == 128UL && in1[0] == 0UL && firmware_doorbells == before);
		if (scenario == 40U) {
			written = control_writes;
			gpu_firmware_task_publish(&firmware, ops, &service, &client_a, token, 0UL, &result);
			assert(result.status == GPU_PRIVATE_INPUT && control_writes == written);
		}
	}
	batch_cs_cleans = batch_cleans = 0U;
	gpu_firmware_task_start(&firmware, ops, &service, &client_a, context, group, token, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	before = firmware_doorbells; written = control_writes;
	batch_cs_cleans = batch_cleans = 0U;
	if (scenario == 52U) {
		model_groups[0].input[0] ^= 1U << 5U;
		/* Even exact publication replay must not bypass pending status ACK. */
		gpu_firmware_task_publish(&firmware, ops, &service, &client_a, token, 2UL, &result);
		assert(result.status == GPU_PRIVATE_STATE && !result.value[0] &&
			firmware_doorbells == before && control_writes == written);
		return false;
	}
	if (start_empty && scenario >= 44U && scenario <= 51U) {
		if (scenario == 44U || scenario == 45U)
			fail_control_write = control_writes + (scenario == 44U ? 1U : 2U);
		batch_publish = true;
		gpu_firmware_task_publish(&firmware, ops, &service, &client_a, token, 3UL, &result);
		batch_publish = false;
		assert(result.status == GPU_PRIVATE_STATE && !result.value[0]);
		if (scenario == 45U) assert(in0[0] == 128UL && in1[0] == 0UL);
		if (scenario == 46U) assert(in0[0] == 128UL && in1[0] == 128UL && firmware_doorbells == before);
		if (scenario == 51U) assert(in0[0] == 0UL && in1[0] == 0UL && control_writes == written);
		before = firmware_doorbells; written = control_writes;
		gpu_firmware_task_publish(&firmware, ops, &service, &client_a, token, 3UL, &result);
		assert(result.status == GPU_PRIVATE_STATE && !result.value[0] &&
			firmware_doorbells == before && control_writes == written);
		return false;
	}
	/* Queue 0's member may finish while the earlier array member on q1 is
	 * still unpublished. COMPLETE must remain INCOMPLETE and keep the AS.
	 */
	gpu_firmware_task_progress(&firmware, ops, &service, &client_a, token, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == (start_empty ? 0UL : 2UL));
	batch_cs_cleans = batch_cleans = 0U;
	gpu_firmware_task_complete(&firmware, ops, &service, &client_a, token, &result);
	assert(result.status == GPU_PRIVATE_INCOMPLETE && cpu_returns == 0U);
	batch_cs_cleans = batch_cleans = 0U; batch_publish = true;
	gpu_firmware_task_publish(&firmware, ops, &service, &client_a, token, 3UL, &result);
	batch_publish = false;
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == 3UL && in0[0] == 128UL && in1[0] == 128UL);
	before = firmware_doorbells; written = control_writes;
	gpu_firmware_task_publish(&firmware, ops, &service, &client_a, token, 3UL, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && firmware_doorbells == before && control_writes == written);
	batch_cs_cleans = batch_cleans = 0U;
	gpu_firmware_task_progress(&firmware, ops, &service, &client_a, token, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == 3UL && cpu_returns == 0U);
	batch_cs_cleans = batch_cleans = 0U; batch_publish = true;
	gpu_firmware_task_publish(&firmware, ops, &service, &client_a, token, full, &result);
	batch_publish = false;
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == full);
	batch_cs_cleans = batch_cleans = 0U;
	gpu_firmware_task_complete(&firmware, ops, &service, &client_a, token, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == 1UL && cpu_returns == 0U);
	before = firmware_doorbells; written = control_writes;
	gpu_firmware_task_publish(&firmware, ops, &service, &client_a, token, full, &result);
	assert(result.status == GPU_PRIVATE_STATE && firmware_doorbells == before && control_writes == written);
	return true;
}

static void suspend_observe_backend(unsigned long context, unsigned long group,
		unsigned long token, struct gpu_private_ops *ops)
{
	struct gpu_private_result result;
	unsigned int test = suspend_observe_case, before = firmware_doorbells, cpu_before = cpu_returns;
	uint32_t other_as[16];

	memcpy(other_as, registers + 0x2480U / 4U, sizeof(other_as));
	memset(returned_data, 0, sizeof(returned_data));
	suspend_observe_active = true;
	/* Simulate actual GPU work reaching terminal records BEFORE the API call.
	 * Old START stream snapshots intentionally still claim busy until SUSPEND.
	 */
	for (unsigned int q = 0U; q < 2U; q++) {
		uint64_t *in = (void *)(uintptr_t)batch_io[q][0];
		uint64_t *out = (void *)(uintptr_t)batch_io[q][1];
		uint32_t *sync = (void *)(uintptr_t)(batch_sync + q * 16U);

		out[0] = in[0];sync[0] = in[0] / 128UL;sync[1] = sync[2] = sync[3] = 0U;
		model_groups[0].cs_output[q][23] = 1U;
	}
	if (test == 2U) (*(uint64_t *)(uintptr_t)(batch_sync + 16U))--;
	if (test == 3U) (*(uint64_t *)(uintptr_t)batch_io[1][1]) -= 128UL;
	unsigned int reads_before = control_reads, writes_before = writes;
	gpu_firmware_task_finish(&fw_ops, ops, &service, &client_b, token, &result);
	assert(result.status == GPU_PRIVATE_INPUT && control_reads == reads_before &&
		writes == writes_before && firmware_doorbells == before && cpu_returns == cpu_before);
	batch_cleans = batch_cs_cleans = 0U;
	if (test == 20U) {
		gpu_firmware_task_complete(&fw_ops, ops, &service, &client_a, token, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && cpu_returns == cpu_before);
		assert(firmware_doorbells == before + 2U); /* Public COMPLETE still STATUS+SUSPEND. */
	}
	gpu_firmware_task_finish(&fw_ops, ops, &service, &client_a, token, &result);
	bool success = test <= 3U || test == 20U;

	assert(result.status == (success ? GPU_PRIVATE_SUCCESS : GPU_PRIVATE_STATE));
	assert(memcmp(other_as, registers + 0x2480U / 4U, sizeof(other_as)) == 0);
	if (success) {
		assert(result.value[0] == 1UL && cpu_returns == cpu_before + 2U);
		assert(firmware_doorbells == before + (test == 2U || test == 3U || test == 20U ? 2U : 1U));
		gpu_firmware_task_finish(&fw_ops, ops, &service, &client_a, token, &result);
		assert(result.status == GPU_PRIVATE_INPUT);
		gpu_private_unmap(&private_ops, &client_a, context, 0x100000UL, 2UL, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
	} else {
		assert(cpu_returns == cpu_before);
		gpu_firmware_group_destroy(ops, &client_a, group, &result);
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_firmware_task_return(&fw_ops, ops, &service, &client_a, token, &result);
		assert(result.status == GPU_PRIVATE_STATE && cpu_returns == cpu_before);
		gpu_firmware_task_cancel(&client_a, token, &result);assert(result.status == GPU_PRIVATE_STATE);
		gpu_private_unmap(&private_ops, &client_a, context, 0x100000UL, 2UL, &result);
		assert(result.status == GPU_PRIVATE_STATE);
	}
	suspend_observe_active = false;
	printf("GPU_SUSPEND_OBSERVE=PASS case=%u success=%u doors=%u current SUSPEND snapshot, real AS disable, postread check, CPU return and retirement, other Client AS unchanged; MODEL_ONLY\n",
		test, success ? 1U : 0U, firmware_doorbells - before);
}

static void persistent_batch_reuse(unsigned long context, unsigned long group,
		const struct gpu_firmware_group_resources *resources, struct gpu_private_ops *ops)
{
	struct gpu_private_result result;
	struct gpu_firmware_task_command commands[3] = {
		{ .start = 0x100000UL, .bytes = 8U, .queue = 1U },
		{ .start = 0x101000UL, .bytes = 8U, .queue = 0U }, { .queue = 1U }
	};
	unsigned int rounds = persistent_case == 1U && resume_accept_case <= 1U && !suspend_observe_case ? 38U : 1U;
	unsigned long last = 0UL;

	for (unsigned int round = 0U; round < rounds; round++) {
		as_count = 0U;
		unsigned int before = firmware_doorbells;
		gpu_firmware_task_stage_batch(ops, &service, &client_a, group,
			persistent_case == 9U ? commands + 1U : commands,
			persistent_case == 9U ? 1U : 3U,
			resume_accept_case && resume_accept_case != 3U ? GPU_PRIVATE_TASK_DEFERRED : 0UL, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		unsigned long token = result.value[0];

		assert(token != last);
		last = token;
		if (persistent_case == 6U) *(uint64_t *)(batch_io[0][0] + 64UL) = 1UL;
		if (persistent_case == 12U) model_groups[0].input[0] ^= 2U;
		if (persistent_case == 13U) model_groups[0].cs_input[0][0] |= 1U;
		if (persistent_case == 14U) model_groups[0].cs_output[0][0] |= 1U << 30U;
		batch_trace = false;
		if (resume_accept_case && resume_accept_case != 3U)
			gpu_firmware_task_prepare_launch(&fw_ops, ops, &service, &client_a, context, group, token, &result);
		else
		gpu_firmware_task_prepare(&fw_ops, ops, &service, &client_a, context, group, token, &result);
		if (persistent_case >= 12U) {
			assert(result.status == GPU_PRIVATE_STATE && firmware_doorbells == before);
			break;
		}
		assert(result.status == GPU_PRIVATE_SUCCESS);
		for (unsigned int q = 0U; q < 2U; q++) {
			uint64_t base = (round + 1UL) * batch_counts[q] * 128UL;
			uint64_t *in = (void *)(uintptr_t)batch_io[q][0];
			unsigned int page = (unsigned int)((resources->ring_va[q] - GPU_PRIVATE_CONTROL_GPU_VA) / 4096UL);
			const uint64_t *wrapper = (void *)(donated_pages[page] + (base & 4095UL));

			unsigned int added = persistent_case == 9U ? (q == 0U ? 1U : 0U) : batch_counts[q];

			assert(in[0] == base + (resume_accept_case && resume_accept_case != 3U ? 0UL : added * 128UL) && in[1] == base);
			if (!added) continue;
			assert((wrapper[0] >> 56U) == 2U && (wrapper[9] >> 56U) == 51U);
		}
		memset(synced_data, 0, sizeof(synced_data));
		if (resume_accept_case && resume_accept_case != 3U) {
			batch_cleans = batch_cs_cleans = 0U;
			batch_trace = true;
			if (resume_accept_case == 2U) model_groups[0].cs_output[1][0] &= ~7U;
			if (resume_accept_case == 13U) {
				unsigned int control_before = control_writes;
				gpu_firmware_task_ready_launch(&fw_ops, ops, &service, &client_b, token, &result);
				assert(result.status == GPU_PRIVATE_INPUT && firmware_doorbells == before && control_writes == control_before);
			}
			do { gpu_firmware_task_ready_launch(&fw_ops, ops, &service, &client_a, token, &result); }
			while (result.status == GPU_PRIVATE_INCOMPLETE);
			assert(result.status == GPU_PRIVATE_SUCCESS && cpu_returns == 2U * (round + 1U));
			assert(firmware_doorbells == before + (resume_accept_case == 2U ? 2U : 1U));
			unsigned int accepted_bells = firmware_doorbells;
			gpu_firmware_task_ready_launch(&fw_ops, ops, &service, &client_a, token, &result);
			assert(result.status == GPU_PRIVATE_STATE && firmware_doorbells == accepted_bells);
		} else {
			do { gpu_firmware_task_ready(&fw_ops, ops, &service, &client_a, token, &result); }
			while (result.status == GPU_PRIVATE_INCOMPLETE);
			assert(result.status == GPU_PRIVATE_SUCCESS);
			batch_cleans = batch_cs_cleans = 0U;
			batch_trace = true;
			if (persistent_case == 9U) {
				gpu_firmware_task_start(&fw_ops, ops, &service, &client_b, context, group, token, &result);
				assert(result.status == GPU_PRIVATE_INPUT && firmware_doorbells == before);
			}
			gpu_firmware_task_start(&fw_ops, ops, &service, &client_a, context, group, token, &result);
			assert(result.status == GPU_PRIVATE_SUCCESS);
			if (resume_accept_case == 3U) assert(firmware_doorbells == before + 2U);
		}
		assert((model_groups[0].input[0] & 7U) == 3U);
		assert(model_queue_state == UINT64_C(0xc5f123456789abcd));
		if (resume_accept_case == 14U) {
			unsigned int accepted_bells = firmware_doorbells;
			gpu_firmware_task_start(&fw_ops, ops, &service, &client_a, context, group, token, &result);
			assert(result.status == GPU_PRIVATE_SUCCESS && firmware_doorbells == accepted_bells);
		}
		if (suspend_observe_case != 0U) {
			suspend_observe_backend(context, group, token, ops);
			break;
		}
		unsigned int cpu_before_complete = cpu_returns;
		if (resume_accept_case >= 4U && resume_accept_case <= 12U) {
			const unsigned int injected[] = {3U, 13U, 12U, 4U, 5U, 30U, 23U, 7U, 8U};
			batch_case = injected[resume_accept_case - 4U];
		}
		if (resume_accept_case == 15U) model_groups[0].cs_output[2][0] ^= 1U << 26U;
		if (resume_accept_case == 16U) model_groups[0].cs_output[2][32] = 7U;
		batch_cleans = batch_cs_cleans = 0U;
		gpu_firmware_task_complete(&fw_ops, ops, &service, &client_a, token, &result);
		if ((resume_accept_case >= 5U && resume_accept_case <= 12U) || resume_accept_case >= 15U) {
			assert(result.status == GPU_PRIVATE_STATE && cpu_returns == cpu_before_complete);
			gpu_firmware_task_return(&fw_ops, ops, &service, &client_a, token, &result);
			assert(result.status == GPU_PRIVATE_STATE && cpu_returns == cpu_before_complete);
			gpu_firmware_task_cancel(&client_a, token, &result);
			assert(result.status == GPU_PRIVATE_STATE);
			gpu_private_unmap(&private_ops, &client_a, context, 0x100000UL, 2UL, &result);
			assert(result.status == GPU_PRIVATE_STATE);
			printf("GPU_RESUME_ACCEPT=PASS case=%u failure quarantines CPU/data/AS holds; MODEL_ONLY\n", resume_accept_case);
			break;
		}
		if (resume_accept_case == 4U) {
			assert(result.status == GPU_PRIVATE_INCOMPLETE && cpu_returns == cpu_before_complete);
			gpu_private_unmap(&private_ops, &client_a, context, 0x100000UL, 2UL, &result);
			assert(result.status == GPU_PRIVATE_STATE);
			batch_case = 0U; model_groups[0].cs_output[1][23] = 0U;
			batch_cleans = batch_cs_cleans = 0U;
			gpu_firmware_task_complete(&fw_ops, ops, &service, &client_a, token, &result);
		}

		if (persistent_case == 7U) {
			assert(result.status == GPU_PRIVATE_STATE);
			gpu_firmware_task_return(&fw_ops, ops, &service, &client_a, token, &result);
			assert(result.status == GPU_PRIVATE_STATE);
			break;
		}
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == 1UL);
		batch_trace = false;
		memset(returned_data, 0, sizeof(returned_data));
		do { gpu_firmware_task_return(&fw_ops, ops, &service, &client_a, token, &result); }
		while (result.status == GPU_PRIVATE_INCOMPLETE);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		if (persistent_case == 8U) fail_control_write = control_writes + 2U;
		gpu_firmware_task_retire(&fw_ops, ops, &service, &client_a, token, &result);
		/* History retirement has no donated-page writes to fail. Case 8's
		 * old injection must now leave the complete retirement successful.
		 */
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[2] == 0UL);
		assert(*(uint64_t *)donated_pages[(resources->suspend_va - GPU_FIRMWARE_CONTROL_VA) / 4096U] ==
			UINT64_C(0xc5f123456789abcd));
		gpu_firmware_task_complete(&fw_ops, ops, &service, &client_a, token, &result);
		assert(result.status == GPU_PRIVATE_INPUT);
	}
	if (resume_accept_case && (resume_accept_case < 5U || resume_accept_case == 13U || resume_accept_case == 14U))
		printf("GPU_RESUME_ACCEPT=PASS case=%u rounds=%u fresh complete/stop/cache/retire retained; MODEL_ONLY\n", resume_accept_case, rounds);
	printf("GPU_PERSISTENT_BATCH=PASS scenario=%u rounds=%u saved native state, RESUME, monotonic ring wrap, stale counter/token rejection and uncertain state retained; MODEL_ONLY\n", persistent_case, rounds);
}

static unsigned int ready_publish_case;

static void task_ready_publish_backend(const struct gpu_private_ops *ops,
		unsigned long context, unsigned long group, unsigned long token,
		const struct gpu_firmware_group_resources *resources, unsigned int count)
{
	struct gpu_private_result result;
	unsigned int before = writes, written = control_writes, bells = firmware_doorbells;
	unsigned int calls = 0U;
	unsigned int test = ready_publish_case;
	unsigned int io = (resources->input_va[0] - GPU_FIRMWARE_CONTROL_VA) / 4096U;
	unsigned int at = (0x2400U + model_groups[0].input[20] * 0x40U) / 4U;

	if (test >= 5U && test <= 8U) {
		gpu_firmware_task_ready_publish(&fw_ops, ops, test == 5U ? &stranger : &service,
			test == 6U ? &client_b : test == 7U ? &service : &client_a,
			test == 8U ? token + 1UL : token, &result);
		assert(result.status == GPU_PRIVATE_INPUT && data_syncs == 0U &&
			control_writes == written && writes == before);
	}
	if (test == 10U) fail_data_sync = data_syncs + 2U;
	if (test == 11U) registers[at] ^= 0x1000U;
	if (test == 12U) fault_after_data_sync = data_syncs + 1U;
	if (test == 13U) *(uint64_t *)donated_pages[io] += 128UL;
	if (test == 14U) model_groups[0].input[2] ^= 1U;
	if (test == 15U || test == 16U) fail_control_write = written + test - 14U;
	if (test == 18U) {
		do {
			gpu_firmware_task_ready(&fw_ops, ops, &service, &client_a, token, &result);
		} while (result.status == GPU_PRIVATE_INCOMPLETE);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		gpu_firmware_task_publish(&fw_ops, ops, &service, &client_a, token, 2UL, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == 2UL);
		written = control_writes;
	}
	do {
		unsigned int old_syncs = data_syncs;

		gpu_firmware_task_ready_publish(&fw_ops, ops, &service, &client_a, token, &result);
		assert(++calls < GPU_PRIVATE_TABLES + 2U && data_syncs - old_syncs <= GPU_PRIVATE_BATCH);
		if (result.status == GPU_PRIVATE_INCOMPLETE) {
			assert(test == 3U && !result.value[0] && result.value[1] == 1UL &&
				result.value[2] <= sync_expected_pages && !result.value[3]);
			assert(control_writes == written && firmware_doorbells == bells && writes == before);
			gpu_firmware_task_start(&fw_ops, ops, &service, &client_a, context, group, token, &result);
			assert(result.status == GPU_PRIVATE_STATE && firmware_doorbells == bells);
			result.status = GPU_PRIVATE_INCOMPLETE;
		}
	} while (result.status == GPU_PRIVATE_INCOMPLETE);
	assert(firmware_doorbells == bells && writes == before && cpu_returns == 0U);
	if (test == 9U || (test >= 10U && test <= 16U) || test == 18U) {
		assert(result.status == GPU_PRIVATE_STATE);
		if (test == 9U || test == 11U) assert(data_syncs == 0U);
		if (test >= 10U && test <= 16U) {
			gpu_firmware_group_inspect(&service, &client_a, group, &result);
			assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_GROUP_QUARANTINED);
		}
	} else {
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == 1UL &&
			result.value[1] == 1UL && result.value[2] == sync_expected_pages && !result.value[3]);
		assert(data_syncs == sync_expected_pages && control_writes == written + 2U);
		assert(test != 3U || calls >= 2U);
		for (unsigned int q = 0U; q < 2U; q++) {
			unsigned int in = (resources->input_va[q] - GPU_FIRMWARE_CONTROL_VA) / 4096U;
			assert(*(uint64_t *)donated_pages[in] == batch_counts[q] * 128UL);
		}
		unsigned int after = control_writes;

		gpu_firmware_task_ready_publish(&fw_ops, ops, &service, &client_a, token, &result);
		assert(result.status == GPU_PRIVATE_STATE && control_writes == after && data_syncs == sync_expected_pages);
		/* Full publication alone never proves completion or permits data return. */
		gpu_firmware_task_complete(&fw_ops, ops, &service, &client_a, token, &result);
		assert(result.status == GPU_PRIVATE_STATE && firmware_doorbells == bells);
		if (test == 17U) {
			batch_mode = batch_trace = true;
			batch_cs_cleans = batch_cleans = 0U;
			launch_csg = 0U; launch_queue = 1U;
			gpu_firmware_task_start(&fw_ops, ops, &service, &client_a, context, group, token, &result);
			assert(result.status == GPU_PRIVATE_SUCCESS);
			after = firmware_doorbells;
			gpu_firmware_task_ready_publish(&fw_ops, ops, &service, &client_a, token, &result);
			assert(result.status == GPU_PRIVATE_STATE && firmware_doorbells == after);
		}
	}
	printf("GPU_TASK_READY_PUBLISH=PASS case=%u members=%u calls=%u pages=%u; MODEL_ONLY\n",
		test, count, calls, data_syncs);
}

static unsigned int ready_launch_case;

static void task_ready_launch_backend(const struct gpu_private_ops *ops,
		unsigned long context, unsigned long group, unsigned long token,
		const struct gpu_firmware_group_resources *resources)
{
	struct gpu_private_result result;
	unsigned int test = ready_launch_case, calls = 0U;
	unsigned int before = writes, written = control_writes, bells = firmware_doorbells;
	unsigned int io = (resources->input_va[0] - GPU_FIRMWARE_CONTROL_VA) / 4096U;
	unsigned int at = (0x2400U + model_groups[0].input[20] * 0x40U) / 4U;

	if (test >= 5U && test <= 8U) {
		gpu_firmware_task_ready_launch(&fw_ops, ops, test == 5U ? &stranger : &service,
			test == 6U ? &client_b : test == 7U ? &service : &client_a,
			test == 8U ? token + 1UL : token, &result);
		assert(result.status == GPU_PRIVATE_INPUT && data_syncs == 0U &&
			writes == before && control_writes == written && firmware_doorbells == bells);
	}
	if (test == 10U) fail_data_sync = data_syncs + 2U;
	if (test == 11U) registers[at] ^= 0x1000U;
	if (test == 12U) fault_after_data_sync = data_syncs + 1U;
	if (test == 13U) *(uint64_t *)donated_pages[io] += 128UL;
	if (test == 14U) model_groups[0].input[2] ^= 1U;
	if (test == 15U || test == 16U) fail_control_write = written + test - 14U;
	if (test == 18U) {
		gpu_firmware_task_prepare_launch(&fw_ops, ops, &service, &client_a, context, group, token, &result);
		assert(result.status == GPU_PRIVATE_STATE && writes == before && control_writes == written);
	}
	batch_mode = batch_trace = true;
	batch_cs_cleans = batch_cleans = 0U;
	launch_csg = 0U; launch_queue = 1U;
	first_launch_exact = test == 24U;
	if (test == 19U) batch_case = 1U; /* One real stream never acknowledges START. */
	if (test == 20U) batch_case = 15U; /* Inactive stream becomes active on START. */
	if (test == 21U) {
		gpu_firmware_task_quiesce(&fw_ops, ops, &service, &client_a, context, group, token, &result);
		assert(result.status == GPU_PRIVATE_STATE); /* Revoked; holds quarantined, not reclaimed. */
		before = writes; written = control_writes; bells = firmware_doorbells;
	}
	if (test == 22U) {
		gpu_firmware_task_ready_publish(&fw_ops, ops, &service, &client_a, token, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && firmware_doorbells == bells);
		written = control_writes;
	}
	do {
		unsigned int old_syncs = data_syncs;

		gpu_firmware_task_ready_launch(&fw_ops, ops, &service, &client_a, token, &result);
		assert(++calls < GPU_PRIVATE_TABLES + 2U && data_syncs - old_syncs <= GPU_PRIVATE_BATCH);
		if (result.status == GPU_PRIVATE_INCOMPLETE) {
			assert(test == 3U && !result.value[0] && result.value[1] == 1UL && !result.value[3]);
			assert(firmware_doorbells == bells && writes == before && control_writes == written);
		}
	} while (result.status == GPU_PRIVATE_INCOMPLETE);
	assert(cpu_returns == 0U);
	if (test == 9U || (test >= 10U && test <= 17U) || (test >= 19U && test <= 22U)) {
		assert(result.status == GPU_PRIVATE_STATE);
		if (test == 9U || test == 11U || test == 17U || test == 21U) assert(data_syncs == 0U);
		if (test < 19U || test == 21U || test == 22U) assert(firmware_doorbells == bells);
	} else {
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == 1UL &&
			result.value[1] == 1UL && result.value[2] == sync_expected_pages && !result.value[3]);
		assert(data_syncs == sync_expected_pages && firmware_doorbells == bells + 2U);
		assert(test != 3U || calls >= 2U);
		gpu_firmware_group_inspect(&service, &client_a, group, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_GROUP_STARTED);
	}
	first_launch_exact = false;
	before = writes; written = control_writes; bells = firmware_doorbells;
	gpu_firmware_task_ready_launch(&fw_ops, ops, &service, &client_a, token, &result);
	assert(result.status == GPU_PRIVATE_STATE && writes == before &&
		control_writes == written && firmware_doorbells == bells && cpu_returns == 0U);
	if (test == 23U) {
		return_expected_base = sync_expected_base; return_expected_pages = 2UL;
		memset(returned_data, 0, sizeof(returned_data));
		batch_cs_cleans = batch_cleans = 0U;
		gpu_firmware_task_complete(&fw_ops, ops, &service, &client_a, token, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == 1UL);
		do {
			gpu_firmware_task_reclaim(&fw_ops, ops, &service, &client_a, token, &result);
		} while (result.status == GPU_PRIVATE_INCOMPLETE);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		gpu_firmware_task_ready_launch(&fw_ops, ops, &service, &client_a, token, &result);
		assert(result.status == GPU_PRIVATE_INPUT);
	}
	printf("GPU_TASK_READY_LAUNCH=PASS case=%u calls=%u pages=%u one-shot service selection, full Client readiness/publication/START; MODEL_ONLY\n",
		test, calls, data_syncs);
}

static void dispatch_request(const struct gpu_private_ops *ops, const void *svc,
        const void *owner, unsigned long context, unsigned long group,
        unsigned long token, struct gpu_private_result *r)
{
#ifdef GPU_DOMAIN_RSI_TEST
    (void)ops; /* RSI selects the fixed production adapter. */
    domain_rsi_call(svc, GPU_PRIVATE_TASK_DISPATCH, token,
        owner == &client_a ? 7UL : owner == &client_b ? 8UL : 99UL,
        context, group, 0UL, 0UL, r);
#else
    gpu_firmware_task_dispatch(&fw_ops, ops, svc, owner, context, group, token, r);
#endif
}

static void dispatch_stage(const struct gpu_private_ops *ops, unsigned long group,
        const struct gpu_firmware_task_command *commands, unsigned int count,
        unsigned long flags, struct gpu_private_result *r)
{
#ifdef GPU_DOMAIN_RSI_TEST
    (void)ops;
    domain_rsi_call(&client_a, GPU_PRIVATE_TASK_STAGE_BATCH, group,
        (unsigned long)(uintptr_t)commands, 7UL, count, flags, 0UL, r);
#else
    gpu_firmware_task_stage_batch(ops, &service, &client_a, group, commands, count, flags, r);
#endif
}

static void task_dispatch_backend(const struct gpu_private_ops *ops,
        unsigned long context, unsigned long group, unsigned long token,
        const struct gpu_firmware_group_resources *resources, unsigned int pages)
{
    struct gpu_private_result r;
    unsigned int test = dispatch_case, before = writes, controls = control_writes;
    unsigned int bells = firmware_doorbells;

    for (unsigned int q = 0U; q < 2U; q++) {
        unsigned int io = (resources->input_va[q] - GPU_FIRMWARE_CONTROL_VA) / 4096U;
        batch_io[q][0] = (uintptr_t)donated_pages[io];
        batch_io[q][1] = (uintptr_t)donated_pages[io + 1U];
    }
    batch_sync = (uintptr_t)donated_pages[(resources->sync_va - GPU_PRIVATE_CONTROL_GPU_VA) / 4096UL];
    batch_mode = true; batch_trace = false; /* Includes PREPARE control copies. */
    batch_cs_cleans = batch_cleans = 0U;
    launch_csg = 0U; launch_queue = 1U;
    sync_expected_base = 0x40400000UL; sync_expected_pages = pages;
    memset(synced_data, 0, sizeof(synced_data));
    if (test >= 4U && test <= 8U) {
        dispatch_request(ops, test == 4U ? &stranger : &service,
            test == 5U ? &client_b : &client_a,
            test == 6U ? context + 1UL : context,
            test == 7U ? group + 1UL : group, test == 8U ? token + 1UL : token, &r);
        assert(r.status != GPU_PRIVATE_SUCCESS && writes == before &&
            control_writes == controls && firmware_doorbells == bells && !data_syncs);
    }
    if (test == 9U) {
        gpu_firmware_task_prepare_launch(&fw_ops, ops, &service, &client_a,
            context, group, token, &r);
        assert(r.status == GPU_PRIVATE_SUCCESS);
    }
    if (test == 10U) fail_data_sync = data_syncs + 1U;
    if (test == 11U) fail_control_write = control_writes + 1U;
    if (test == 12U) batch_case = 1U;
    dispatch_request(ops, &service, &client_a, context, group, token, &r);
    if (test == 2U || test >= 9U) {
        assert(r.status != GPU_PRIVATE_SUCCESS);
        if (test == 2U) assert(writes == before && control_writes == controls && !data_syncs);
    } else {
        assert(r.status == GPU_PRIVATE_SUCCESS && r.value[0] == (test == 3U ? 4UL : 5UL) &&
            r.value[1] == 1UL && !r.value[2] && !r.value[3]);
        if (test == 3U) {
            assert(data_syncs <= GPU_PRIVATE_BATCH && firmware_doorbells == bells);
            do {gpu_firmware_task_ready_launch(&fw_ops, ops, &service, &client_a, token, &r);}
            while (r.status == GPU_PRIVATE_INCOMPLETE);
            assert(r.status == GPU_PRIVATE_SUCCESS);
        }
        assert(data_syncs == pages && cpu_returns == 0U);
        gpu_firmware_group_inspect(&service, &client_a, group, &r);
        assert(r.status == GPU_PRIVATE_SUCCESS && r.value[0] == GPU_FIRMWARE_GROUP_STARTED);
    }
    before = writes; controls = control_writes; bells = firmware_doorbells;
    dispatch_request(ops, &service, &client_a, context, group, token, &r);
    assert(r.status != GPU_PRIVATE_SUCCESS && writes == before && control_writes == controls &&
        firmware_doorbells == bells && !cpu_returns);
    gpu_firmware_task_cancel_staged(ops, &client_a, token, &r);
    assert(r.status == (test == 2U ? GPU_PRIVATE_SUCCESS : GPU_PRIVATE_STATE));
    printf("GPU_TASK_DISPATCH=PASS case=%u explicit consent, real prepare/cache/publish/START, one-shot, bounded Client continuation, retained holds; MODEL_ONLY\n", test);
}

static void task_batch_backend(unsigned long contexts[2], unsigned int scenario)
{
	struct gpu_private_result result;
	struct gpu_firmware_group_resources resources;
	struct gpu_private_ops ops = donated_ops;
	struct gpu_firmware_queue_config queues[2] = {
		{ .ring_bytes = 4096U, .priority = 2U },
		{ .ring_bytes = 4096U, .priority = 7U }
	};
	struct gpu_firmware_task_command commands[6] = {
		{ .start = 0x100000UL, .bytes = 8U, .queue = 1U, .latest_flush = 7U },
		{ .start = 0x101000UL, .bytes = 8U, .queue = 0U, .latest_flush = 8U },
		{ .queue = 1U }, { .queue = 0U }, { .queue = 1U }, { .queue = 0U }
	};
	unsigned long group, token, ipas[2] = { 0x400000UL, 0x401000UL };
	unsigned int count = scenario == 14U || scenario == 33U || scenario == 53U ? 6U : 3U;
	unsigned int pages = ready_publish_case == 3U || (ready_launch_case == 3U || dispatch_case == 3U) ? GPU_PRIVATE_BATCH + 1U : 2U;
	if (ready_publish_case == 2U || ready_launch_case == 2U) count = 6U;

	ops.read_page = batch_read;
	batch_case = scenario;
	batch_counts[0] = count == 6U ? 3U : 1U;
	batch_counts[1] = count == 6U ? 3U : 2U;
	if (scenario == 10U)
		for (unsigned int i = 0U; i < 6U; i++) commands[i].start = commands[i].bytes = 0U;
	gpu_firmware_group_create(&fw_ops, &ops, &service, &client_a, contexts[0], 2UL, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	group = result.value[0];
	gpu_firmware_group_configure(&ops, &service, &client_a, group, queues, 2UL, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	assert(gpu_firmware_group_resources(&service, &client_a, group, &resources));
	gpu_private_bo_create(&client_a, &service, pages * 4096UL, GPU_PRIVATE_READ, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	prepared_bos[0] = result.value[0];
	for (unsigned int j = 0U; j < pages; j++) {
		ipas[0] = 0x400000UL + j * 4096UL;
		gpu_private_bo_append(&private_ops, &client_a, prepared_bos[0], j * 4096UL, ipas, 1U, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
	}
	for (unsigned int j = 0U; j < pages; j += GPU_PRIVATE_BATCH) {
		unsigned int length = pages - j;
		if (length > GPU_PRIVATE_BATCH) length = GPU_PRIVATE_BATCH;
		gpu_private_map(&private_ops, &client_a, contexts[0], prepared_bos[0], j * 4096UL,
			0x100000UL + j * 4096UL, length, GPU_PRIVATE_READ | GPU_PRIVATE_CACHE, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
	}

	gpu_firmware_task_stage_batch(&private_ops, &service, &client_b, group, commands, count, 0UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	if (dispatch_case)
        dispatch_stage(&private_ops, group, commands, count, GPU_PRIVATE_TASK_DEFERRED |
            (dispatch_case != 2U ? GPU_PRIVATE_TASK_DELEGATE : 0UL), &result);
    else {
	gpu_firmware_task_stage_batch(&private_ops, &service, &client_a, group, commands, count,
		scenario >= 36U && ready_publish_case != 9U && ready_launch_case != 9U ?
        GPU_PRIVATE_TASK_DEFERRED | (dispatch_case && dispatch_case != 2U ? GPU_PRIVATE_TASK_DELEGATE : 0UL) : 0UL, &result);
    }
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[1] == count && result.value[2] == 3U);
	token = result.value[0];
	last_prepared_task = token;
	if (scenario >= 18U) {
		unsigned int before = firmware_doorbells;

		gpu_firmware_task_progress(&fw_ops, &ops, &service, &client_a, token, &result);
		assert(result.status == GPU_PRIVATE_STATE && firmware_doorbells == before);
	}
	memset(commands, 0xff, sizeof(commands));
	if (ready_publish_case == 4U) {
		gpu_firmware_task_ready_publish(&fw_ops, &ops, &service, &client_a, token, &result);
		assert(result.status == GPU_PRIVATE_STATE && data_syncs == 0U && firmware_doorbells == 1U);
	}
	if (scenario == 11U) fail_control_write = control_writes + 2U;
	if (scenario == 36U || scenario == 37U) {
		/* A stopped slot can retain ACK=1 for endpoint configuration,
		 * independently of the status toggle. Preparing it must not turn
		 * that acknowledged state into an unsolicited pending request.
		 */
		model_groups[0].input[0] = model_groups[0].output[0] =
			(1U << 4U) | (scenario == 37U ? 1U << 5U : 0U);
	}
	if (dispatch_case) {
        task_dispatch_backend(&ops, contexts[0], group, token, &resources, pages);
        if (dispatch_case == 2U) goto finish;
        goto retained;
    }
	if (ready_launch_case == 4U) {
		gpu_firmware_task_ready_launch(&fw_ops, &ops, &service, &client_a, token, &result);
		assert(result.status == GPU_PRIVATE_STATE && data_syncs == 0U && firmware_doorbells == 1U);
	}
	if (ready_launch_case == 24U) {
		unsigned int before = writes, written = control_writes;
		for (unsigned int i = 0U; i < 4U; i++) {
			gpu_firmware_task_prepare_launch(&fw_ops, &ops, i == 0U ? &stranger : &service,
				i == 1U ? &client_b : &client_a, i == 2U ? contexts[1] : contexts[0],
				i == 3U ? group + 1UL : group, token, &result);
			assert(result.status != GPU_PRIVATE_SUCCESS && writes == before && control_writes == written);
		}
	}
	if (ready_launch_case == 9U) {
		unsigned int before = writes, written = control_writes;
		gpu_firmware_task_prepare_launch(&fw_ops, &ops, &service, &client_a, contexts[0], group, token, &result);
		assert(result.status == GPU_PRIVATE_STATE && writes == before && control_writes == written);
	}
	if (ready_launch_case && ready_launch_case != 9U && ready_launch_case != 17U)
		gpu_firmware_task_prepare_launch(&fw_ops, &ops, &service, &client_a, contexts[0], group, token, &result);
	else
		gpu_firmware_task_prepare(&fw_ops, &ops, &service, &client_a, contexts[0], group, token, &result);
	if (ready_launch_case == 17U) {
		unsigned int before = writes, written = control_writes;
		struct gpu_private_result prepared = result;
		gpu_firmware_task_prepare_launch(&fw_ops, &ops, &service, &client_a, contexts[0], group, token, &result);
		assert(result.status == GPU_PRIVATE_STATE && writes == before && control_writes == written);
		result = prepared;
	}
	if (scenario == 11U) {
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_firmware_task_cancel(&client_a, token, &result);
		assert(result.status == GPU_PRIVATE_STATE);
		goto finish;
	}
	assert(result.status == GPU_PRIVATE_SUCCESS);
	if (scenario == 36U || scenario == 37U) {
		assert(((model_groups[0].input[0] ^ model_groups[0].output[0]) & 0x30U) == 0U);
		assert((model_groups[0].input[0] & 7U) == 0U && firmware_doorbells == 1U);
	}
	for (unsigned int q = 0U; q < 2U; q++) {
		unsigned int ring = (unsigned int)((resources.ring_va[q] - GPU_PRIVATE_CONTROL_GPU_VA) / 4096UL);
		unsigned int in = (resources.input_va[q] - GPU_FIRMWARE_CONTROL_VA) / 4096U;

		batch_io[q][0] = (uintptr_t)donated_pages[in];
		batch_io[q][1] = (uintptr_t)donated_pages[in + 1U];
		assert(*(uint64_t *)donated_pages[in] == (scenario >= 36U && ready_publish_case != 9U && ready_launch_case != 9U ? 0UL : batch_counts[q] * 128UL));
		uint64_t sync_value = 0U;

		for (unsigned int j = 0U; j < batch_counts[q]; j++) {
			const uint64_t *wrapper = (void *)(donated_pages[ring] + j * 128U);

			/* Execute the completion MOV48 + SYNC_ADD64 arithmetic. Using
			 * member ordinals as addends creates triangular counts (1,3,6),
			 * which must never be accepted as the observed prefix (1,2,3).
			 * This is instruction-semantics modeling, not GPU execution.
			 */
			assert((wrapper[7] >> 56U) == 1U && (wrapper[9] >> 56U) == 51U);
			assert(((wrapper[7] >> 48U) & 255U) == ((wrapper[9] >> 32U) & 255U));
			sync_value += wrapper[7] & UINT64_C(0xffffffffffff);
			assert(sync_value == j + 1U);
			if (j == 0U && scenario != 10U)
				assert((wrapper[2] & UINT64_C(0xffffffffffff)) == (q == 0U ? 0x101000UL : 0x100000UL));
			else
				for (unsigned int w = 2U; w <= 5U; w++) assert(wrapper[w] == 0U);
		}
	}
	batch_sync = (uintptr_t)donated_pages[(resources.sync_va - GPU_PRIVATE_CONTROL_GPU_VA) / 4096UL];
	sync_expected_base = 0x40400000UL;
	sync_expected_pages = 2UL;
	memset(synced_data, 0, sizeof(synced_data));
	if (ready_launch_case != 0U) {
		sync_expected_pages = pages;
		task_ready_launch_backend(&ops, contexts[0], group, token, &resources);
		if (ready_launch_case == 23U) {
			gpu_private_unmap(&private_ops, &client_a, contexts[0], 0x100000UL, 2UL, &result);
			assert(result.status == GPU_PRIVATE_SUCCESS); /* Reclaimed token left no mapping hold. */
			goto finish;
		}
		goto retained;
	}
	if (ready_publish_case != 0U) {
		sync_expected_pages = pages;
		task_ready_publish_backend(&ops, contexts[0], group, token, &resources, count);
		goto retained;
	}
	if (scenario == 42U) {
		unsigned int before = control_writes;

		gpu_firmware_task_publish(&fw_ops, &ops, &service, &client_a, token, 2UL, &result);
		assert(result.status == GPU_PRIVATE_STATE && control_writes == before && data_syncs == 0U);
	}
	do {
		gpu_firmware_task_ready(&fw_ops, &ops, &service, &client_a, token, &result);
	} while (result.status == GPU_PRIVATE_INCOMPLETE);
	assert(result.status == GPU_PRIVATE_SUCCESS && data_syncs == 2U);
	batch_mode = batch_trace = true;
	batch_cs_cleans = batch_cleans = 0U;
	launch_csg = 0U; launch_queue = 1U;
	if (scenario >= 36U) {
		if (task_publication_backend(&ops, contexts[0], group, token, count, scenario))
			goto completed;
		goto retained;
	}
	gpu_firmware_task_start(&fw_ops, &ops, &service, &client_a, contexts[0], group, token, &result);
	if (scenario == 1U || scenario == 15U) {
		assert(result.status == GPU_PRIVATE_STATE);
		goto retained;
	}
	assert(result.status == GPU_PRIVATE_SUCCESS && batch_cs_cleans == 2U);
	unsigned int doorbells = firmware_doorbells, before = writes;

	batch_cs_cleans = batch_cleans = 0U;
	gpu_firmware_task_start(&fw_ops, &ops, &service, &client_a, contexts[0], group, token, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && firmware_doorbells == doorbells && writes == before);
	if (scenario >= 18U) {
		gpu_firmware_task_progress(&fw_ops, &ops, &service, &client_b, token, &result);
		assert(result.status == GPU_PRIVATE_INPUT && firmware_doorbells == doorbells);
		gpu_firmware_task_progress(&fw_ops, &ops, &service, &service, token, &result);
		assert(result.status == GPU_PRIVATE_INPUT && firmware_doorbells == doorbells);
		gpu_firmware_task_progress(&fw_ops, &ops, &client_b, &client_a, token, &result);
		assert(result.status == GPU_PRIVATE_INPUT && firmware_doorbells == doorbells);
		if (scenario == 31U) model_groups[0].input[0] ^= 1U << 5U;
		batch_cs_cleans = batch_cleans = 0U;
		gpu_firmware_task_progress(&fw_ops, &ops, &service, &client_a, token, &result);
		if (scenario >= 25U && scenario <= 30U) {
			assert(result.status == GPU_PRIVATE_STATE && !result.value[0]);
			unsigned int after_failure = firmware_doorbells;

			gpu_firmware_task_progress(&fw_ops, &ops, &service, &client_a, token, &result);
			assert(result.status == GPU_PRIVATE_STATE && !result.value[0] &&
				firmware_doorbells == after_failure);
			goto retained;
		}
		uint32_t expected = scenario == 19U || scenario == 35U ? 2U :
			(scenario >= 20U && scenario <= 22U) ? 1U :
			(scenario == 23U || scenario == 31U || scenario == 32U) ? 0U :
			scenario == 33U ? 11U : 7U;

		assert(result.status == (scenario == 31U ? GPU_PRIVATE_INCOMPLETE : GPU_PRIVATE_SUCCESS));
		assert(result.value[0] == expected && result.value[1] == count &&
			result.value[2] == 3U && !result.value[3]);
		assert(firmware_doorbells == doorbells + (scenario == 31U ? 0U : 1U));
		assert(data_syncs == 2U && cpu_returns == 0U);
		if (scenario == 18U) {
			batch_cs_cleans = batch_cleans = 0U;
			gpu_firmware_task_progress(&fw_ops, &ops, &service, &client_a, token, &result);
			assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == expected &&
				firmware_doorbells == doorbells + 2U && cpu_returns == 0U);
		}
		assert((registers[(0x2400U + model_groups[0].input[20] * 0x40U) / 4U] |
			registers[(0x2404U + model_groups[0].input[20] * 0x40U) / 4U]) != 0U);
		/* Even all-member progress cannot be used as success or to recycle. */
		gpu_firmware_task_return(&fw_ops, &ops, &service, &client_a, token, &result);
		assert(result.status == GPU_PRIVATE_STATE && cpu_returns == 0U);
		gpu_private_unmap(&private_ops, &client_a, contexts[0], 0x100000UL, 2UL, &result);
		assert(result.status == GPU_PRIVATE_STATE);
		if (scenario == 24U) {
			batch_case = 19U; batch_cs_cleans = batch_cleans = 0U;
			gpu_firmware_task_progress(&fw_ops, &ops, &service, &client_a, token, &result);
			assert(result.status == GPU_PRIVATE_STATE && !result.value[0]);
			goto retained;
		}
		if (scenario == 31U) model_groups[0].input[0] ^= 1U << 5U;
		if (scenario == 34U) {
			batch_cs_cleans = batch_cleans = 0U;
			gpu_firmware_task_complete(&fw_ops, &ops, &service, &client_a, token, &result);
			assert(result.status == GPU_PRIVATE_INCOMPLETE && !result.value[0]);
		}
		batch_case = 0U;
		model_groups[0].cs_output[1][23] = 0U;
		batch_cs_cleans = batch_cleans = 0U;
		gpu_firmware_task_complete(&fw_ops, &ops, &service, &client_a, token, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == 1UL);
		unsigned int after = firmware_doorbells;

		gpu_firmware_task_progress(&fw_ops, &ops, &service, &client_a, token, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == (1UL << count) - 1UL &&
			result.value[1] == count && result.value[2] == 3UL && firmware_doorbells == after);
		goto completed;
	}
	if (persistent_case != 0U) model_queue_state = UINT64_C(0xc5f123456789abcd);
	gpu_firmware_task_complete(&fw_ops, &ops, &service, &client_b, token, &result);
	assert(result.status == GPU_PRIVATE_INPUT && firmware_doorbells == doorbells);
	gpu_firmware_task_complete(&fw_ops, &ops, &service, &client_a, token, &result);
	if (scenario == 2U || scenario == 3U || scenario == 17U) {
		assert(result.status == GPU_PRIVATE_INCOMPLETE && firmware_doorbells == doorbells + 1U);
		assert((registers[(0x2400U + model_groups[0].input[20] * 0x40U) / 4U] |
			registers[(0x2404U + model_groups[0].input[20] * 0x40U) / 4U]) != 0U);
		if (scenario != 2U)
			goto retained;
		batch_case = 0U;
		batch_cs_cleans = batch_cleans = 0U;
		gpu_firmware_task_complete(&fw_ops, &ops, &service, &client_a, token, &result);
		assert(firmware_doorbells == doorbells + 3U); /* Prior pending status, fresh status, SUSPEND. */
	}
	if ((persistent_case >= 2U && persistent_case <= 5U) ||
	    persistent_case == 10U || persistent_case == 11U) {
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_firmware_task_return(&fw_ops, &ops, &service, &client_a, token, &result);
		assert(result.status == GPU_PRIVATE_STATE && cpu_returns == 0U);
		gpu_firmware_task_cancel(&client_a, token, &result);
		assert(result.status == GPU_PRIVATE_STATE);
		printf("GPU_PERSISTENT_BATCH=PASS scenario=%u suspend failure retains task and pages, no CPU ownership; MODEL_ONLY\n", persistent_case);
		goto finish;
	}
	if (scenario != 0U && scenario != 2U && scenario != 10U && scenario != 14U) {
		assert(result.status == GPU_PRIVATE_STATE);
		goto retained;
	}
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == 1UL);
completed:
	batch_trace = false;
	return_expected_base = sync_expected_base; return_expected_pages = 2UL;
	memset(returned_data, 0, sizeof(returned_data));
	do {
		gpu_firmware_task_return(&fw_ops, &ops, &service, &client_a, token, &result);
	} while (result.status == GPU_PRIVATE_INCOMPLETE);
	assert(result.status == GPU_PRIVATE_SUCCESS && cpu_returns == 2U);
	do {
		gpu_firmware_task_retire(&fw_ops, &ops, &service, &client_a, token, &result);
	} while (result.status == GPU_PRIVATE_INCOMPLETE);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[2] == 0U); /* Continuing group retains its protected state. */
	if (persistent_case != 0U) {
		persistent_batch_reuse(contexts[0], group, &resources, &ops);
		goto finish;
	}
	gpu_private_unmap(&private_ops, &client_a, contexts[0], 0x100000UL, 2UL, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS); /* No extra per-member hold leaked. */
	gpu_firmware_task_cancel(&client_a, token, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	if (scenario >= 18U) {
		gpu_firmware_task_progress(&fw_ops, &ops, &service, &client_a, token, &result);
		assert(result.status == GPU_PRIVATE_INPUT);
	}
	goto finish;
retained:
	batch_trace = false;
	gpu_firmware_task_cancel(&client_a, token, &result);
	assert(result.status == GPU_PRIVATE_STATE && cpu_returns == 0U);
	gpu_firmware_task_return(&fw_ops, &ops, &service, &client_a, token, &result);
	assert(result.status == GPU_PRIVATE_STATE && cpu_returns == 0U);
	gpu_private_unmap(&private_ops, &client_a, contexts[0], 0x100000UL, 2UL, &result);
	assert(result.status == GPU_PRIVATE_STATE);
finish:
	batch_mode = batch_trace = false;
	printf("GPU_TASK_BATCH_BACKEND=PASS scenario=%u ordered duplicate/fence-only members, all-CS publication/ACK, every-queue completion and native SUSPEND barrier, one cache/ref lifecycle, uncertain backing retained; MODEL_ONLY\n", scenario);
	if (scenario >= 18U && scenario < 36U)
		printf("GPU_TASK_PROGRESS_BACKEND=PASS scenario=%u actual common observer, fresh ACK, per-array/per-queue prefix, no STOP/CPU return/reference release; MODEL_ONLY\n", scenario);
	if (scenario >= 36U)
		printf("GPU_TASK_PUBLICATION_BACKEND=PASS scenario=%u actual Client per-queue INSERT prefixes, empty START, partial progress, immutable wrappers, ACK/replay and failed-state retention; MODEL_ONLY\n", scenario);
}

static void task_admission_backend(unsigned long contexts[4], bool partial_prepare)
{
	const void *owners[4] = { &client_a, &client_a, &client_a, &client_b };
	unsigned long task_contexts[4] = { contexts[0], 0UL, 0UL, contexts[1] };
	const struct gpu_firmware_queue_config queue = { .ring_bytes = 4096U };
	const struct gpu_firmware_task_command command = {0}; /* Fence-only. */
	struct gpu_private_result result;
	unsigned long groups[4], tokens[4];
	unsigned int before, controls_before, doors_before, syncs_before;
	static uint32_t saved_registers[sizeof(registers) / sizeof(registers[0])];
	static unsigned char saved_control[sizeof(donated_pages)];

	assert(model_group_count == 3U);
	/* The fixed runtime requires at least three CSGs. Fill all three with
	 * distinct GPUVMs, preserving the per-context execution exclusion.
	 */
	for (unsigned int i = 1U; i < 3U; i++) {
		gpu_private_context_create(&private_ops, &client_a, &service, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		task_contexts[i] = contexts[i + 1U] = result.value[0];
	}
	for (unsigned int i = 0U; i < 4U; i++) {
		gpu_firmware_group_create(&fw_ops, &donated_ops, &service, owners[i],
			task_contexts[i], 1UL, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		groups[i] = result.value[0];
		gpu_firmware_group_configure(&donated_ops, &service, owners[i], groups[i],
			&queue, 1UL, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		gpu_firmware_task_stage_batch(&private_ops, &service, owners[i], groups[i],
			&command, 1U, GPU_PRIVATE_TASK_DEFERRED, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		tokens[i] = result.value[0];
	}
	for (unsigned int i = 0U; i < 3U; i++) {
		fail_control_write = partial_prepare && i == 2U ? control_writes + 1U : 0U;
		gpu_firmware_task_prepare(&fw_ops, &donated_ops, &service, owners[i],
			task_contexts[i], groups[i], tokens[i], &result);
		assert(result.status == (partial_prepare && i == 2U ? GPU_PRIVATE_STATE : GPU_PRIVATE_SUCCESS));
	}
	fail_control_write = 0U;
	before = writes;
	controls_before = control_writes;
	doors_before = firmware_doorbells;
	syncs_before = data_syncs;
	memcpy(saved_registers, registers, sizeof(registers));
	memcpy(saved_control, donated_pages, sizeof(donated_pages));
	for (unsigned int retry = 0U; retry < 3U; retry++) {
		gpu_firmware_task_prepare(&fw_ops, &donated_ops, &service, owners[3],
			task_contexts[3], groups[3], tokens[3], &result);
		assert(result.status == GPU_PRIVATE_FULL);
		for (unsigned int i = 0U; i < 4U; i++)
			assert(result.value[i] == 0UL);
		assert(writes == before && control_writes == controls_before &&
			firmware_doorbells == doors_before && data_syncs == syncs_before);
		assert(memcmp(saved_registers, registers, sizeof(registers)) == 0 &&
			memcmp(saved_control, donated_pages, sizeof(donated_pages)) == 0);
		/* Only the blocked Client may cancel; the prepared/uncertain holder
		 * cannot free its slot or make its token reusable this way.
		 */
		gpu_firmware_task_cancel(owners[0], tokens[3], &result);
		assert(result.status == GPU_PRIVATE_INPUT);
		for (unsigned int i = 0U; i < 3U; i++) {
			gpu_firmware_task_cancel(owners[i], tokens[i], &result);
			assert(result.status == GPU_PRIVATE_STATE);
		}
		gpu_firmware_task_cancel(owners[3], tokens[3], &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		for (unsigned int i = 0U; i < 4U; i++)
			assert(result.value[i] == 0UL);
		gpu_firmware_task_prepare(&fw_ops, &donated_ops, &service, owners[3],
			task_contexts[3], groups[3], tokens[3], &result);
		assert(result.status == GPU_PRIVATE_INPUT);
		unsigned long old = tokens[3];

		gpu_firmware_task_stage_batch(&private_ops, &service, owners[3], groups[3],
			&command, 1U, GPU_PRIVATE_TASK_DEFERRED, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] != old);
		tokens[3] = result.value[0];
	}
	gpu_firmware_task_cancel(owners[3], tokens[3], &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	gpu_firmware_group_destroy(&donated_ops, owners[3], groups[3], &result);
	assert(result.status == GPU_PRIVATE_SUCCESS); /* No leaked task references. */
	assert(writes == before && firmware_doorbells == doors_before);
	printf("GPU_TASK_ADMISSION_BACKEND=PASS partial_prepare=%u three occupied CSGs, two Clients, FULL leaves registers/control unchanged, wrong owner/stale token denied, unprepared cancel and fresh staging, prepared/uncertain holder retained; MODEL_ONLY\n",
		partial_prepare ? 1U : 0U);
}

static void firmware_integration(const char *path)
{
	struct gpu_private_result result, boot_result;
	unsigned char input[4096];
	unsigned long root, offset, arena;
	unsigned long group_contexts[4];
	FILE *file;

	/* End the preceding independent legacy service instance. */
	assert(opencca_gpu_pm_destroy_begin(&service));
	opencca_gpu_mmio_release(&service);
	initialize();
	assert(opencca_gpu_mmio_grant(&service) && opencca_gpu_claim(&service));
	assert(opencca_gpu_service_isolate(&device_ops, &service));
	gpu_private_device_revoked(&private_ops);
	gpu_firmware_device_revoked();
	for (unsigned int phase = domain_dispatch_only ? 465U : 0U; phase < 545U; phase++) {
		/* RELEASE ends the service instance, so its partial-boot case is last. */
		retire_boundary_case = phase >= 192U && phase < 214U ? phase - 191U : 0U;
		complete_boundary_case = phase >= 214U && phase < 229U ? phase - 213U : 0U;
		reclaim_case = phase >= 229U && phase < 250U ? phase - 228U : 0U;
		ready_publish_case = phase >= 250U && phase < 268U ? phase - 249U : 0U;
		fatal_snapshot_case = phase == 268U;
		dispatch_case = phase >= 532U && phase < 544U ? phase - 531U : 0U;
		ready_launch_case = phase >= 269U && phase < 293U ? phase - 268U : 0U;
		finish_case = phase >= 293U && phase < 334U ? phase - 292U : 0U;
		if (phase >= 374U && phase < 404U) finish_case = phase - 332U;
		if (finish_case >= 10U && finish_case <= 24U) complete_boundary_case = finish_case - 9U;
		suspend_observe_case = phase >= 350U && phase < 374U ? phase - 349U : 0U;
		resume_accept_case = phase >= 334U && phase < 350U ? phase - 333U : suspend_observe_case ? 1U : 0U;
		drain_case = phase >= 404U && phase < 465U ? phase - 403U : 0U;
		domain_case = phase >= 465U && phase < 532U ? phase - 464U : 0U;
		domain_active = false; domain_write_fault = domain_read_fault = domain_reads_until_fault = 0U;
		drain_flushes = drain_post_corruption = 0U;
		drain_barrier_failure = false; drain_fault = NULL;
		memset(nc_data_visibility, 0, sizeof(nc_data_visibility));
		unsigned int failure = phase == 544U ? 2U : dispatch_case ? 130U : domain_case || drain_case ? 66U : resume_accept_case ? 180U : finish_case != 0U ? (finish_case == 3U ? 70U : finish_case == 4U ? 81U : 66U) : ready_launch_case != 0U ? 130U : fatal_snapshot_case ? 31U : ready_publish_case != 0U ? 130U : reclaim_case != 0U || complete_boundary_case != 0U ? 66U : retire_boundary_case != 0U ?
			(retire_boundary_case <= 18U ? 66U : 60U) :
			phase >= 175U ? phase + 2U : phase >= 2U ? phase + 1U : phase;

		refresh_failure = failure >= 177U && failure <= 179U ? failure - 176U : 0U;
		persistent_case = failure >= 180U ? failure - 179U : 0U;
		suspend_count = 0U;
		model_queue_state = 0U;
		model_limited_groups = failure >= 148U && failure < 150U;

		control_writes = fail_control_write = as_count = data_syncs = fail_data_sync = fault_after_data_sync = 0U;
		cpu_returns = fail_cpu_return = return_case = 0U;
		control_reads = complete_reads_this_call = status_cleans = 0U;
		track_complete = false;
		prepared_alias_context = 0UL;
		memset(group_contexts, 0, sizeof(group_contexts));
		memset(prepared_bos, 0, sizeof(prepared_bos));
		memset(heap_test_bos, 0, sizeof(heap_test_bos));
		file = fopen(path, "rb");
		assert(file != NULL);
		gpu_firmware_begin(&service, GPU_FIRMWARE_IMAGE_SIZE, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		for (offset = 0UL; offset < GPU_FIRMWARE_IMAGE_SIZE; offset += sizeof(input)) {
			assert(fread(input, 1U, sizeof(input), file) == sizeof(input));
			gpu_firmware_write(&service, offset, input, sizeof(input), &result);
			assert(result.status == GPU_PRIVATE_SUCCESS);
		}
		assert(fgetc(file) == EOF && fclose(file) == 0);
		gpu_firmware_seal(&fw_ops, &service, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		gpu_firmware_prepare(&fw_ops, &service, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		arena = donate_arena();
		allow_firmware = update_firmware_shared = true;
		fail_as_command = failure == 2U ? 1U : 0U;
		gpu_firmware_boot(&fw_ops, &service, &result);
		boot_result = result;
		root = registers[0x2400U / 4U] | ((unsigned long)registers[0x2404U / 4U] << 32U);
		assert(root != 0UL);
		assert((*firmware_leaf(root, 0x00800000UL) & (1UL << 7U)) != 0UL);
		assert((*firmware_leaf(root, 0x00800000UL) & (3UL << 53U)) == 0UL);
		/* Inspect leaves reached from the AS0 root actually installed by the
		 * platform backend, including the next 2 MiB table. No private pointer
		 * is returned to the service API, and even a failed install retains it.
		 */
		for (unsigned int i = 0U; i < CONTROL_TEST_PAGES; i++) {
			uint64_t pte = *firmware_leaf(root, GPU_FIRMWARE_CONTROL_VA + i * 4096UL);

			assert((pte & 0x000000fffffff000UL) == (uintptr_t)donated_pages[i]);
			assert((pte & (3UL << 53U)) == (3UL << 53U));
			assert((pte & (1UL << 7U)) == 0UL && (pte & (7UL << 2U)) == 0UL);
			assert(!donated_visible[i]);
		}
		gpu_private_control_destroy(&donated_ops, &service, arena, &result);
		assert(result.status == GPU_PRIVATE_STATE && !donated_visible[0]);
		/* Model confidential GPU state. Restore must scrub it after reset. */
		memset(donated_pages, 0x5a, sizeof(donated_pages));
		assert(!opencca_gpu_mmio_allowed(&service) && !opencca_gpu_mmio_grant(&service));
		result = boot_result;
		if (failure != 2U) {
			assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_BOOTED);
			assert(firmware_starts == 1U);
			if (model_limited_groups) {
				gpu_firmware_properties(&service, 0UL, &result);
				assert(result.status == GPU_PRIVATE_SUCCESS && result.value[2] == 3UL);
			}
			gpu_firmware_properties(&service, 1UL, &result);
			assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == 8UL);
			assert(result.value[2] == 0x40000UL);
			firmware_acks = failure != 1U;
			gpu_firmware_configure(&fw_ops, &service, &result);
			assert(firmware_doorbells == 1U);
			if (failure != 1U) {
				assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_CONFIGURED);
				gpu_firmware_configure(&fw_ops, &service, &result);
				assert(result.status == GPU_PRIVATE_SUCCESS && firmware_doorbells == 1U);
				group_backend_integration(root, group_contexts);
				if (persistent_case != 0U)
					task_batch_backend(group_contexts, 0U);
				else if (refresh_failure != 0U)
					task_backend_integration(root, group_contexts, 13U);
				else if (failure >= 150U)
					task_heap_backend(root, group_contexts, failure - 150U);
				else if (failure >= 148U)
					task_admission_backend(group_contexts, failure == 149U);
				else if (failure >= 94U)
					task_batch_backend(group_contexts, failure - 94U);
				else
					task_backend_integration(root, group_contexts, failure);
			} else {
				assert(result.status == GPU_PRIVATE_STATE);
				gpu_firmware_inspect(&service, &result);
				assert(result.value[0] == GPU_FIRMWARE_QUARANTINED);
			}
			assert(opencca_gpu_control(&device_ops, NULL, OPENCCA_GPU_RESET, 0UL, 0UL));
			assert(opencca_gpu_service_isolated(&service));
		} else {
			assert(result.status == GPU_PRIVATE_STATE && firmware_starts == 0U);
			gpu_firmware_inspect(&service, &result);
			assert(result.value[0] == GPU_FIRMWARE_QUARANTINED);
			gpu_firmware_begin(&service, GPU_FIRMWARE_IMAGE_SIZE, &result);
			assert(result.status == GPU_PRIVATE_STATE);
			assert(opencca_gpu_control(&device_ops, NULL, OPENCCA_GPU_RELEASE, 0UL, 0UL));
		}
		/* Same reset/release retirement calls as the real RMI adapter. */
		gpu_private_device_revoked(&private_ops);
		gpu_firmware_device_revoked();
		if (prepared_alias_context != 0UL) {
			gpu_private_context_destroy(&private_ops, &client_a, prepared_alias_context, &result);
			assert(result.status == GPU_PRIVATE_SUCCESS);
		}
		for (unsigned int i = 0U; i < 4U; i++) {
			if (group_contexts[i] == 0UL)
				continue;
			gpu_private_context_destroy(&private_ops,
				i == 1U ? &client_b : &client_a, group_contexts[i], &result);
			assert(result.status == GPU_PRIVATE_SUCCESS);
		}
		assert(!donated_visible[0]); /* Reset alone never restores CPU access. */
		for (unsigned int i = 0U; i < 2U; i++) {
			if (prepared_bos[i] == 0UL)
				continue;
			struct gpu_private_ops nc = nc_data_ops();
			do {
				if (drain_nc_client(i))
					gpu_private_bo_release(&nc, i == 0U ? &client_a : &client_b, prepared_bos[i], &result);
				else
					destroy_prepared_bo(i == 0U ? &client_a : &client_b, prepared_bos[i], &result);
			} while (result.status == GPU_PRIVATE_INCOMPLETE);
			assert(result.status == GPU_PRIVATE_SUCCESS);
		}
		for (unsigned int i = 0U; i < 2U; i++) {
			if (heap_test_bos[i] == 0UL) continue;
			do {
				gpu_private_bo_destroy(i == 0U ? &client_a : &client_b, heap_test_bos[i], &result);
			} while (result.status == GPU_PRIVATE_INCOMPLETE);
			assert(result.status == GPU_PRIVATE_SUCCESS);
		}
		gpu_firmware_task_cancel(&client_a, last_prepared_task, &result);
		assert(result.status == GPU_PRIVATE_INPUT);
		gpu_private_control_destroy(&donated_ops, &service, arena, &result);
		assert(result.status == GPU_PRIVATE_INCOMPLETE && result.value[0] == 1UL);
		gpu_private_control_destroy(&donated_ops, &service, arena, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		for (unsigned int i = 0U; i < CONTROL_TEST_PAGES; i++)
			assert(donated_visible[i]);
		assert(registers[0x2400U / 4U] == 0U && registers[0x704U / 4U] == 0U);
		gpu_firmware_inspect(&service, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_EMPTY);
		assert(*(uint64_t *)(uintptr_t)root == 0UL);
		if (fatal_snapshot_case)
			puts("GPU_STREAM_FATAL_SNAPSHOT=PASS fatal-only state rejects START and retains backing; MODEL_ONLY");
		firmware_starts = firmware_doorbells = 0U;
	}
	assert(opencca_gpu_pm_destroy_begin(&service));
	opencca_gpu_mmio_release(&service);
	puts("GPU_FIRMWARE_BACKEND_INTEGRATION=PASS real pinned image, RMM runtime tables and 513 donated pages to actual AS0 register model, RW/XN/NC control leaves, MCU and global configuration ACK handshakes, sanitized properties, raw access denied, install/ACK failure retains CPU-hidden backing, mediated RESET/RELEASE followed by scrub-before-restore; MODEL_ONLY");
}

int main(int argc, char **argv)
{
	assert(argc == 2 || (argc == 3 && strcmp(argv[2], "--domain-only") == 0));
	domain_dispatch_only = argc == 3;
	setvbuf(stdout, NULL, _IONBF, 0);
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
	private_pt();
	private_integration();
	firmware_mmio();
	firmware_integration(argv[1]);
	return 0;
}
