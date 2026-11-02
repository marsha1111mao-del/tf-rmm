/* SPDX-License-Identifier: BSD-3-Clause */
/* Actual RSI task and memory callback chain. GPU/MCU/REC/RTT/cache effects
 * remain host models. This is not shader execution or physical isolation. */
#define GPU_RSI_TASK_CHAIN_TEST
#include "opencca_gpu_rsi_memory_chain_test.c"
#include <stdlib.h>

static unsigned long task_contexts[2], task_bos[2], task_groups[2], task_tokens[2];
static unsigned long task_roots[2], task_arena;
static unsigned int task_fault_case, task_fault_countdown;
static uint32_t *task_fault_word, task_fault_saved;
static unsigned int task_cpu_returns[2];
static unsigned int task_rmi_requests, task_reset_rsi_requests;
static unsigned int task_reclaim_requests;
#define TASK_RECLAIM_ANY_ERROR (~0UL)

static void task_before_cache(unsigned int owner, unsigned int page, bool to_device)
{
	if (!domain_active || owner >= 2U || page < 1U || page > 2U || to_device)
		return;
	unsigned int as = model_groups[owner].input[20];
	unsigned int at = (0x2400U + as * 0x40U) / 4U;
	chain_expect(as > 0U && as < 16U && words64(registers + at, 0) == 0UL &&
		registers[at + 12U] == 1U, "actual CPU return follows AS disable");
	chain_expect((model_groups[owner].input[0] & 7U) == 2U &&
		((model_groups[owner].input[0] ^ model_groups[owner].output[0]) & 0x37U) == 0U,
		"actual CPU return follows acknowledged suspension");
	task_cpu_returns[owner]++;
}

static void task_after_unmap(unsigned int owner, unsigned int page)
{
	/* Armed only during FINISH: corrupt after the real read_page has copied
	 * a protected control snapshot, not before its cache invalidation. */
	if (!task_fault_countdown || owner != 2U || page < 9U || --task_fault_countdown)
		return;
	unsigned int as = model_groups[0].input[20];
	task_fault_word = task_fault_case == 1U ? &registers[(0x2400U + as * 0x40U) / 4U] :
		&model_groups[0].cs_output[0][32];
	task_fault_saved = *task_fault_word;
	*task_fault_word ^= 0x1000U;
}

static void task_upload(const char *path)
{
	unsigned int starts_before = firmware_starts, bells_before = firmware_doorbells;
	/* Fresh firmware global configuration uses the MCU boot/config double,
	 * before the queue-domain double is enabled for the new lifetime. */
	domain_active = false;
	FILE *file = fopen(path, "rb");
	chain_expect(file != NULL, "pinned firmware input opens");
	chain_success(chain_call(2, GPU_PRIVATE_FW_BEGIN, 0, GPU_FIRMWARE_IMAGE_SIZE, 0, 0, 0, 0));
	for (unsigned long offset = 0; offset < GPU_FIRMWARE_IMAGE_SIZE; offset += 4096UL) {
		chain_expect(fread(chain_device[2][0], 1, 4096, file) == 4096, "firmware chunk read");
		memset(chain_cpu[2][0], 0x18, 4096);
		chain_success(chain_call(2, GPU_PRIVATE_FW_WRITE, 0, INPUT_IPA, 4096, offset, 0, 0));
	}
	chain_expect(fgetc(file) == EOF && fclose(file) == 0, "firmware input length exact");
	chain_success(chain_call(2, GPU_PRIVATE_FW_SEAL, 0, 0, 0, 0, 0, 0));
	chain_success(chain_call(2, GPU_PRIVATE_FW_PREPARE, 0, 0, 0, 0, 0, 0));
	struct gpu_private_result r = chain_call(2, GPU_PRIVATE_CONTROL_CREATE, 0, 513UL * 4096UL, 0, 0, 0, 0);
	chain_success(r); task_arena = r.value[0];
	for (unsigned int first = 0; first < 513; first += GPU_PRIVATE_BATCH) {
		unsigned int count = first ? 1U : GPU_PRIVATE_BATCH;
		chain_input(2, ARENA_IPA + first * 4096UL, count);
		chain_success(chain_call(2, GPU_PRIVATE_CONTROL_APPEND, task_arena,
			INPUT_IPA, count, first * 4096UL, 0, 0));
	}
	chain_success(chain_call(2, GPU_PRIVATE_FW_CONTROL_BIND, task_arena, 0, 0, 0, 0, 0));
	allow_firmware = update_firmware_shared = true;
	chain_success(chain_call(2, GPU_PRIVATE_FW_BOOT, 0, 0, 0, 0, 0, 0));
	chain_success(chain_call(2, GPU_PRIVATE_FW_CONFIGURE, 0, 0, 0, 0, 0, 0));
	chain_expect(firmware_starts == starts_before + 1U && firmware_doorbells == bells_before + 1U,
		"actual platform boot/configuration used");
	unsigned long root = words64(registers + 0x2400U / 4U, 0U);
	for (unsigned int p = 0; p < 513; p++) {
		uint64_t pte = *firmware_leaf(root, GPU_FIRMWARE_CONTROL_VA + p * 4096UL);
		chain_expect((pte & UINT64_C(0x000000fffffff000)) == chain_data[2][p + 9U].pa,
			"MCU PTE reaches donated device backing");
		chain_expect((*chain_entry(2, p + 9U) & 4095UL) == 16UL,
			"CPU cannot access donated MCU backing");
	}
	/* Existing MCU double walks actual PTEs and executes wrapper completion
	 * records only. It does not interpret or execute the Client GPU program. */
	domain_active = true;
}

static void task_create(unsigned int c)
{
	struct gpu_private_result r = chain_call(c, GPU_PRIVATE_CONTEXT_CREATE, chain_channels[c], 0, 0, 0, 0, 0);
	chain_success(r); task_contexts[c] = r.value[0]; task_roots[c] = latest_table_pa;
	r = chain_call(c, GPU_PRIVATE_BO_CREATE, chain_channels[c], 8192,
		GPU_PRIVATE_READ | GPU_PRIVATE_WRITE | GPU_PRIVATE_EXEC, 0, 0, 0);
	chain_success(r); task_bos[c] = r.value[0];
	chain_input(c, DATA_IPA, 2);
	chain_success(chain_call(c, GPU_PRIVATE_BO_APPEND, task_bos[c], INPUT_IPA, 2, 0, 0, 0));
	memset(chain_cpu[c][1], 0x70 + c, 4096);
	memset(chain_cpu[c][2], 0x78 + c, 4096);
	unsigned long prot = GPU_PRIVATE_READ | GPU_PRIVATE_WRITE | GPU_PRIVATE_EXEC | GPU_PRIVATE_CACHE;
	r = chain_call(c, GPU_PRIVATE_MAP_AUTHORIZE, task_contexts[c], task_bos[c], 0, 0x800000UL, 2, prot);
	chain_success(r);
	chain_success(chain_call(2, GPU_PRIVATE_SERVICE_MAP, task_contexts[c], chain_channels[c], r.value[0], 0,
		0x800000UL, (2UL << 8U) | prot));
	for (unsigned int p = 0; p < 2; p++)
		chain_expect(chain_leaf(task_roots[c], 0x800000UL + p * 4096UL) == chain_data[c][p + 1U].pa,
			"task GPU root maps only its Client data");
	r = chain_call(c, GPU_PRIVATE_GROUP_CREATE, task_contexts[c], chain_channels[c], 2, 0, 0, 0);
	chain_success(r); task_groups[c] = r.value[0];
	struct gpu_firmware_queue_config queues[2] = {
		{.ring_bytes = 4096, .priority = 2}, {.ring_bytes = 4096, .priority = 3}
	};
	memcpy(chain_device[c][0], queues, sizeof(queues));
	memset(chain_cpu[c][0], 0x19, 4096); chain_mutate = true;
	chain_success(chain_call(c, GPU_PRIVATE_GROUP_CONFIGURE, task_groups[c], INPUT_IPA, chain_channels[c], 2, 0, 0));
	chain_expect(!chain_mutate, "queue config snapshot privately copied");
	struct gpu_firmware_task_command commands[2] = {
		{.start = 0x800000UL, .bytes = 8, .queue = 0},
		{.start = 0x801000UL, .bytes = 8, .queue = 1}
	};
	memcpy(chain_device[c][0], commands, sizeof(commands));
	memset(chain_cpu[c][0], 0x20, 4096); chain_mutate = true;
	r = chain_call(c, GPU_PRIVATE_TASK_STAGE_BATCH, task_groups[c], INPUT_IPA, chain_channels[c], 2,
		GPU_PRIVATE_TASK_DEFERRED | GPU_PRIVATE_TASK_DELEGATE, 0);
	chain_success(r); task_tokens[c] = r.value[0];
	chain_expect(!chain_mutate && r.value[1] == 2 && r.value[2] == 3, "task snapshot binds both queue members");
}

static void task_launch(unsigned int c)
{
	unsigned int before = chain_flushes;
	chain_success(chain_call(2, GPU_PRIVATE_TASK_DISPATCH, task_tokens[c], chain_channels[c],
		task_contexts[c], task_groups[c], 0, 0));
	chain_expect(chain_flushes == before + 2U, "READY flushes actual two Client pages");
	chain_expect(chain_device[c][1][0] == 0x70 + c && chain_device[c][2][0] == 0x78 + c,
		"READY sends private CPU input to correct device backing");
	chain_expect(!opencca_gpu_mmio_allowed(&chain_owners[2]), "driver service retains no raw MMIO authority");
	for (unsigned int p = 9; p < CHAIN_PAGES; p++)
		chain_expect((*chain_entry(2, p) & 4095UL) == 16UL, "control pages stay CPU hidden after START");
}

static void task_bad_requests(unsigned int c)
{
	unsigned int written = writes, cleaned = chain_cleans;
	chain_denied(chain_call(2, GPU_PRIVATE_TASK_DISPATCH, task_tokens[c], chain_channels[1U - c],
		task_contexts[c], task_groups[c], 0, 0));
	chain_denied(chain_call(1U - c, GPU_PRIVATE_TASK_FINISH, task_tokens[c], chain_channels[1U - c], 0, 0, 0, 0));
	chain_denied(chain_call(c, GPU_PRIVATE_TASK_RETURN, task_tokens[c], chain_channels[c], 0, 0, 0, 0));
	chain_denied(chain_call(c, GPU_PRIVATE_TASK_RETIRE, task_tokens[c], chain_channels[c], 0, 0, 0, 0));
	chain_expect(writes == written && chain_cleans == cleaned, "identity/early completion denials never publish or return data");
}

static void task_finish_one(unsigned int c)
{
	/* Model GPU output, separate from CPU bytes. The real CPU-return callback
	 * must invalidate/copy the right Client pages before successful FINISH. */
	memset(chain_device[c][1], 0x40 + c, 4096);
	memset(chain_device[c][2], 0x50 + c, 4096);
	struct gpu_private_result r;
	unsigned int attempts = 0;
	do {
		r = chain_call(c, GPU_PRIVATE_TASK_FINISH, task_tokens[c], chain_channels[c], 0, 0, 0, 0);
		chain_expect(++attempts <= 8U, "bounded complete/return/retire continuation");
	} while (r.status == GPU_PRIVATE_INCOMPLETE);
	chain_success(r);
	chain_expect(r.value[0] == 1 && r.value[1] == 0 && !r.value[2] && !r.value[3], "exact terminal RSI result");
	chain_expect(task_cpu_returns[c] == 2U, "exact two data-page CPU returns");
	for (unsigned int p = 1; p <= 2; p++)
		for (unsigned int i = 0; i < 4096; i++)
			chain_expect(chain_cpu[c][p][i] == (p == 1 ? 0x40 + c : 0x50 + c), "fresh complete CPU output for correct owner");
	unsigned int written = writes, cleaned = chain_cleans, invalidated = chain_invalidates;
	chain_denied(chain_call(c, GPU_PRIVATE_TASK_FINISH, task_tokens[c], chain_channels[c], 0, 0, 0, 0));
	chain_expect(writes == written && chain_cleans == cleaned && chain_invalidates == invalidated,
		"retired token cannot reuse completion or touch backing");
	chain_success(chain_call(c, GPU_PRIVATE_GROUP_DESTROY, task_groups[c], 0, 0, 0, 0, 0));
	chain_success(chain_call(2, GPU_PRIVATE_SERVICE_UNMAP, task_contexts[c], chain_channels[c], 0x800000UL, 2, 0, 0));
	chain_success(chain_call(c, GPU_PRIVATE_CONTEXT_DESTROY, task_contexts[c], 0, 0, 0, 0, 0));
	chain_success(chain_call(c, GPU_PRIVATE_BO_DESTROY, task_bos[c], 0, 0, 0, 0, 0));
}

static void task_finish_fault(void)
{
	unsigned int flushes = chain_flushes;
	memset(chain_device[0][1], 0x40, 4096);
	memset(chain_device[0][2], 0x50, 4096);
	task_fault_countdown = 1U;
	struct gpu_private_result r = chain_call(0, GPU_PRIVATE_TASK_FINISH,
		task_tokens[0], chain_channels[0], 0, 0, 0, 0);
	chain_expect(task_fault_countdown == 0U && task_fault_word != NULL,
		"post-snapshot device corruption actually injected");
	chain_expect(r.status == GPU_PRIVATE_STATE && !r.value[0], "post-read fault cannot complete task");
	chain_expect(!task_cpu_returns[0] && chain_cpu[0][1][0] == 0x70 && chain_cpu[0][2][0] == 0x78,
		"failed task does not return device output");
	unsigned int written = writes, cleaned = chain_cleans, invalidated = chain_invalidates;
	chain_denied(chain_call(0, GPU_PRIVATE_TASK_FINISH, task_tokens[0], chain_channels[0], 0, 0, 0, 0));
	chain_denied(chain_call(0, GPU_PRIVATE_TASK_RETURN, task_tokens[0], chain_channels[0], 0, 0, 0, 0));
	chain_denied(chain_call(0, GPU_PRIVATE_TASK_RETIRE, task_tokens[0], chain_channels[0], 0, 0, 0, 0));
	chain_expect(writes == written && chain_cleans == cleaned && chain_invalidates == invalidated && chain_flushes == flushes,
		"quarantined task replay does not touch memory or device");
	chain_denied(chain_call(0, GPU_PRIVATE_GROUP_DESTROY, task_groups[0], 0, 0, 0, 0, 0));
	chain_denied(chain_call(0, GPU_PRIVATE_BO_DESTROY, task_bos[0], 0, 0, 0, 0, 0));
	chain_expect(gpu_private_range_busy(&chain_owners[0], DATA_IPA, 8192), "fault retains private backing references");
	chain_expect(chain_cpu[1][1][0] == 0x71 && chain_cpu[1][2][0] == 0x79,
		"other Client input unchanged by failing task");
	/* Remove only the injected device-double fault. Protected quarantine and
	 * references survive until the explicit trusted reset below. */
	*task_fault_word = task_fault_saved;
}

static struct smc_result task_pm(unsigned long operation, unsigned long argument, unsigned long error)
{
	struct smc_result result;

	/* Production RMI dispatch owns this gate, not the PM adapter itself. */
	xshm_policy_lock();
	smc_opencca_gpu_pm(operation, argument, error, &result);
	xshm_policy_unlock();
	task_rmi_requests++;
	chain_balanced();
	chain_expect(result.x[1] == (unsigned long)opencca_gpu_state(), "RMI returns actual device state");
	for (unsigned int i = 2; i < 8; i++)
		chain_expect(!result.x[i], "reset/release unused return registers zero");
	return result;
}

static void task_destroy_arena(void)
{
	struct gpu_private_result r;
	unsigned int attempts = 0;

	do {
		r = chain_call(2, GPU_PRIVATE_CONTROL_DESTROY, task_arena, 0, 0, 0, 0, 0);
		chain_expect(++attempts <= 3U, "bounded revoked arena scrub and restoration");
	} while (r.status == GPU_PRIVATE_INCOMPLETE);
	chain_success(r);
	for (unsigned int p = 9; p < CHAIN_PAGES; p++)
		chain_expect((*chain_entry(2, p) & 4095UL) == 0x3fUL,
			"revoked arena CPU mapping restored only after scrub");
}

static struct smc_result task_reclaim(unsigned long address, unsigned long error)
{
	struct smc_result result;

	xshm_policy_lock();
	smc_opencca_gpu_pm(OPENCCA_GPU_PRIVATE_RECLAIM, address, error, &result);
	xshm_policy_unlock();
	task_rmi_requests++; task_reclaim_requests++;
	chain_balanced();
	if (error == 0UL)
		chain_expect(result.x[1] == (unsigned long)opencca_gpu_state(), "reclaim returns actual device state");
	for (unsigned int i = error ? 1U : 4U; i < 8U; i++)
		chain_expect(result.x[i] == 0UL, "reclaim unused return registers zero");
	return result;
}

static void task_reclaim_denied(unsigned long address, unsigned long error, unsigned long status)
{
	unsigned long entries[OWNERS][3][512];
	unsigned int written = writes, cleaned = chain_cleans, invalidated = chain_invalidates;
	unsigned int flushed = chain_flushes, tlbis = chain_tlbis;

	memcpy(entries, chain_entries, sizeof(entries));
	struct smc_result r = task_reclaim(address, error);
	chain_expect(r.x[0] == RMI_ERROR_INPUT && (error || status == TASK_RECLAIM_ANY_ERROR || r.x[2] == status),
		"Host reclaim must prove dead REC-free non-NEW owner and trusted revocation");
	chain_expect(writes == written && chain_cleans == cleaned && chain_invalidates == invalidated &&
		chain_flushes == flushed && chain_tlbis == tlbis && !memcmp(entries, chain_entries, sizeof(entries)),
		"denied reclaim has no MMIO cache or RTT side effects");
	chain_expect(gpu_private_owner_busy(&chain_owners[0]) && gpu_private_owner_busy(&chain_owners[1]) &&
		gpu_private_owner_busy(&chain_owners[2]), "denied reclaim retains all owners");
}

static void task_dead_owner(void)
{
	unsigned int c = task_fault_case == 5U ? 0U : 2U;
	unsigned long address = CHAIN_RD_PA + c * 4096UL;

	task_reclaim_denied(address + 1UL, 0, GPU_PRIVATE_INPUT);
	task_reclaim_denied(chain_data[c][1].pa, 0, GPU_PRIVATE_INPUT);
	task_reclaim_denied(address, 1, 0);
	/* Before revocation, assert denial and no effects without requiring a
	 * particular rejection precedence. Missing liveness checks must reach
	 * the independent post-revocation oracle below, not fail on errno alone. */
	task_reclaim_denied(address, 0, TASK_RECLAIM_ANY_ERROR); /* Existing stopped REC. */
	chain_owners[c].refs = 0U;
	chain_realm_state[c] = REALM_NEW;
	task_reclaim_denied(address, 0, TASK_RECLAIM_ANY_ERROR);
	chain_realm_state[c] = REALM_ACTIVE;
	task_reclaim_denied(address, 0, GPU_PRIVATE_STATE); /* No DMA-stop proof. */
	soft_succeeds = hard_succeeds = false;
	chain_expect(task_pm(OPENCCA_GPU_RELEASE, 0, 0).x[0] == RMI_ERROR_INPUT &&
		opencca_gpu_state() == OPENCCA_GPU_QUARANTINED, "failed release cannot prove DMA stopped");
	task_reclaim_denied(address, 0, GPU_PRIVATE_STATE);
	for (unsigned int owner = 0; owner < 2; owner++)
		for (unsigned int p = 0; p < 2; p++)
			chain_expect(chain_leaf(task_roots[owner], 0x800000UL + p * 4096UL) == chain_data[owner][p+1U].pa,
				"failed release/reclaim keeps actual Client PTEs");
	soft_succeeds = hard_succeeds = true;
	chain_expect(task_pm(OPENCCA_GPU_RELEASE, 0, 0).x[0] == RMI_SUCCESS &&
		opencca_gpu_state() == OPENCCA_GPU_REVOKED, "successful release supplies trusted revocation");
	/* Test liveness/state independently AFTER revocation so a device-state
	 * rejection cannot hide a missing REC-count or NEW-state check. */
	chain_owners[c].refs = 1U;
	task_reclaim_denied(address, 0, GPU_PRIVATE_INPUT);
	chain_owners[c].refs = 0U; chain_realm_state[c] = REALM_NEW;
	task_reclaim_denied(address, 0, GPU_PRIVATE_INPUT);
	chain_realm_state[c] = task_fault_case == 5U ? REALM_ACTIVE : REALM_SYSTEM_OFF;
	struct smc_result r = task_reclaim(address, 0);
	if (c == 0U) {
		chain_expect(r.x[0] == RMI_SUCCESS && r.x[2] == GPU_PRIVATE_SUCCESS &&
			!gpu_private_owner_busy(&chain_owners[0]), "dead Client actual context and BO reclaimed");
		chain_expect(gpu_private_range_busy(&chain_owners[1], DATA_IPA, 8192) &&
			chain_data[1][1].state == GRANULE_STATE_DATA && chain_data[1][2].state == GRANULE_STATE_DATA,
			"dead Client reclaim retains living Client registrations");
		chain_denied(chain_call(0, GPU_PRIVATE_TASK_FINISH, task_tokens[0], chain_channels[0], 0, 0, 0, 0));
		chain_success(chain_call(1, GPU_PRIVATE_CONTEXT_DESTROY, task_contexts[1], 0, 0, 0, 0, 0));
		chain_success(chain_call(1, GPU_PRIVATE_BO_DESTROY, task_bos[1], 0, 0, 0, 0, 0));
		task_destroy_arena();
	} else {
		chain_expect(r.x[0] == RMI_SUCCESS && r.x[2] == GPU_PRIVATE_INCOMPLETE && r.x[3] == 1UL,
			"dead service reclaim has bounded 512-page continuation");
		chain_expect((*chain_entry(2,9) & 4095UL) == 16UL &&
			(*chain_entry(2,10) & 4095UL) == 0x3fUL, "dead service restores only scrubbed suffix");
		/* Check detachment before terminal cleanup status: an orphaned
		 * service pointer itself keeps owner_busy true. A later SUCCESS
		 * assertion would otherwise mask these independent identity oracles.
		 * Direct core probes bypass the outer device-state gate; this is
		 * not a complete RD destroy/recreate sequence. */
		for (unsigned int owner = 0; owner < 2; owner++) {
			struct gpu_private_result inspect;
			xshm_policy_lock();
			gpu_private_bo_inspect(&chain_owners[2], &chain_owners[owner], task_bos[owner], &inspect);
			xshm_policy_unlock();
			chain_expect(inspect.status != GPU_PRIVATE_SUCCESS, "recycled service RD cannot inspect living Client BO");
			xshm_policy_lock();
			gpu_private_context_inspect(&chain_owners[2], &chain_owners[owner], task_contexts[owner], &inspect);
			xshm_policy_unlock();
			chain_expect(inspect.status != GPU_PRIVATE_SUCCESS, "recycled service RD cannot inspect living Client context");
		}
		r = task_reclaim(address, 0);
		chain_expect(r.x[0] == RMI_SUCCESS && r.x[2] == GPU_PRIVATE_SUCCESS &&
			!gpu_private_owner_busy(&chain_owners[2]), "dead service cleanup completes after final page");
		for (unsigned int p = 9; p < CHAIN_PAGES; p++) {
			chain_expect((*chain_entry(2,p) & 4095UL) == 0x3fUL,
				"dead service donated page CPU mapping restored");
			for (unsigned int i = 0; i < 4096; i++)
				chain_expect(chain_device[2][p][i] == 0, "dead service actual device backing scrubbed");
		}
		for (unsigned int owner = 0; owner < 2; owner++) {
			chain_expect(gpu_private_range_busy(&chain_owners[owner], DATA_IPA, 8192) &&
				chain_data[owner][1].state == GRANULE_STATE_DATA && chain_data[owner][2].state == GRANULE_STATE_DATA,
				"dead service retains living Client registrations");
			chain_success(chain_call(owner, GPU_PRIVATE_CONTEXT_DESTROY, task_contexts[owner], 0, 0, 0, 0, 0));
			chain_success(chain_call(owner, GPU_PRIVATE_BO_DESTROY, task_bos[owner], 0, 0, 0, 0, 0));
		}
	}
	chain_expect(!task_cpu_returns[0] && !task_cpu_returns[1], "dead-owner cleanup never forges successful CPU completion");
	for (unsigned int owner = 0; owner < 2; owner++)
		for (unsigned int p = 1; p <= 2; p++)
			chain_expect(chain_data[owner][p].refs == 0U &&
				chain_cpu[owner][p][0] == (p == 1U ? 0x70 + owner : 0x78 + owner),
				"ordinary data released without returning uncompleted device output");
	chain_expect(!opencca_gpu_mmio_allowed(&chain_owners[2]), "dead-owner cleanup grants no raw MMIO");
}

static void task_revocation(const char *firmware)
{
	unsigned long old_contexts[2], old_groups[2], old_tokens[2];
	memcpy(old_contexts, task_contexts, sizeof(old_contexts));
	memcpy(old_groups, task_groups, sizeof(old_groups));
	memcpy(old_tokens, task_tokens, sizeof(old_tokens));
	unsigned int written = writes, cleaned = chain_cleans, invalidated = chain_invalidates;
	/* A mediated Proxy must not recover raw-control authority through the
	 * older GPU_CONTROL RSI, nor reset another Client's running queues. */
	for (unsigned int c = 0; c < 3; c++) {
		struct rec rec = {.realm_info = {&chain_owners[c], chain_rd[c].s2_ctx}, .regs = {0, 1}};
		struct rsi_result result = {0};
		xshm_policy_lock();
		handle_rsi_opencca_gpu_control(&rec, &result);
		xshm_policy_unlock();
		task_reset_rsi_requests++;
		chain_balanced();
		chain_expect(result.action == UPDATE_REC_RETURN_TO_REALM &&
			result.smc_res.x[0] == RSI_ERROR_INPUT && writes == written,
			"Realm reset cannot bypass trusted mediated control");
	}
	for (unsigned int i = 0; i < 2; i++) {
		struct smc_result result = task_pm(OPENCCA_GPU_RESET, i == 0U ? 1UL : 0UL, i == 1U ? 1UL : 0UL);
		chain_expect(result.x[0] == RMI_ERROR_INPUT && writes == written &&
			opencca_gpu_service_isolated(&chain_owners[2]) &&
			chain_cleans == cleaned && chain_invalidates == invalidated,
			"malformed Host reset rejected without side effects");
	}
	if (task_fault_case == 3U) {
		/* Neither a Host request nor a failed physical reset constitutes a
		 * DMA-stop proof. Keep all task/backing leases and hidden controls. */
		soft_succeeds = hard_succeeds = false;
		struct smc_result result = task_pm(OPENCCA_GPU_RESET, 0, 0);
		chain_expect(result.x[0] == RMI_ERROR_INPUT && opencca_gpu_state() == OPENCCA_GPU_QUARANTINED,
			"failed reset quarantines device");
		for (unsigned int c = 0; c < 2; c++) {
			struct gpu_private_result held = chain_call(c, GPU_PRIVATE_CONTEXT_DESTROY,
				task_contexts[c], 0, 0, 0, 0, 0);
			chain_expect(held.status != GPU_PRIVATE_SUCCESS, "failed reset retains task references");
			chain_denied(chain_call(c, GPU_PRIVATE_BO_DESTROY, task_bos[c], 0, 0, 0, 0, 0));
			for (unsigned int p = 0; p < 2; p++)
				chain_expect(chain_leaf(task_roots[c], 0x800000UL + p * 4096UL) == chain_data[c][p + 1U].pa,
					"failed reset retains actual trusted PTEs");
		}
		chain_denied(chain_call(2, GPU_PRIVATE_CONTROL_DESTROY, task_arena, 0, 0, 0, 0, 0));
		chain_expect(!opencca_gpu_mmio_allowed(&chain_owners[2]) &&
			!task_cpu_returns[0] && !task_cpu_returns[1], "failed reset never returns data or raw MMIO");
		soft_succeeds = hard_succeeds = true;
		/* RESET in quarantine remains fail-closed even if hardware now stops;
		 * RELEASE is the existing recovery operation which retires references. */
		result = task_pm(OPENCCA_GPU_RESET, 0, 0);
		chain_expect(result.x[0] == RMI_SUCCESS && opencca_gpu_state() == OPENCCA_GPU_QUARANTINED,
			"successful quarantine RESET does not reopen service");
		chain_denied(chain_call(0, GPU_PRIVATE_CONTEXT_DESTROY, task_contexts[0], 0, 0, 0, 0, 0));
		result = task_pm(OPENCCA_GPU_RELEASE, 0, 0);
		chain_expect(result.x[0] == RMI_SUCCESS && opencca_gpu_state() == OPENCCA_GPU_REVOKED,
			"trusted RELEASE completes quarantine recovery");
	} else {
		struct smc_result result = task_pm(OPENCCA_GPU_RESET, 0, 0);
		chain_expect(result.x[0] == RMI_SUCCESS && opencca_gpu_service_isolated(&chain_owners[2]),
			"trusted mediated reset preserves only isolated service authority");
	}
	for (unsigned int c = 0; c < 2; c++) {
		/* Unlike TASK_VALIDATE, metadata inspection does not consult a
		 * revoked private context. Detect stale firmware state independently. */
		struct gpu_private_result r = chain_call(2, GPU_PRIVATE_GROUP_INSPECT,
			old_groups[c], chain_channels[c], 0, 0, 0, 0);
		chain_expect(r.status != GPU_PRIVATE_SUCCESS, "revoked firmware group handle is stale");
		r = chain_call(2, GPU_PRIVATE_TASK_VALIDATE, old_tokens[c],
			chain_channels[c], old_contexts[c], old_groups[c], 0, 0);
		chain_expect(r.status != GPU_PRIVATE_SUCCESS, "revoked firmware task handle is stale");
		r = chain_call(c, GPU_PRIVATE_CONTEXT_DESTROY, old_contexts[c], 0, 0, 0, 0, 0);
		chain_expect(r.status == GPU_PRIVATE_SUCCESS, "revoked contexts release after trusted reset");
		chain_success(chain_call(c, GPU_PRIVATE_BO_DESTROY, task_bos[c], 0, 0, 0, 0, 0));
		chain_expect(!gpu_private_range_busy(&chain_owners[c], DATA_IPA, 8192), "revoked old data registration released");
	}
	task_destroy_arena();
	if (task_fault_case == 4U) {
		/* Reuse the very same physical pages after trusted teardown. Old
		 * tokens/contexts must remain invalid despite table-slot reuse. */
		task_upload(firmware);
		for (unsigned int c = 0; c < 2; c++) {
			task_create(c);
			chain_expect(task_contexts[c] != old_contexts[c] && task_groups[c] != old_groups[c] &&
				task_tokens[c] != old_tokens[c], "reused storage has fresh opaque generations");
		}
		written = writes; cleaned = chain_cleans; invalidated = chain_invalidates;
		for (unsigned int c = 0; c < 2; c++) {
			chain_denied(chain_call(2, GPU_PRIVATE_TASK_DISPATCH, old_tokens[c], chain_channels[c],
				task_contexts[c], task_groups[c], 0, 0));
			chain_denied(chain_call(2, GPU_PRIVATE_TASK_DISPATCH, task_tokens[c], chain_channels[c],
				old_contexts[c], old_groups[c], 0, 0));
			chain_denied(chain_call(c, GPU_PRIVATE_TASK_FINISH, old_tokens[c], chain_channels[c], 0, 0, 0, 0));
			chain_denied(chain_call(2, GPU_PRIVATE_SERVICE_MAP, old_contexts[c], chain_channels[c], 1,
				0, 0x800000UL, (2UL << 8U) | GPU_PRIVATE_READ));
		}
		chain_expect(writes == written && chain_cleans == cleaned && chain_invalidates == invalidated,
			"old generation replay cannot touch new device or backing");
		for (unsigned int c = 0; c < 2; c++) task_launch(c);
		for (unsigned int c = 0; c < 2; c++) task_finish_one(c);
		chain_expect(task_pm(OPENCCA_GPU_RESET, 0, 0).x[0] == RMI_SUCCESS, "final trusted reset after reuse");
		task_destroy_arena();
	}
}

int main(int argc, char **argv)
{
	chain_expect(argc == 2 || argc == 3, "pinned firmware path and optional fault case required");
	if (argc == 3) task_fault_case = (unsigned int)strtoul(argv[2], NULL, 10);
#ifdef GPU_RSI_REALM_LIFECYCLE_TEST
	chain_expect(task_fault_case == 7U || task_fault_case == 8U, "known actual Realm-destroy lifecycle case");
#else
	chain_expect(task_fault_case <= 6U, "known post-read/revocation/dead-owner case");
#endif
	chain_setup(); chain_registration(); chain_busy_and_channels(); chain_handoff(); chain_control();
	task_upload(argv[1]);
	for (unsigned int c = 0; c < 2; c++) task_create(c);
	for (unsigned int c = 0; c < 2; c++) { task_launch(c); task_bad_requests(c); }
#ifdef GPU_RSI_REALM_LIFECYCLE_TEST
	task_realm_lifecycle();
	goto done;
#endif
	if (task_fault_case >= 5U) {
		task_dead_owner();
		goto done;
	}
	if (task_fault_case >= 3U) {
		task_revocation(argv[1]);
		goto done;
	}
	if (task_fault_case) task_finish_fault(); else task_finish_one(0);
	task_finish_one(1);
	chain_expect(task_pm(OPENCCA_GPU_RESET, 0, 0).x[0] == RMI_SUCCESS, "trusted RMI reset model");
	if (task_fault_case) {
		chain_success(chain_call(0, GPU_PRIVATE_CONTEXT_DESTROY, task_contexts[0], 0, 0, 0, 0, 0));
		chain_success(chain_call(0, GPU_PRIVATE_BO_DESTROY, task_bos[0], 0, 0, 0, 0, 0));
	}
	task_destroy_arena();
done:
	chain_balanced();
	chain_expect(!gpu_private_owner_busy(&chain_owners[0]) && !gpu_private_owner_busy(&chain_owners[1]) &&
		!gpu_private_owner_busy(&chain_owners[2]), "all actual private owner refs retired");
	printf("GPU_RSI_TASK_CHAIN=PASS case=%u rsi_requests=%u rmi_requests=%u reset_rsi_requests=%u reclaim_requests=%u clients=2 actual_memory_callbacks firmware/PT/dispatch/finish/return/retire/revoke/dead-owner MODEL_ONLY no shader/GPC/concurrency\n",
		task_fault_case, chain_checks, task_rmi_requests, task_reset_rsi_requests, task_reclaim_requests);
	return 0;
}
