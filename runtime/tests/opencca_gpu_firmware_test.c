/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <limits.h>
#include <mbedtls/sha256.h>
#include <opencca_gpu_firmware.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char service, attacker;
static unsigned char client_a, client_b;
static unsigned char quota_clients[3];
static unsigned char original[GPU_FIRMWARE_IMAGE_SIZE];
static unsigned char supplied[GPU_FIRMWARE_IMAGE_SIZE];
static unsigned int digest_calls;
static bool digest_succeeds = true;
static bool install_succeeds = true, boot_succeeds = true, bad_shared;
static unsigned int installs, boots, cleans, invalidations;
static unsigned long installed_root;
static unsigned char *runtime_memory;
static size_t runtime_bytes;
static uint64_t *runtime_root;
static unsigned int malformed, notifications, clean_inputs;
static bool notify_succeeds = true, acknowledge = true, config_succeeds = true;
static bool fault_after_ack;
static unsigned long clock_ticks;
static uint32_t *global_input, *global_output;
static uint32_t previous_ack;
static unsigned char arena[GPU_PRIVATE_CONTROL_PAGES][4096]
	__attribute__((aligned(4096)));
static bool arena_cpu[GPU_PRIVATE_CONTROL_PAGES];
static unsigned int fail_clear_index = UINT_MAX;
static uint32_t test_suspend_size = 0x40000U;
static unsigned long stale_group;
static unsigned long latest_private_table;
static unsigned int fault_after_leaf_writes;
static bool fail_table_lookup;
static unsigned char client_commands[2][4096] __attribute__((aligned(4096)));
static unsigned long stale_task;
static unsigned long retained_task_bo;

#define ADDRESS_MASK UINT64_C(0x000000fffffff000)

static uint64_t pte_at(unsigned long root, unsigned long va)
{
	uint64_t *table = (void *)root;

	for (unsigned int level = 0U; level < 3U; level++) {
		uint64_t pte = table[(va >> (39U - level * 9U)) & 511UL];

		if (pte == 0UL)
			return 0UL;
		assert((pte & 3UL) == 3UL);
		table = (void *)(uintptr_t)(pte & ADDRESS_MASK);
	}
	return table[(va >> 12U) & 511UL];
}

static unsigned long address(const void *memory)
{
	return (uintptr_t)memory;
}

static void clean(const void *memory, size_t size)
{
	if (size == 0x88U) {
		assert(memory == global_input);
		clean_inputs++;
		return;
	}
	cleans++;
	if (size == GPU_FIRMWARE_RUNTIME_PAGES * 4096UL) {
		runtime_memory = (void *)memory;
		runtime_bytes = size;
		assert(size == GPU_FIRMWARE_RUNTIME_PAGES * 4096UL);
	} else {
		assert(size == GPU_FIRMWARE_TABLES * 4096UL);
		runtime_root = (void *)memory;
		assert(size == GPU_FIRMWARE_TABLES * 4096UL);
	}
}

static void invalidate(const void *memory, size_t size)
{
	assert((const unsigned char *)memory >= runtime_memory);
	assert((const unsigned char *)memory + size <= runtime_memory + runtime_bytes);
	assert(size == 0xc000UL || (memory == global_output && size == 0x1cU));
	invalidations++;
}

static bool install(unsigned long root)
{
	assert(root == (uintptr_t)runtime_root && cleans >= 2U);
	installed_root = root;
	installs++;
	return install_succeeds;
}

static bool boot(unsigned long root)
{
	uint32_t *shared;

	assert(root == installed_root);
	boots++;
	if (!boot_succeeds)
		return false;
	shared = (void *)(uintptr_t)(pte_at(root, 0x04000000UL) & ADDRESS_MASK);
	assert(shared != NULL && shared[0] == 0U); /* Firmware initial state. */
	shared[0] = 0x01010000U;
	for (unsigned int g = 0U; g < shared[4]; g++) {
		uint32_t *group = (void *)((unsigned char *)shared + 4096U + g * shared[5]);

		/* Synthetic MCU results: only geometry/addresses come from the pinned
		 * image. These are not asserted to be real hardware capabilities.
		 */
		group[3] = test_suspend_size;
		group[4] = 0x20000U;
		for (unsigned int s = 0U; s < group[5]; s++) {
			uint32_t *stream = (void *)((unsigned char *)group + 64U + s * group[6]);

			stream[0] = 0x7015fU;
		}
	}
	global_input = (void *)((unsigned char *)shared + shared[2] - 0x04000000U);
	global_output = (void *)((unsigned char *)shared + shared[3] - 0x04000000U);
	global_output[0] = previous_ack;
	/* Corrupt the MCU-produced metadata after successful boot indication. */
	uint32_t *group = (void *)((unsigned char *)shared + 4096U);
	uint32_t *stream = (void *)((unsigned char *)group + 64U);

	switch (malformed) {
	case 1U: group[1] = shared[2]; break; /* Group input aliases global input. */
	case 2U: group[6] = UINT32_MAX - 3U; break; /* Overflow-sized stream stride. */
	case 3U: group[5] = 33U; break;
	case 4U: stream[2] = 0x0400bff8U; break; /* Complete stream output crosses end. */
	case 5U: stream[1] = 0x04001000U; break; /* Input aliases descriptors. */
	case 6U: ((uint32_t *)((unsigned char *)stream + group[6]))[2] = stream[2]; break;
	case 7U: ((uint32_t *)((unsigned char *)group + shared[5]))[3]++; break;
	case 8U: ((uint32_t *)((unsigned char *)stream + group[6]))[0]++; break;
	case 9U: shared[5] = UINT32_MAX - 3U; break;
	case 10U: group[3] = 0U; break;
	case 11U: shared[3] = shared[2] + 8U; break;
	case 12U: stream[2] += 8U; break; /* Byte bounds fit, cache line ownership does not. */
	case 13U: shared[2]++; break;
	case 14U: shared[3]++; break;
	case 15U: group[1]++; break;
	case 16U: group[2]++; break;
	case 17U: stream[1]++; break;
	case 18U: stream[2]++; break;
	default: break;
	}
	if (bad_shared)
		shared[2] = 0x0400bff8U; /* Starting pointer fits, complete input does not. */
	return true;
}

static bool configuration(unsigned long root, struct gpu_firmware_config *config)
{
	assert(root == installed_root);
	if (!config_succeeds || (fault_after_ack && notifications != 0U))
		return false;
	*config = (struct gpu_firmware_config) {
		.shader_mask = UINT64_C(0x100000005), .poweroff_timer = 10U,
		.idle_timer = 1U, .ack_timeout_ticks = 10UL
	};
	return true;
}

static bool notify(unsigned long root)
{
	assert(root == installed_root && clean_inputs > notifications);
	assert(global_input[0] == ((~previous_ack) & 14U));
	assert(global_input[4] == 2560000U && global_input[5] == 10U);
	assert(global_input[6] == 5U && global_input[7] == 1U && global_input[33] == 1U);
	for (unsigned int i = 1U; i < 33U; i++)
		if (i < 4U || i > 7U)
			assert(global_input[i] == 0U); /* No counters, raw pointers, IRQs. */
	notifications++;
	if (acknowledge)
		global_output[0] = global_input[0];
	return notify_succeeds;
}

static unsigned long ticks(void)
{
	return clock_ticks++;
}

static bool digest(const void *image, size_t size, unsigned char output[32])
{
	digest_calls++;
	assert(size == sizeof(original) && image != supplied && image != original);
	return digest_succeeds && mbedtls_sha256(image, size, output, 0) == 0;
}

static const struct gpu_firmware_ops ops = {
	.digest = digest, .address = address, .clean = clean,
	.invalidate = invalidate, .install = install, .boot = boot,
	.configuration = configuration, .notify = notify, .clock = ticks
};

static void begin(void)
{
	struct gpu_private_result result;

	gpu_firmware_begin(&service, sizeof(original), &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	assert(result.value[0] == sizeof(original));
}

static void upload(void)
{
	struct gpu_private_result result;

	for (unsigned long offset = 0UL; offset < sizeof(supplied); offset += 4096UL) {
		gpu_firmware_write(&service, offset, supplied + offset, 4096U, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		assert(result.value[0] == offset + 4096UL);
	}
}

static void rejected_image(unsigned long offset)
{
	struct gpu_private_result result;
	struct gpu_firmware_section section;
	const void *data;

	begin();
	memcpy(supplied, original, sizeof(supplied));
	supplied[offset] ^= 1U;
	upload();
	gpu_firmware_seal(&ops, &service, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_inspect(&service, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_EMPTY);
	assert(result.value[1] == 0UL && result.value[2] == 0UL && result.value[3] == 0UL);
	assert(!gpu_firmware_section(&service, 0U, &section, &data));
}

static void prepared(void)
{
	struct gpu_private_result result;
	struct gpu_firmware_section sections[GPU_FIRMWARE_SECTIONS];
	const void *data;

	begin();
	memcpy(supplied, original, sizeof(supplied));
	upload();
	gpu_firmware_seal(&ops, &service, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	for (unsigned int i = 0U; i < 7U; i++)
		assert(gpu_firmware_section(&service, i, &sections[i], &data));
	gpu_firmware_prepare(&ops, &attacker, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_boot(&ops, &service, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_firmware_prepare(&ops, &service, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_PREPARED);
	assert(installed_root == 0UL); /* Preparation does not touch hardware. */
	for (unsigned int i = 0U; i < 7U; i++) {
		const struct gpu_firmware_section *section = &sections[i];

		for (unsigned long j = 0UL; j < section->size; j += 4096UL) {
			uint64_t pte = pte_at((uintptr_t)runtime_root, section->va + j);
			const unsigned char *page = (void *)(uintptr_t)(pte & ADDRESS_MASK);
			unsigned long bytes = 0UL;

			assert(page >= runtime_memory && page + 4096UL <= runtime_memory + runtime_bytes);
			assert(((pte & (1UL << 7U)) != 0UL) == ((section->flags & 2U) == 0U));
			assert(((pte & (3UL << 53U)) == 0UL) == ((section->flags & 4U) != 0U));
			if (j < section->data_size) {
				bytes = section->data_size - j;
				if (bytes > 4096UL)
					bytes = 4096UL;
				assert(memcmp(page, original + section->data_offset + j, bytes) == 0);
			}
			for (unsigned long k = bytes; k < 4096UL; k++)
				assert(page[k] == 0U);
		}
	}
	assert(pte_at((uintptr_t)runtime_root, 0x03000000UL) == 0UL); /* Protected section. */
	assert(pte_at((uintptr_t)runtime_root, 0x08000000UL) == 0UL);
	gpu_firmware_begin(&service, sizeof(original), &result);
	assert(result.status == GPU_PRIVATE_STATE);
	unsigned int old_cleans = cleans;

	gpu_firmware_prepare(&ops, &service, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && cleans == old_cleans);
}

static bool arena_source(const void *owner, unsigned long ipa, unsigned long *pa)
{
	if (owner != &service || ipa < 0x20000000UL || (ipa & 4095UL) != 0UL ||
	    (ipa - 0x20000000UL) / 4096UL >= GPU_PRIVATE_CONTROL_PAGES ||
	    gpu_private_range_busy(owner, ipa, 4096UL))
		return false;
	unsigned int index = (unsigned int)((ipa - 0x20000000UL) / 4096UL);

	if (!arena_cpu[index])
		return false;
	*pa = (uintptr_t)arena[index];
	return true;
}

static unsigned int arena_index(unsigned long pa)
{
	assert(pa >= (uintptr_t)arena && pa < (uintptr_t)arena + sizeof(arena));
	assert((pa & 4095UL) == 0UL);
	return (unsigned int)((pa - (uintptr_t)arena) / 4096UL);
}

static bool arena_hide(const void *owner, unsigned long ipa, unsigned long pa)
{
	unsigned int index = arena_index(pa);

	assert(owner == &service && ipa == 0x20000000UL + index * 4096UL);
	assert(arena_cpu[index]);
	arena_cpu[index] = false;
	return true;
}

static bool arena_clear(unsigned long pa)
{
	unsigned int index = arena_index(pa);

	assert(!arena_cpu[index]);
	if (index == fail_clear_index)
		return false;
	memset(arena[index], 0, 4096U);
	return true;
}

static bool arena_restore(const void *owner, unsigned long ipa, unsigned long pa)
{
	unsigned int index = arena_index(pa);

	assert(owner == &service && ipa == 0x20000000UL + index * 4096UL);
	assert(!arena_cpu[index]);
	for (unsigned int i = 0U; i < 4096U; i++)
		assert(arena[index][i] == 0U);
	arena_cpu[index] = true;
	return true;
}

static void context_table_clean(const void *memory, size_t bytes)
{
	assert(memory != NULL && (bytes == 4096U || bytes == sizeof(uint64_t)));
	if (bytes == 4096U)
		latest_private_table = (uintptr_t)memory;
	if (bytes == sizeof(uint64_t) && (*(const uint64_t *)memory & (1UL << 10U)) != 0UL &&
	    fault_after_leaf_writes != 0U &&
	    --fault_after_leaf_writes == 0U)
		fail_table_lookup = true;
}

static unsigned long faulting_table_address(const void *memory)
{
	return fail_table_lookup ? (1UL << 48U) : address(memory);
}

static const struct gpu_private_ops arena_ops = {
	.source_page = arena_source, .hide_page = arena_hide,
	.restore_page = arena_restore, .clear_page = arena_clear,
	.table_pa = address, .clean = context_table_clean
};

static bool context_activate_model(unsigned long context, unsigned long root, unsigned int slot)
{
	assert(context != 0UL && root != 0UL && slot == 1U);
	return true; /* Software lifetime model only, no hardware installation. */
}

static bool context_sync_model(unsigned long context, unsigned long root)
{
	assert(context != 0UL && root != 0UL);
	return true;
}

static void destroy_group(const void *owner, unsigned long group, bool large)
{
	struct gpu_private_result result;
	bool batched = false;

	do {
		gpu_firmware_group_destroy(&arena_ops, owner, group, &result);
		batched |= result.status == GPU_PRIVATE_INCOMPLETE;
	} while (result.status == GPU_PRIVATE_INCOMPLETE);
	assert(result.status == GPU_PRIVATE_SUCCESS && (!large || batched));
}

static bool command_source(const void *owner, unsigned long ipa, unsigned long *pa)
{
	if (owner != &client_a || ipa < 0x40000000UL || ipa >= 0x40002000UL || (ipa & 4095UL) != 0UL)
		return false;
	*pa = (uintptr_t)client_commands[(ipa - 0x40000000UL) / 4096UL];
	return true;
}

static void staged_tasks(unsigned long context, unsigned long group, unsigned long other,
		const struct gpu_firmware_group_resources *group_resources, unsigned long root)
{
	struct gpu_private_result result;
	struct gpu_private_ops memory_ops = arena_ops;
	struct gpu_firmware_task_resources resources, saved;
	unsigned long object, token, grant, ipas[2] = { 0x40000000UL, 0x40001000UL };
	unsigned long tokens[GPU_FIRMWARE_CLIENT_TASKS];
	unsigned int old_notifications = notifications;

	memory_ops.source_page = command_source;
	gpu_firmware_task_cancel(&client_a, stale_task, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_bo_create(&client_a, &service, sizeof(client_commands), GPU_PRIVATE_READ, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	object = result.value[0];
	gpu_private_bo_append(&memory_ops, &client_a, object, 0UL, ipas, 2U, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	gpu_private_map(&memory_ops, &client_a, context, object, 0UL, 0x100000UL, 1U, GPU_PRIVATE_READ, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	/* A missing second page fails before taking a hold: mapping it still works. */
	gpu_firmware_task_stage(&memory_ops, &service, &client_a, group, 0UL, 0x100ff8UL, 16UL, 7UL, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_private_map(&memory_ops, &client_a, context, object, 4096UL, 0x101000UL, 1U, GPU_PRIVATE_READ, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	/* Batch admission is atomic: a bad later member must not leak a hold. */
	struct gpu_firmware_task_command commands[GPU_PRIVATE_TASK_BATCH] = {
		{ .start = 0x100000UL, .bytes = 8U, .queue = 1U },
		{ .start = 0x101000UL, .bytes = 8U, .queue = 0U },
		{ .queue = 1U }, { .queue = 0U }, { .queue = 1U }, { .queue = 0U }
	};
	gpu_firmware_task_stage_batch(&memory_ops, &service, &client_a,
		group, commands, GPU_PRIVATE_TASK_BATCH, 2UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT && result.value[0] == 0UL);
	for (unsigned int bad = 0U; bad < 10U; bad++) {
		struct gpu_firmware_task_command invalid[GPU_PRIVATE_TASK_BATCH];

		memcpy(invalid, commands, sizeof(invalid));
		if (bad == 0U) invalid[5].queue = 2U;
		if (bad == 1U) invalid[5].pad = 1U;
		if (bad == 2U) invalid[5].start = 0x100008UL, invalid[5].bytes = 8U;
		if (bad == 3U) invalid[5].start = 0x100000UL;
		if (bad == 4U) invalid[5].bytes = 8U;
		if (bad == 5U) invalid[5].start = 0x300000UL, invalid[5].bytes = 8U;
		if (bad == 6U) invalid[5].start = group_resources->ring_va[0], invalid[5].bytes = 8U;
		gpu_firmware_task_stage_batch(&memory_ops, &service, bad == 7U ? &client_b : &client_a,
			group, invalid, bad == 8U ? 0U : bad == 9U ? GPU_PRIVATE_TASK_BATCH + 1U : GPU_PRIVATE_TASK_BATCH, 0UL, &result);
		assert(result.status != GPU_PRIVATE_SUCCESS && result.value[0] == 0UL);
	}
	struct gpu_private_command_range too_many[2] = {
		{ .start = 0x100000UL, .bytes = 8192UL },
		{ .start = 0x100000UL, .bytes = (GPU_PRIVATE_BATCH - 1UL) * 4096UL }
	};
	assert(!gpu_private_task_hold_batch(&memory_ops, &service, &client_a, context, too_many, 2U));
	/* No leaked hold from any rejected array: this mapping remains mutable. */
	gpu_private_unmap(&memory_ops, &client_a, context, 0x101000UL, 1U, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	gpu_private_map(&memory_ops, &client_a, context, object, 4096UL, 0x101000UL, 1U, GPU_PRIVATE_READ, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	gpu_firmware_task_stage_batch(&memory_ops, &service, &client_a, group, commands,
		GPU_PRIVATE_TASK_BATCH, 0UL, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[1] == 6U && result.value[2] == 3U);
	unsigned long batch = result.value[0];

	memset(commands, 0xff, sizeof(commands)); /* Admission owns its snapshot. */
	assert(gpu_firmware_task_resources(&service, &client_a, batch, &resources));
	assert(resources.queue == 1U && resources.bytes == 8U);
	gpu_private_unmap(&memory_ops, &client_a, context, 0x101000UL, 1U, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_firmware_task_cancel(&client_a, batch, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	gpu_private_unmap(&memory_ops, &client_a, context, 0x101000UL, 1U, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS); /* Exactly ONE reference released. */
	gpu_private_map(&memory_ops, &client_a, context, object, 4096UL, 0x101000UL, 1U, GPU_PRIVATE_READ, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	memset(commands, 0, sizeof(commands));
	gpu_firmware_task_stage_batch(&memory_ops, &service, &client_a, group, commands, 6U, 0UL, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[2] == 1U);
	batch = result.value[0];
	gpu_firmware_task_cancel(&client_a, batch, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	puts("GPU_TASK_BATCH_ADMISSION=PASS actual Client, array bounds, alignment, fence-only, private command backing, atomic rejection, aggregate walk bound, one mapping hold; MODEL_ONLY");
	for (unsigned int i = 0U; i < 9U; i++) {
		const void *owner = i == 0U ? &client_b : &client_a;
		const void *service_rd = i == 1U ? &attacker : &service;
		unsigned long queue = i == 2U ? 2UL : 0UL;
		unsigned long start = i == 3U ? group_resources->ring_va[0] :
			i == 4U ? 0x100001UL : i == 5U ? 0x300000UL : 0x100000UL;
		unsigned long bytes = i == 6U ? 0UL : i == 7U ? 7UL : 8UL;
		unsigned long flush = i == 8U ? 1UL << 32U : 0UL;

		gpu_firmware_task_stage(&memory_ops, service_rd, owner, group, queue, start, bytes, flush, &result);
		assert(result.status != GPU_PRIVATE_SUCCESS && result.value[0] == 0UL);
	}
	assert(!gpu_private_task_hold(&memory_ops, &service, &client_a, context,
		0x100000UL, (GPU_PRIVATE_BATCH + 1UL) * 4096UL));
	gpu_firmware_task_stage(&memory_ops, &service, &client_a, group, 1UL, 0x100ff8UL, 16UL, 7UL, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[1] == 1UL);
	token = result.value[0];
	assert(gpu_firmware_task_resources(&service, &client_a, token, &resources));
	assert(resources.group == group && resources.context == context && resources.queue == 1U &&
		resources.bytes == 16U && resources.latest_flush == 7U);
	saved = resources;
	/* Actual native command encoding, including correct per-queue sync offset. */
	uint64_t sync = group_resources->sync_va + 16U;
	const uint64_t expected[GPU_FIRMWARE_TASK_INSTRUCTIONS] = {
		(UINT64_C(2) << 56U) | (UINT64_C(94) << 48U) | 7U,
		(UINT64_C(36) << 56U) | (UINT64_C(94) << 40U) | 0x233U,
		(UINT64_C(1) << 56U) | (UINT64_C(92) << 48U) | 0x100ff8U,
		(UINT64_C(2) << 56U) | (UINT64_C(94) << 48U) | 16U,
		(UINT64_C(3) << 56U) | (UINT64_C(1) << 16U),
		(UINT64_C(32) << 56U) | (UINT64_C(92) << 40U) | (UINT64_C(94) << 32U),
		(UINT64_C(1) << 56U) | (UINT64_C(92) << 48U) | sync,
		(UINT64_C(1) << 56U) | (UINT64_C(94) << 48U) | 1U,
		(UINT64_C(3) << 56U) | (UINT64_C(1) << 16U),
		(UINT64_C(51) << 56U) | (UINT64_C(92) << 40U) | (UINT64_C(94) << 32U) | 1U,
		UINT64_C(47) << 56U
	};
	assert(memcmp(resources.instructions, expected, sizeof(expected)) == 0);
	memset(&resources, 0xff, sizeof(resources));
	assert(gpu_firmware_task_resources(&service, &client_a, token, &resources));
	assert(memcmp(&resources, &saved, sizeof(resources)) == 0);
	assert(!gpu_firmware_task_resources(&service, &client_b, token, &resources));
	for (unsigned int i = 0U; i < sizeof(resources); i++)
		assert(((unsigned char *)&resources)[i] == 0U);
	gpu_firmware_task_validate(&service, &client_a, context, group, token, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == 1UL &&
		result.value[1] == 16UL && result.value[2] == 7UL && result.value[3] == 0UL);
	gpu_firmware_task_validate(&attacker, &client_a, context, group, token, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_task_validate(&service, &client_a, context + 1UL, group, token, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_task_validate(&service, &client_a, context, other, token, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_task_cancel(&service, token, &result);
	assert(result.status == GPU_PRIVATE_INPUT); /* Service cannot cancel Client tasks. */
	gpu_firmware_task_cancel(&client_b, token, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	/* Both direct and exact-grant service mapping paths respect the freeze. */
	gpu_private_map_authorize(&client_a, context, object, 0UL, 0x200000UL, 1U, GPU_PRIVATE_READ, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	grant = result.value[0];
	gpu_private_service_map(&memory_ops, &service, &client_a, context, grant,
		0UL, 0x200000UL, 1U, GPU_PRIVATE_READ, &result);
	assert(result.status == GPU_PRIVATE_STATE && pte_at(root, 0x200000UL) == 0UL);
	gpu_private_service_unmap(&memory_ops, &service, &client_a, context, 0x100000UL, 1U, &result);
	assert(result.status == GPU_PRIVATE_STATE && pte_at(root, 0x100000UL) != 0UL);
	gpu_firmware_group_destroy(&memory_ops, &client_a, group, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_firmware_group_validate(&service, &client_a, context, group, 2UL, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS); /* Refused destroy did not close group. */
	tokens[0] = token;
	for (unsigned int i = 1U; i < GPU_FIRMWARE_CLIENT_TASKS; i++) {
		gpu_firmware_task_stage(&memory_ops, &service, &client_a, group, 0UL, 0x100000UL, 8UL, i, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		tokens[i] = result.value[0];
	}
	gpu_firmware_task_stage(&memory_ops, &service, &client_a, group, 0UL, 0x100000UL, 8UL, 0UL, &result);
	assert(result.status == GPU_PRIVATE_FULL);
	for (unsigned int i = 0U; i < GPU_FIRMWARE_CLIENT_TASKS; i++) {
		gpu_firmware_task_cancel(&client_a, tokens[i], &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
	}
	gpu_firmware_task_cancel(&client_a, token, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	stale_task = token;
	gpu_private_service_map(&memory_ops, &service, &client_a, context, grant,
		0UL, 0x200000UL, 1U, GPU_PRIVATE_READ, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS); /* Failed frozen use did not consume grant. */
	gpu_private_unmap(&memory_ops, &client_a, context, 0x200000UL, 1U, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	gpu_private_unmap(&memory_ops, &client_a, context, 0x100000UL, 2U, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	gpu_private_bo_destroy(&client_a, object, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	assert(notifications == old_notifications); /* No GPU publication or notification. */
	puts("GPU_TASK_STAGING=PASS authenticated immutable CALL wrapper, exact private mapped range, mapping freeze, Client-only prelaunch cancellation, quota, old token and group/context substitution rejection; MODEL_ONLY");
}

static void group_reservations(unsigned long contexts[2])
{
	struct gpu_private_result result;
	struct gpu_firmware_group_resources resources[2], reused;
	unsigned long group[2], quotas[GPU_FIRMWARE_CLIENT_GROUPS];
	unsigned int before = notifications;
	unsigned long roots[2];
	bool large = test_suspend_size > GPU_PRIVATE_BATCH * 4096UL;

	gpu_private_context_create(&arena_ops, &client_a, &service, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	contexts[0] = result.value[0];
	roots[0] = latest_private_table;
	gpu_private_context_create(&arena_ops, &client_b, &service, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	contexts[1] = result.value[0];
	roots[1] = latest_private_table;
	gpu_firmware_group_create(&ops, &arena_ops, &service, &client_a, contexts[0], 1UL, &result);
	assert(result.status == GPU_PRIVATE_STATE); /* Firmware must be configured. */
	gpu_firmware_configure(&ops, &service, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && notifications == before + 1U);
	gpu_firmware_group_inspect(&service, &client_a, stale_group, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_group_create(&ops, &arena_ops, &attacker, &client_a, contexts[0], 1UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_group_create(&ops, &arena_ops, &service, &service, contexts[0], 1UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_group_create(&ops, &arena_ops, &service, &client_b, contexts[0], 1UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT); /* Cannot borrow another context. */
	gpu_firmware_group_create(&ops, &arena_ops, &service, &client_a, contexts[0], 0UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_group_create(&ops, &arena_ops, &service, &client_a, contexts[0], 9UL, &result);
	assert(result.status == GPU_PRIVATE_STATE); /* Pinned model reports eight streams. */
	config_succeeds = false;
	gpu_firmware_group_create(&ops, &arena_ops, &service, &client_a, contexts[0], 1UL, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	config_succeeds = true;
	for (unsigned int i = 0U; i < 2U; i++) {
		const void *owner = i == 0U ? &client_a : &client_b;

		gpu_firmware_group_create(&ops, &arena_ops, &service, owner, contexts[i], 2UL - i, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[1] == 2UL - i);
		assert(result.value[2] == test_suspend_size);
		assert(result.value[3] == (test_suspend_size + 4095UL) / 4096UL + 2UL * (2UL - i));
		group[i] = result.value[0];
		struct gpu_firmware_queue_config queues[2] = {
			{ .ring_bytes = 4096U, .priority = 1U },
			{ .ring_bytes = 65536U, .priority = 15U }
		};

		gpu_firmware_group_configure(&arena_ops, &attacker, owner, group[i], queues, 2UL - i, &result);
		assert(result.status == GPU_PRIVATE_INPUT);
		gpu_firmware_group_configure(&arena_ops, &service, owner, group[i], queues, 0UL, &result);
		assert(result.status == GPU_PRIVATE_INPUT);
		queues[0].ring_bytes = 4097U;
		gpu_firmware_group_configure(&arena_ops, &service, owner, group[i], queues, 2UL - i, &result);
		assert(result.status == GPU_PRIVATE_INPUT);
		queues[0].ring_bytes = 4096U;
		queues[0].priority = 16U;
		gpu_firmware_group_configure(&arena_ops, &service, owner, group[i], queues, 2UL - i, &result);
		assert(result.status == GPU_PRIVATE_INPUT);
		queues[0].priority = 1U;
		gpu_firmware_group_configure(&arena_ops, &service, owner, group[i], queues, 2UL - i, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == 2UL - i &&
			result.value[1] == (i == 0U ? 18UL : 2UL));
		gpu_firmware_group_configure(&arena_ops, &service, owner, group[i], queues, 2UL - i, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS); /* Exact idempotent replay. */
		queues[0].priority++;
		gpu_firmware_group_configure(&arena_ops, &service, owner, group[i], queues, 2UL - i, &result);
		assert(result.status == GPU_PRIVATE_STATE); /* Immutable once configured. */
		queues[0].priority--;
		assert(gpu_firmware_group_resources(&service, owner, group[i], &resources[i]));
		assert(resources[i].context == contexts[i] && resources[i].streams == 2U - i);
		assert(resources[i].suspend_bytes == test_suspend_size);
		for (unsigned int s = 0U; s < resources[i].streams; s++) {
			uint32_t va = resources[i].input_va[s];

			assert(va == resources[i].suspend_va + ((test_suspend_size + 4095U) & ~4095U) + s * 8192U);
			assert(resources[i].output_va[s] == va + 4096U);
			assert((pte_at(installed_root, va) & ADDRESS_MASK) ==
				(uintptr_t)arena[(va - GPU_FIRMWARE_CONTROL_VA) / 4096U]);
			uint64_t ring = resources[i].ring_va[s];
			unsigned int first = (unsigned int)((ring - GPU_PRIVATE_CONTROL_GPU_VA) / 4096UL);

			assert(resources[i].ring_bytes[s] == queues[s].ring_bytes &&
				resources[i].priority[s] == queues[s].priority);
			for (unsigned int p = 0U; p < queues[s].ring_bytes / 4096U; p++) {
				uint64_t leaf = pte_at(roots[i], ring + p * 4096UL);

				assert((leaf & ADDRESS_MASK) == (uintptr_t)arena[first + p]);
				assert((leaf & (UINT64_C(1) << 7U)) != 0U); /* GPU read-only. */
				assert((leaf & (UINT64_C(3) << 53U)) == (UINT64_C(3) << 53U));
				assert((leaf & (UINT64_C(7) << 2U)) == 0U && !arena_cpu[first + p]);
			}
			gpu_private_unmap(&arena_ops, owner, contexts[i], ring, 1U, &result);
			assert(result.status == GPU_PRIVATE_INPUT && pte_at(roots[i], ring) != 0UL);
			gpu_firmware_group_queue_validate(&service, owner, group[i], s,
				queues[s].ring_bytes, queues[s].priority, &result);
			assert(result.status == GPU_PRIVATE_SUCCESS);
			gpu_firmware_group_queue_validate(&service, owner, group[i], s,
				queues[s].ring_bytes, queues[s].priority + 1U, &result);
			assert(result.status == GPU_PRIVATE_INPUT);
		}
		uint64_t sync = pte_at(roots[i], resources[i].sync_va);

		assert(sync != 0UL && (sync & (UINT64_C(1) << 7U)) == 0UL);
		assert((sync & (UINT64_C(3) << 53U)) == (UINT64_C(3) << 53U));
		assert(pte_at(roots[1U - i], resources[i].ring_va[0]) == 0UL);
	}
	assert(resources[0].output_va[1] + 4096U <= resources[1].suspend_va);
	staged_tasks(contexts[0], group[0], group[1], &resources[0], roots[0]);
	gpu_firmware_group_validate(&service, &client_a, contexts[0], group[0], 2UL, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_GROUP_RESERVED &&
		result.value[1] == 2UL && result.value[2] == test_suspend_size);
	gpu_firmware_group_validate(&attacker, &client_a, contexts[0], group[0], 2UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_group_validate(&service, &client_b, contexts[0], group[0], 2UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_group_validate(&service, &client_a, contexts[1], group[0], 2UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_group_validate(&service, &client_a, contexts[0], group[0], 1UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_group_validate(&service, &client_a, contexts[0], group[0], 0UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	/* Even two contexts belonging to the same Client cannot substitute. */
	gpu_private_context_create(&arena_ops, &client_a, &service, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	unsigned long sibling_context = result.value[0];

	gpu_firmware_group_validate(&service, &client_a, sibling_context, group[0], 2UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_context_destroy(&arena_ops, &client_a, sibling_context, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	gpu_firmware_group_inspect(&attacker, &client_a, group[0], &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_group_inspect(&service, &client_b, group[0], &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	assert(!gpu_firmware_group_resources(&service, &client_b, group[0], &reused));
	gpu_firmware_group_destroy(&arena_ops, &service, group[0], &result);
	assert(result.status == GPU_PRIVATE_INPUT); /* Proxy cannot revoke a Client group. */
	gpu_private_context_destroy(&arena_ops, &client_a, contexts[0], &result);
	assert(result.status == GPU_PRIVATE_STATE); /* Actual context hold. */
	unsigned int first = (resources[0].suspend_va - GPU_FIRMWARE_CONTROL_VA) / 4096U;
	unsigned int pages = (test_suspend_size + 4095U) / 4096U + 4U;

	memset(arena[first], 0x41, pages * 4096UL);
	fail_clear_index = first + 2U;
	gpu_firmware_group_destroy(&arena_ops, &client_a, group[0], &result);
	assert(result.status == GPU_PRIVATE_STATE && result.value[0] == pages + 18U - 2U);
	assert(pte_at(roots[0], resources[0].ring_va[0]) == 0UL &&
		pte_at(roots[0], resources[0].sync_va) == 0UL); /* Detached before clearing. */
	assert(!gpu_firmware_group_resources(&service, &client_a, group[0], &reused));
	gpu_firmware_group_validate(&service, &client_a, contexts[0], group[0], 2UL, &result);
	assert(result.status == GPU_PRIVATE_STATE); /* Partially scrubbed, never importable. */
	gpu_firmware_group_inspect(&service, &client_a, group[0], &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_GROUP_CLOSING);
	fail_clear_index = UINT_MAX;
	destroy_group(&client_a, group[0], large);
	for (unsigned int i = first; i < first + pages; i++) {
		assert(!arena_cpu[i]); /* Group destruction never restores donor access. */
		for (unsigned int b = 0U; b < 4096U; b++)
			assert(arena[i][b] == 0U);
	}
	gpu_firmware_group_create(&ops, &arena_ops, &service, &client_a, contexts[0], 2UL, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] != group[0]);
	quotas[0] = result.value[0];
	assert(gpu_firmware_group_resources(&service, &client_a, quotas[0], &reused));
	assert(reused.suspend_va == resources[0].suspend_va);
	gpu_firmware_group_inspect(&service, &client_a, group[0], &result);
	assert(result.status == GPU_PRIVATE_INPUT); /* A reused extent has a new generation. */
	gpu_firmware_group_validate(&service, &client_a, contexts[0], group[0], 2UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	unsigned int count = 1U;

	if (!large) {
		for (; count < GPU_FIRMWARE_CLIENT_GROUPS; count++) {
			gpu_firmware_group_create(&ops, &arena_ops, &service, &client_a, contexts[0], 1UL, &result);
			assert(result.status == GPU_PRIVATE_SUCCESS);
			quotas[count] = result.value[0];
		}
		gpu_firmware_group_create(&ops, &arena_ops, &service, &client_a, contexts[0], 1UL, &result);
		assert(result.status == GPU_PRIVATE_FULL); /* Other Client still owns its extent. */
	} else {
		for (; count < GPU_FIRMWARE_CLIENT_GROUPS; count++) {
			gpu_firmware_group_create(&ops, &arena_ops, &service, &client_a, contexts[0], 1UL, &result);
			if (result.status == GPU_PRIVATE_FULL)
				break;
			assert(result.status == GPU_PRIVATE_SUCCESS);
			quotas[count] = result.value[0];
		}
		assert(count < GPU_FIRMWARE_CLIENT_GROUPS); /* Arena full before owner quota. */
		assert(gpu_firmware_group_resources(&service, &client_b, group[1], &reused));
	}
	for (unsigned int i = 0U; i < count; i++)
		destroy_group(&client_a, quotas[i], large);
	if (!large) {
		unsigned long extra_contexts[3], full[GPU_FIRMWARE_LOGICAL_GROUPS - 1U];
		const void *owners[4] = { &client_a, &client_b, &quota_clients[0], &quota_clients[1] };
		unsigned long owner_contexts[4] = { contexts[0], contexts[1], 0UL, 0UL };

		for (unsigned int i = 0U; i < 3U; i++) {
			gpu_private_context_create(&arena_ops, &quota_clients[i], &service, &result);
			assert(result.status == GPU_PRIVATE_SUCCESS);
			extra_contexts[i] = result.value[0];
			if (i < 2U)
				owner_contexts[i + 2U] = extra_contexts[i];
		}
		for (unsigned int i = 0U; i < GPU_FIRMWARE_LOGICAL_GROUPS - 1U; i++) {
			unsigned int owner = i < 8U ? 0U : i < 15U ? 1U : i < 23U ? 2U : 3U;

			gpu_firmware_group_create(&ops, &arena_ops, &service, owners[owner],
				owner_contexts[owner], 1UL, &result);
			assert(result.status == GPU_PRIVATE_SUCCESS);
			full[i] = result.value[0];
		}
		gpu_firmware_group_create(&ops, &arena_ops, &service, &quota_clients[2],
			extra_contexts[2], 1UL, &result);
		assert(result.status == GPU_PRIVATE_FULL); /* All 32 slots, not this owner's quota. */
		for (unsigned int i = 0U; i < GPU_FIRMWARE_LOGICAL_GROUPS - 1U; i++) {
			unsigned int owner = i < 8U ? 0U : i < 15U ? 1U : i < 23U ? 2U : 3U;

			destroy_group(owners[owner], full[i], false);
		}
		for (unsigned int i = 0U; i < 3U; i++) {
			gpu_private_context_destroy(&arena_ops, &quota_clients[i], extra_contexts[i], &result);
			assert(result.status == GPU_PRIVATE_SUCCESS);
		}
	}
	/* Scrub failure during CREATE retains a typed cleanup object and context. */
	fail_clear_index = first;
	gpu_firmware_group_create(&ops, &arena_ops, &service, &client_a, contexts[0], 1UL, &result);
	assert(result.status == GPU_PRIVATE_STATE && result.value[0] != 0UL);
	unsigned long failed = result.value[0];

	assert(!gpu_firmware_group_resources(&service, &client_a, failed, &reused));
	gpu_firmware_group_validate(&service, &client_a, contexts[0], failed, 1UL, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_firmware_group_inspect(&service, &client_a, failed, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_GROUP_QUARANTINED);
	fail_clear_index = UINT_MAX;
	destroy_group(&client_a, failed, large);
	/* Queue setup failures retain their separate extent and context hold. */
	for (unsigned int failure = 0U; failure < 2U; failure++) {
		struct gpu_private_ops memory_ops = arena_ops;
		struct gpu_firmware_queue_config queue = { .ring_bytes = 4096U };

		gpu_firmware_group_create(&ops, &arena_ops, &service, &client_a, contexts[0], 1UL, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		failed = result.value[0];
		unsigned int base_pages = (unsigned int)result.value[3];

		assert(gpu_firmware_group_resources(&service, &client_a, failed, &reused));
		if (failure == 0U)
			fail_clear_index = (reused.suspend_va - GPU_FIRMWARE_CONTROL_VA) / 4096U + base_pages;
		else
			memory_ops.clean = NULL; /* Fails before a Client leaf can be published. */
		gpu_firmware_group_configure(&memory_ops, &service, &client_a, failed, &queue, 1UL, &result);
		assert(result.status != GPU_PRIVATE_SUCCESS);
		gpu_firmware_group_inspect(&service, &client_a, failed, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_GROUP_QUARANTINED &&
			result.value[3] == base_pages + 2UL);
		gpu_private_context_destroy(&arena_ops, &client_a, contexts[0], &result);
		assert(result.status == GPU_PRIVATE_STATE);
		fail_clear_index = UINT_MAX;
		destroy_group(&client_a, failed, large);
	}
	/* First ring is really mapped before the second walk fails. Its alias
	 * and arena lifetime must survive until typed retirement removes it.
	 */
	gpu_firmware_group_create(&ops, &arena_ops, &service, &client_a, contexts[0], 2UL, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	failed = result.value[0];
	struct gpu_firmware_queue_config partial_queues[2] = {
		{ .ring_bytes = 4096U }, { .ring_bytes = 4096U }
	};
	struct gpu_private_ops faulting_ops = arena_ops;

	faulting_ops.table_pa = faulting_table_address;
	fault_after_leaf_writes = 1U;
	gpu_firmware_group_configure(&faulting_ops, &service, &client_a, failed, partial_queues, 2UL, &result);
	assert(result.status == GPU_PRIVATE_FULL && fail_table_lookup);
	fail_table_lookup = false;
	gpu_private_query(&client_a, contexts[0], 0UL, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == 1UL);
	assert(!gpu_firmware_group_resources(&service, &client_a, failed, &reused));
	destroy_group(&client_a, failed, large);
	gpu_private_query(&client_a, contexts[0], 0UL, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == 0UL);
	gpu_firmware_group_create(&ops, &arena_ops, &service, &client_a, contexts[0], 1UL, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	stale_group = result.value[0]; /* Retained with B until verified reset. */
	struct gpu_firmware_queue_config queue = { .ring_bytes = 4096U };
	struct gpu_private_ops active_ops = arena_ops;

	gpu_firmware_group_configure(&arena_ops, &service, &client_a, stale_group, &queue, 1UL, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	struct gpu_private_ops command_ops = arena_ops;
	unsigned long command_ipa = 0x40000000UL;

	command_ops.source_page = command_source;
	gpu_private_bo_create(&client_a, &service, 4096UL, GPU_PRIVATE_READ, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	retained_task_bo = result.value[0];
	gpu_private_bo_append(&command_ops, &client_a, retained_task_bo, 0UL, &command_ipa, 1U, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	gpu_private_map(&command_ops, &client_a, contexts[0], retained_task_bo, 0UL, 0x100000UL, 1U,
		GPU_PRIVATE_READ, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	gpu_firmware_task_stage(&command_ops, &service, &client_a, stale_group, 0UL, 0x100000UL, 8UL, 0UL, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	stale_task = result.value[0]; /* Verify cancellation cannot retire an active root. */
	active_ops.activate = context_activate_model;
	active_ops.synchronize = context_sync_model;
	gpu_private_context_activate(&active_ops, &service, contexts[0], 1UL, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	gpu_firmware_task_cancel(&client_a, stale_task, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_private_bo_destroy(&client_a, retained_task_bo, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_firmware_group_destroy(&arena_ops, &client_a, stale_group, &result);
	assert(result.status == GPU_PRIVATE_STATE); /* Active GPU aliases cannot be recycled. */
	assert(notifications == before + 1U); /* Reservations never ring a task doorbell. */
}

static void protected_arena(uint32_t suspend_bytes)
{
	struct gpu_private_result result;
	unsigned long object, other, ipas[GPU_PRIVATE_BATCH], contexts[2];
	unsigned int bindings;

	installed_root = 0UL;
	test_suspend_size = suspend_bytes;
	prepared();
	for (unsigned int i = 0U; i < GPU_PRIVATE_CONTROL_PAGES; i++)
		arena_cpu[i] = true;
	memset(arena, 0xcc, sizeof(arena));
	gpu_private_control_create(&service, sizeof(arena), &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	object = result.value[0];
	gpu_firmware_control_bind(&ops, &arena_ops, &service, object, &result);
	assert(result.status == GPU_PRIVATE_STATE); /* Not donated yet. */
	for (unsigned int offset = 0U; offset < GPU_PRIVATE_CONTROL_PAGES; offset += GPU_PRIVATE_BATCH) {
		for (unsigned int i = 0U; i < GPU_PRIVATE_BATCH; i++)
			ipas[i] = 0x20000000UL + (offset + i) * 4096UL;
		gpu_private_control_append(&arena_ops, &service, object,
			offset * 4096UL, ipas, GPU_PRIVATE_BATCH, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
	}
	gpu_firmware_control_bind(&ops, &arena_ops, &attacker, object, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_control_bind(&ops, &arena_ops, &service, object, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == sizeof(arena));
	assert(result.value[1] == GPU_PRIVATE_CONTROL_PAGES && result.value[2] == 0UL && result.value[3] == 0UL);
	assert(GPU_FIRMWARE_CONTROL_VA >= 0x04000000U &&
		(uint64_t)GPU_FIRMWARE_CONTROL_VA + sizeof(arena) <= 0x08000000U);
	for (unsigned int i = 0U; i < GPU_PRIVATE_CONTROL_PAGES; i++) {
		uint64_t pte = pte_at((uintptr_t)runtime_root, GPU_FIRMWARE_CONTROL_VA + i * 4096UL);

		assert((pte & ADDRESS_MASK) == (uintptr_t)arena[i]);
		assert((pte & (3UL << 53U)) == (3UL << 53U) && (pte & (1UL << 7U)) == 0UL);
		assert((pte & (7UL << 2U)) == 0UL); /* Fixed NC MCU data. */
		assert(!arena_cpu[i] && arena[i][0] == 0U);
	}
	bindings = cleans;
	gpu_firmware_control_bind(&ops, &arena_ops, &service, object, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && cleans == bindings);
	gpu_private_control_create(&service, 4096UL, &result);
	assert(result.status == GPU_PRIVATE_FULL); /* Global arena quota is held. */
	gpu_private_control_destroy(&arena_ops, &service, object, &result);
	assert(result.status == GPU_PRIVATE_STATE && !arena_cpu[0]);
	gpu_firmware_boot(&ops, &service, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	unsigned long root = installed_root;

	gpu_firmware_control_bind(&ops, &arena_ops, &service, object, &result);
	assert(result.status == GPU_PRIVATE_STATE); /* No live AS0 edits. */
	group_reservations(contexts);
	memset(arena, 0x5a, sizeof(arena)); /* Model private GPU suspend/ring state. */
	gpu_private_device_revoked(&arena_ops);
	gpu_firmware_device_revoked();
	assert(!arena_cpu[0] && *(uint64_t *)(uintptr_t)root == 0UL);
	gpu_firmware_task_cancel(&client_a, stale_task, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_bo_destroy(&client_a, retained_task_bo, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS); /* Verified reset retired mappings/holds. */
	retained_task_bo = 0UL;
	gpu_firmware_group_inspect(&service, &client_a, stale_group, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_context_destroy(&arena_ops, &client_a, contexts[0], &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	gpu_private_context_destroy(&arena_ops, &client_b, contexts[1], &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	do {
		gpu_private_control_destroy(&arena_ops, &service, object, &result);
	} while (result.status == GPU_PRIVATE_INCOMPLETE);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	for (unsigned int i = 0U; i < GPU_PRIVATE_CONTROL_PAGES; i++)
		assert(arena_cpu[i] && arena[i][0] == 0U);
	/* A Client data object can never become an internal MCU arena. */
	installed_root = 0UL;
	prepared();
	gpu_private_bo_create(&attacker, &service, 4096UL, GPU_PRIVATE_READ, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	other = result.value[0];
	gpu_firmware_control_bind(&ops, &arena_ops, &service, other, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_private_bo_destroy(&attacker, other, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	gpu_firmware_device_revoked();
	test_suspend_size = 0x40000U;
	puts("GPU_FIRMWARE_CONTROL_ARENA=PASS real 16 MiB donated object and four-level MCU PTEs, all 4096 page addresses/permissions, opaque reply, pre-boot-only binding, hold across boot, trusted reset and scrub-before-CPU-restore");
	puts("GPU_GROUP_MEMORY=PASS actual Client/context/service binding, context holds, disjoint protected suspend/queue IO extents and real MCU leaves, no Proxy addresses or launch, per-Client quota, stale generations, scrub failures retained, bounded retirement, zero-before-reuse and trusted reset");
	puts("GPU_GROUP_RINGS=PASS immutable Client queue snapshot, 4KiB/64KiB RO/XN/NC real Client PTEs, RW/XN completion page, no cross-Client alias, reserved MAP/UNMAP rejection, configuration clear/map failures and partial first-ring mapping retained, detach-before-scrub and active-context retirement refusal; MODEL_ONLY no task publication");
}

static void runtime(void)
{
	struct gpu_private_result result;
	unsigned int old_installs, old_boots;

	prepared();
	gpu_firmware_boot(&ops, &attacker, &result);
	assert(result.status == GPU_PRIVATE_INPUT && installs == 0U);
	gpu_firmware_boot(&ops, &service, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_BOOTED);
	assert(installs == 1U && boots == 1U && invalidations == 1U);
	gpu_firmware_boot(&ops, &service, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && installs == 1U && boots == 1U);
	gpu_firmware_device_revoked();
	for (size_t i = 0U; i < runtime_bytes; i++)
		assert(runtime_memory[i] == 0U);
	assert(pte_at((uintptr_t)runtime_root, 0UL) == 0UL);
	for (unsigned int failure = 0U; failure < 3U; failure++) {
		installed_root = 0UL;
		prepared();
		install_succeeds = failure != 0U;
		boot_succeeds = failure != 1U;
		bad_shared = failure == 2U;
		old_installs = installs;
		old_boots = boots;
		gpu_firmware_boot(&ops, &service, &result);
		assert(result.status == GPU_PRIVATE_STATE);
		assert(installs == old_installs + 1U);
		assert(boots == old_boots + (failure != 0U ? 1U : 0U));
		gpu_firmware_inspect(&service, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_QUARANTINED);
		assert(pte_at((uintptr_t)runtime_root, 0x00800000UL) != 0UL); /* Retain backing. */
		gpu_firmware_prepare(&ops, &service, &result);
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_firmware_begin(&service, sizeof(original), &result);
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_firmware_boot(&ops, &service, &result);
		assert(result.status == GPU_PRIVATE_STATE && installs == old_installs + 1U);
		gpu_firmware_device_revoked();
		install_succeeds = boot_succeeds = true;
		bad_shared = false;
	}
	puts("GPU_FIRMWARE_RUNTIME=PASS private runtime pages, real 4-level descriptors, full image and zero tails, permissions, protected-section exclusion, opaque root install, boot handshake, bounds, idempotence, quarantine and reset retirement");
}

static void configured_runtime(void)
{
	struct gpu_private_result result;
	unsigned int before;

	for (unsigned int scenario = 0U; scenario < 6U; scenario++) {
		installed_root = 0UL;
		notifications = clean_inputs = 0U;
		clock_ticks = ~0UL - 4UL; /* Bounded elapsed arithmetic across wrap. */
		previous_ack = scenario == 5U ? 10U : 0U;
		prepared();
		gpu_firmware_properties(&service, 0UL, &result);
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_firmware_boot(&ops, &service, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS);
		gpu_firmware_properties(&attacker, 0UL, &result);
		assert(result.status == GPU_PRIVATE_INPUT);
		gpu_firmware_properties(&service, 2UL, &result);
		assert(result.status == GPU_PRIVATE_INPUT);
		gpu_firmware_properties(&service, 0UL, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == 0x01010000UL);
		assert(result.value[2] == 8UL && result.value[3] == 0x71UL);
		gpu_firmware_properties(&service, 1UL, &result);
		assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == 8UL);
		assert(result.value[1] == 0x7015fUL && result.value[2] == 0x40000UL && result.value[3] == 0x20000UL);
		/* Cached bounds/properties must not follow later live pointer changes. */
		uint32_t *shared = (void *)(uintptr_t)(pte_at(installed_root, 0x04000000UL) & ADDRESS_MASK);

		shared[2] = UINT32_MAX;
		config_succeeds = scenario != 1U;
		notify_succeeds = scenario != 2U;
		acknowledge = scenario != 3U;
		fault_after_ack = scenario == 4U;
		gpu_firmware_configure(&ops, &attacker, &result);
		assert(result.status == GPU_PRIVATE_INPUT && notifications == 0U);
		gpu_firmware_configure(&ops, &service, &result);
		if (scenario == 0U || scenario == 5U) {
			assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] == GPU_FIRMWARE_CONFIGURED);
			assert(notifications == 1U);
			before = installs;
			gpu_firmware_configure(&ops, &service, &result);
			assert(result.status == GPU_PRIVATE_SUCCESS && notifications == 1U);
			gpu_firmware_boot(&ops, &service, &result);
			assert(result.status == GPU_PRIVATE_SUCCESS && installs == before);
		} else {
			assert(result.status == GPU_PRIVATE_STATE);
			gpu_firmware_inspect(&service, &result);
			assert(result.value[0] == (scenario == 1U ? GPU_FIRMWARE_BOOTED : GPU_FIRMWARE_QUARANTINED));
			assert(notifications == (scenario == 1U ? 0U : 1U));
			if (scenario != 1U) {
				gpu_firmware_properties(&service, 0UL, &result);
				assert(result.status == GPU_PRIVATE_STATE);
				gpu_firmware_configure(&ops, &service, &result);
				assert(result.status == GPU_PRIVATE_STATE && notifications == 1U);
			}
		}
		gpu_firmware_device_revoked();
		gpu_firmware_properties(&service, 0UL, &result);
		assert(result.status != GPU_PRIVATE_SUCCESS);
		config_succeeds = notify_succeeds = acknowledge = true;
		fault_after_ack = false;
	}
	previous_ack = 0U;
	for (malformed = 1U; malformed <= 18U; malformed++) {
		installed_root = 0UL;
		prepared();
		gpu_firmware_boot(&ops, &service, &result);
		assert(result.status == GPU_PRIVATE_STATE);
		gpu_firmware_inspect(&service, &result);
		assert(result.value[0] == GPU_FIRMWARE_QUARANTINED);
		gpu_firmware_properties(&service, 0UL, &result);
		assert(result.status == GPU_PRIVATE_STATE);
		assert(pte_at((uintptr_t)runtime_root, 0x04000000UL) != 0UL);
		gpu_firmware_device_revoked();
	}
	malformed = 0U;
	puts("GPU_FIRMWARE_WORD_ALIGNMENT=PASS six interface starts reject byte misalignment before configuration; MODEL_ONLY");
	puts("GPU_FIRMWARE_CONFIG=PASS complete group/stream bounds, cross-interface alias/overflow rejection, immutable sanitized properties, fixed private config, ACK toggle, bounded real ACK, wraparound, hardware-fault rejection, quarantine and reset");
}

int main(int argc, char **argv)
{
	struct gpu_private_result result;
	struct gpu_firmware_section section;
	const void *data;
	FILE *file;
	unsigned int before;
	unsigned long total = 0UL;

	assert(argc == 2);
	file = fopen(argv[1], "rb");
	assert(file != NULL);
	assert(fread(original, 1U, sizeof(original), file) == sizeof(original));
	assert(fgetc(file) == EOF);
	assert(fclose(file) == 0);
	assert(!gpu_firmware_section(&service, 0U, &section, &data));
	gpu_firmware_begin(NULL, sizeof(original), &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_begin(&service, sizeof(original) - 1UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	begin();
	gpu_firmware_begin(&attacker, sizeof(original), &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_firmware_write(&attacker, 0UL, original, 4096U, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_write(&service, 0UL, original, 4097U, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_write(&service, ~0UL, original, 4096U, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_firmware_write(&service, 4096UL, original, 4096U, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_firmware_seal(&ops, &service, &result);
	assert(result.status == GPU_PRIVATE_INCOMPLETE && digest_calls == 0U);
	gpu_firmware_write(&service, 0UL, original, 4096U, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	gpu_firmware_write(&service, 0UL, original, 4096U, &result);
	assert(result.status == GPU_PRIVATE_STATE); /* No replay or overwrite. */
	begin(); /* Interrupted upload can be restarted by its authenticated service. */
	memcpy(supplied, original, sizeof(supplied));
	upload();
	memset(supplied, 0x55, sizeof(supplied)); /* Source mutation after copy. */
	gpu_firmware_seal(&ops, &attacker, &result);
	assert(result.status == GPU_PRIVATE_INPUT && digest_calls == 0U);
	gpu_firmware_seal(&ops, &service, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && digest_calls == 1U);
	assert(result.value[0] == GPU_FIRMWARE_VERIFIED);
	assert(result.value[1] == sizeof(original) && result.value[2] == 7UL);
	assert(result.value[3] == 720896UL);
	for (unsigned int i = 0U; i < 7U; i++) {
		assert(gpu_firmware_section(&service, i, &section, &data));
		assert((section.flags & 32U) == 0U); /* Protected section not imported. */
		assert(memcmp(data, original + section.data_offset, section.data_size) == 0);
		total += section.size;
		if ((section.flags & (1U << 30U)) != 0U)
			assert(section.va == 0x04000000U && section.size == 0xc000U);
	}
	assert(total == 720896UL);
	assert(!gpu_firmware_section(&service, 7U, &section, &data));
	assert(!gpu_firmware_section(&attacker, 0U, &section, &data));
	assert(!gpu_firmware_section(&service, 0U, NULL, &data));
	before = digest_calls;
	gpu_firmware_begin(&service, sizeof(original), &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_firmware_write(&service, 0UL, original, 4096U, &result);
	assert(result.status == GPU_PRIVATE_STATE);
	gpu_firmware_seal(&ops, &service, &result);
	assert(result.status == GPU_PRIVATE_STATE && digest_calls == before);
	gpu_firmware_device_revoked();
	assert(!gpu_firmware_section(&service, 0U, &section, &data));
	gpu_firmware_device_revoked(); /* Idempotent; no source-page references. */
	rejected_image(0UL); /* Header. */
	rejected_image(116UL); /* Executable section metadata. */
	rejected_image(0x244cUL); /* Executable bytes. */
	rejected_image(sizeof(original) - 1UL); /* Full image, including trailing bytes. */
	begin();
	memcpy(supplied, original, sizeof(supplied));
	upload();
	digest_succeeds = false;
	gpu_firmware_seal(&ops, &service, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	digest_succeeds = true;
	runtime();
	configured_runtime();
	protected_arena(0x40000U);
	protected_arena(0x210000U); /* Multi-batch group retirement with real large extents. */
	puts("GPU_FIRMWARE_SNAPSHOT=PASS pinned SHA256, real CSF metadata, private copy, owner binding, ordered upload, no post-seal overwrite, tamper and crypto failure rejection, trusted retirement");
	puts("GPU_FIRMWARE_BOOT=MODEL_ONLY GPU_PRIVATE_EXECUTION=NOT_IMPLEMENTED");
	return 0;
}
