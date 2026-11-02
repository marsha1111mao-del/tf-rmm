/* SPDX-License-Identifier: BSD-3-Clause */
/* Appended only to the checker's firmware translation unit, giving this
 * model access to private records without adding any production test API.
 */
#include <stdio.h>

void gpu_replay_input_test(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long context, unsigned long handle,
		unsigned long token)
{
	struct fw_group *group = group_lookup(owner, handle);
	struct fw_task *task = task_lookup(owner, token);
	struct gpu_private_result replay;
	unsigned char *shared = runtime_pages[section_page[interfaces.section]];
	struct fw_slot *slot = &interfaces.slots[group->hardware_csg];
	unsigned char *global = shared + interfaces.global.input;
	unsigned char *input = shared + slot->group.input;
	unsigned char global_before[FW_GLOBAL_INPUT_SIZE], input_before[FW_GROUP_INPUT_SIZE];
	struct fw_group group_before = *group;
	struct fw_task task_before = *task;
	unsigned int checks = 0U;

	assert(task != NULL && task->started && task->start_attempted);
	memcpy(global_before, global, sizeof(global_before));
	memcpy(input_before, input, sizeof(input_before));
	/* Every consumed word must be reread after a previously successful replay.
	 * Include the complete CSG state, rather than only its low state bit.
	 */
	for (unsigned int field = 0U; field < 5U; field++) {
		unsigned char *word = field < 2U ? global : input;
		unsigned int index = field == 0U || field == 2U ? 0U : field == 4U ? 20U : 2U;
		uint32_t value, mask = field == 0U || field == 2U ? 2U :
			field == 1U ? 1U << group->hardware_csg : field == 3U ? group->active_queues : 1U;

		gpu_firmware_task_start(ops, memory_ops, service, owner, context, handle, token, &replay);
		assert(replay.status == GPU_PRIVATE_SUCCESS && "valid replay before changed input");
		memcpy(&value, word + index * 4U, sizeof(value));
		value ^= mask;
		memcpy(word + index * 4U, &value, sizeof(value));
		gpu_firmware_task_start(ops, memory_ops, service, owner, context, handle, token, &replay);
		assert(replay.status != GPU_PRIVATE_SUCCESS && "replay rejects changed input");
		assert(group->state == GPU_FIRMWARE_GROUP_QUARANTINED);
		assert(memcmp(task, &task_before, sizeof(*task)) == 0);
		/* Model-only rollback isolates the next fault. No production recovery
		 * path restores a quarantined task this way.
		 */
		memcpy(global, global_before, sizeof(global_before));
		memcpy(input, input_before, sizeof(input_before));
		*group = group_before;
		checks++;
	}
	/* Other input words are preserved by replay and are never republished.
	 * Perturb each independently: it must not affect acceptance or be changed.
	 */
	for (unsigned int area = 0U; area < 2U; area++) {
		unsigned char *memory = area == 0U ? global : input;
		unsigned int words = (area == 0U ? sizeof(global_before) : sizeof(input_before)) / 4U;

		for (unsigned int word = 0U; word < words; word++) {
			uint32_t value, after;

			if (word == 0U || word == 2U || (area == 1U && word == 20U))
				continue;
			memcpy(&value, memory + word * 4U, sizeof(value));
			value ^= UINT32_C(0xa5963c5a);
			memcpy(memory + word * 4U, &value, sizeof(value));
			gpu_firmware_task_start(ops, memory_ops, service, owner, context, handle, token, &replay);
			assert(replay.status == GPU_PRIVATE_SUCCESS && "irrelevant input unchanged by replay");
			memcpy(&after, memory + word * 4U, sizeof(after));
			assert(after == value);
			assert(memcmp(group, &group_before, sizeof(*group)) == 0);
			assert(memcmp(task, &task_before, sizeof(*task)) == 0);
			memcpy(global, global_before, sizeof(global_before));
			memcpy(input, input_before, sizeof(input_before));
			checks++;
		}
	}
	printf("GPU_REPLAY_INPUT=PASS checks=%u fresh five words, all other input preserved, no task mutation; MODEL_ONLY\n", checks);
}
