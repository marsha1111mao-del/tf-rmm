/* SPDX-License-Identifier: BSD-3-Clause */
/* Exercise the actual firmware helper, including all-queue atomicity. Only
 * private-task lease release is substituted, to inject its failure boundary.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#define gpu_private_task_retire history_test_task_retire
#include "../core/opencca_gpu_firmware.c"
#undef gpu_private_task_retire

static unsigned char test_service, test_owner;
static unsigned int releases;
static bool release_ok;

bool history_test_task_retire(const void *service, const void *owner,
		unsigned long context, unsigned long token)
{
	assert(service == &test_service && owner == &test_owner);
	assert(context == 17UL && token == 29UL);
	releases++;
	return release_ok;
}

int main(int argc, char **argv)
{
	assert(argc == 2);
	unsigned int scenario = (unsigned int)strtoul(argv[1], NULL, 10);
	struct fw_group *group = &groups[3];
	*group = (struct fw_group){ .context = 17UL, .streams = GPU_FIRMWARE_STREAMS };
	uint64_t *history = fw_storage.history[3];
	struct fw_task task = { .handle = 29UL, .preserve = true };
	uint64_t saved[GPU_FIRMWARE_STREAMS], base;
	bool expected = true;

	assert(scenario < 18U);
	state = GPU_FIRMWARE_CONFIGURED;
	fw_storage.history[2][31] = 987648UL;
	for (unsigned int q = 0U; q < group->streams; q++) {
		history[q] = (uint64_t)(q + 1U) * 4096U;
		task.queue_count[q] = (uint8_t)(q % 3U);
	}
	release_ok = true;
	switch (scenario) {
	case 0: break; /* Distinct queue histories, including untouched queues. */
	case 1: release_ok = expected = false; break;
	case 2: history[31]++; expected = false; break;
	case 3: history[31] = UINT64_MAX - 127U; expected = false; break;
	case 4: task.queue_count[31] = GPU_PRIVATE_TASK_BATCH + 1U; expected = false; break;
	case 5: /* Exact last legal starting cursor must complete without wrap. */
		history[31] = (UINT64_MAX - GPU_PRIVATE_TASK_BATCH * 128U) & ~UINT64_C(127);
		task.queue_count[31] = GPU_PRIVATE_TASK_BATCH;
		break;
	case 6: task.preserve = false; break; /* Aborted, scrubbed arena restarts. */
	case 7: task.preserve = false; release_ok = expected = false; break;
	case 8: group->streams = 1U; task.queue_count[0] = GPU_PRIVATE_TASK_BATCH; break;
	case 9: group->streams = GPU_FIRMWARE_STREAMS + 1U; expected = false; break;
	case 10: /* No queue may release or advance if a late queue is invalid. */
		history[30] = UINT64_MAX; expected = false; break;
	case 11: group->streams = 2U; task.queue_count[0] = 0U; task.queue_count[1] = 3U; break;
	case 12: memset(history, 0, sizeof(fw_storage.history[3])); break;
	case 13: group->streams = 0U; expected = false; break;
	case 14: state = GPU_FIRMWARE_BOOTED; expected = false; break;
	case 15:
		gpu_firmware_device_revoked();
		for (unsigned int i = 0U; i < sizeof(fw_storage); i++)
			assert(((unsigned char *)&fw_storage)[i] == 0U);
		puts("GPU_QUEUE_HISTORY=PASS scenario=15 trusted reset erases all history and discovery scratch; MODEL_ONLY");
		return 0;
	case 16:
		group->streams = 1U;
		break; /* Retirement of group 3 must not alter group 2. */
	case 17:
		assert(!shared_ready(NULL)); /* Cannot rediscover while CONFIGURED. */
		break;
	}
	memcpy(saved, history, sizeof(saved));
	assert(!queue_base(group, GPU_FIRMWARE_STREAMS, &base));
	assert(retire_history(&test_service, &test_owner, group, &task) == expected);
	if (!expected) {
		assert(memcmp(saved, history, sizeof(saved)) == 0);
		assert(releases == (release_ok ? 0U : 1U));
	} else {
		assert(releases == 1U);
		for (unsigned int q = 0U; q < GPU_FIRMWARE_STREAMS; q++) {
			uint64_t target = !task.preserve ? 0U : saved[q] +
				(q < group->streams ? task.queue_count[q] * UINT64_C(128) : 0U);
			assert(history[q] == target);
		}
		if (scenario == 5U)
			assert(!queue_base(group, 31U, &base)); /* Next use denied, never wrap. */
		if (scenario == 0U) {
			/* A second task continues every queue rather than replacing base. */
			assert(retire_history(&test_service, &test_owner, group, &task));
			for (unsigned int q = 0U; q < group->streams; q++)
				assert(history[q] == saved[q] + task.queue_count[q] * UINT64_C(256));
		}
	}
	assert(fw_storage.history[2][31] == 987648UL);
	printf("GPU_QUEUE_HISTORY=PASS scenario=%u in-RMM canonical cursors, all-queue preflight, lease failure atomicity and abort reset; MODEL_ONLY\n", scenario);
	return 0;
}
