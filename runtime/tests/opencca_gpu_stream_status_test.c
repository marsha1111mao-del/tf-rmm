/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* The checker extracts the actual production status reader into this file.
 * Device writes remain invisible until the invalidation double copies whole
 * cache lines. A direct coherent-memory test would miss stale-field bugs.
 */
static unsigned char device[256] __attribute__((aligned(64)));
static unsigned char cached[256] __attribute__((aligned(64)));
static unsigned int calls, lines;
struct gpu_firmware_ops {
	void (*invalidate)(const void *memory, size_t bytes);
};
#define FW_STREAM_OUTPUT_SIZE 0xd8U
#include "stream-status.inc"

static void invalidate(const void *memory, size_t bytes)
{
	assert(memory == cached && bytes > 0U && bytes <= FW_STREAM_OUTPUT_SIZE);
	calls++;
	lines = (unsigned int)((bytes + 63U) / 64U);
	memcpy(cached, device, lines * 64U);
}

int main(int argc, char **argv)
{
	const struct gpu_firmware_ops ops = {.invalidate = invalidate};
	const unsigned int offsets[] = {0U, 23U, 24U, 32U, 33U};
	bool full = argc == 2 && strcmp(argv[1], "full-reference") == 0;
	unsigned int observations = 0U;

	for (unsigned int field = 0U; field < 5U; field++) {
		for (unsigned int trial = 1U; trial <= 128U; trial++) {
			struct fw_stream_status status;
			uint32_t expected[5], actual[5];

			memset(device, 0x5a, sizeof(device));
			memset(cached, 0xa5, sizeof(cached));
			memset(&status, 0, sizeof(status));
			for (unsigned int i = 0U; i < 5U; i++) {
				expected[i] = i == field ? (1U << ((trial - 1U) % 32U)) : 0U;
				memcpy(device + offsets[i] * 4U, &expected[i], 4U);
			}
			calls = 0U;
			stream_status(&ops, cached, &status);
			actual[0] = status.ack;
			actual[1] = status.scoreboards;
			actual[2] = status.blocked_reason;
			actual[3] = status.fault;
			actual[4] = status.fatal;
			assert(calls == 1U && lines == (full ? 4U : 3U));
			assert(memcmp(actual, expected, sizeof(actual)) == 0);
			/* The fourth line contains no field consumed by this helper. */
			assert(cached[192] == (full ? 0x5aU : 0xa5U));
			observations++;
		}
	}
	printf("GPU_STREAM_STATUS=PASS observations=%u lines=%u all five fields fresh\n",
		observations, lines);
	return 0;
}
