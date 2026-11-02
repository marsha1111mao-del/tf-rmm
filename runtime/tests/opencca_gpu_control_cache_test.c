/* SPDX-License-Identifier: BSD-3-Clause */
/* Actual RSI callbacks, with a noncoherent CPU/GPU memory and slot model.
 * This verifies cache coverage and ordering, not physical GPC enforcement.
 */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GRANULE_SIZE 4096U
#define GRANULE_STATE_DATA 1
#define SLOT_RSI_CALL 7
#define LINE 64U
#define PAGE_PA 0x10000UL

struct granule { unsigned int unused; } page;
static _Alignas(GRANULE_SIZE) unsigned char cpu[GRANULE_SIZE];
static unsigned char gpu[GRANULE_SIZE], output[GRANULE_SIZE];
static unsigned int stage, lookups, lines, snapshots;
static bool full_reference, missing_page;
static size_t requested_offset, requested_bytes;

static struct granule *find_lock_granule(unsigned long pa, int state)
{
	assert(stage == 0U && state == GRANULE_STATE_DATA);
	++lookups;
	if (missing_page || pa != PAGE_PA)
		return NULL;
	stage = 1;
	return &page;
}

static void *buffer_granule_map(struct granule *p, int slot)
{
	assert(stage == 1U && p == &page && slot == SLOT_RSI_CALL);
	stage = 2;
	return cpu;
}

static void inv_dcache_range(uintptr_t address, size_t bytes)
{
	size_t offset = address - (uintptr_t)cpu;
	assert(stage == 2U && offset < GRANULE_SIZE);
	assert(bytes != 0U && bytes <= GRANULE_SIZE - offset);
	if (snapshots != 0U) {
		assert(offset == (full_reference ? 0U : requested_offset));
		assert(bytes == (full_reference ? GRANULE_SIZE : requested_bytes));
	} else {
		/* Actual private-data ownership callbacks must still cover the page. */
		assert(offset == 0U && bytes == GRANULE_SIZE);
	}
	for (size_t i = offset & ~(LINE - 1U); i < offset + bytes; i += LINE) {
		memcpy(cpu + i, gpu + i, LINE);
		++lines;
	}
	stage = 3;
}

static void flush_dcache_range(uintptr_t address, size_t bytes)
{
	assert(stage == 2U && address == (uintptr_t)cpu && bytes == GRANULE_SIZE);
	memcpy(gpu, cpu, GRANULE_SIZE);
	lines += GRANULE_SIZE / LINE;
	stage = 3;
}

static void barrier(void)
{
	assert(stage == 3U);
	stage = 4;
}
#define dsb(kind) barrier()

static void *snapshot_copy(void *destination, const void *source, size_t bytes)
{
	assert(stage == 4U && destination == output);
	assert(source == cpu + requested_offset && bytes == requested_bytes);
	stage = 5;
	return memcpy(destination, source, bytes);
}

static void buffer_unmap(void *memory)
{
	assert(memory == cpu && stage == (snapshots != 0U ? 5U : 4U));
	stage = 6;
}

static void granule_unlock(struct granule *p)
{
	assert(stage == 6U && p == &page);
	stage = 7;
}

#define memcpy snapshot_copy
#include "control-cache.inc"
#undef memcpy

static void snapshot(size_t offset, size_t bytes, unsigned int generation)
{
	stage = lookups = lines = 0;
	snapshots = 1;
	requested_offset = offset;
	requested_bytes = bytes;
	memset(output, 0x55, sizeof(output));
	memset(cpu, 0xa5, sizeof(cpu));
	for (size_t i = 0; i < sizeof(gpu); ++i)
		gpu[i] = (unsigned char)(i * 17U + generation);
	assert(read_page(PAGE_PA, offset, output, bytes));
	assert(stage == 7U && lookups == 1U);
	assert(memcmp(output, gpu + offset, bytes) == 0);
	assert(lines == (full_reference ? GRANULE_SIZE / LINE :
		((offset + bytes - 1U) / LINE - offset / LINE + 1U)));
	for (size_t i = bytes; i < sizeof(output); ++i)
		assert(output[i] == 0x55);
	if (!full_reference) {
		size_t first = offset & ~(LINE - 1U);
		size_t end = (offset + bytes + LINE - 1U) & ~(LINE - 1U);
		for (size_t i = 0; i < sizeof(cpu); ++i)
			assert(cpu[i] == (i >= first && i < end ? gpu[i] : 0xa5));
	}
}

int main(int argc, char **argv)
{
	unsigned int cases = 0;
	assert(argc == 2);
	full_reference = strcmp(argv[1], "full-reference") == 0;
	assert(full_reference || strcmp(argv[1], "range") == 0);
	const size_t sizes[] = {1, 8, 16, 32, 64, 65, 216, GRANULE_SIZE};
	for (size_t offset = 0; offset < GRANULE_SIZE; ++offset) {
		for (size_t k = 0; k < sizeof(sizes) / sizeof(sizes[0]); ++k) {
			if (sizes[k] > GRANULE_SIZE - offset)
				continue;
			snapshot(offset, sizes[k], ++cases);
		}
		snapshot(offset, GRANULE_SIZE - offset, ++cases);
	}
	/* A later snapshot must observe fresh device data, including a range
	 * whose stale/speculatively filled cache lines were previously unread.
	 */
	snapshot(64, 8, ++cases);
	memset(gpu + 256, 0x3c, LINE);
	stage = lookups = lines = 0;
	requested_offset = 256;
	requested_bytes = 16;
	assert(read_page(PAGE_PA, 256, output, 16));
	for (size_t i = 0; i < 16; ++i)
		assert(output[i] == 0x3c);

	stage = lookups = lines = 0;
	assert(!read_page(PAGE_PA, 0, NULL, 1));
	assert(!read_page(PAGE_PA, 0, output, 0));
	assert(!read_page(PAGE_PA, GRANULE_SIZE, output, 1));
	assert(!read_page(PAGE_PA, GRANULE_SIZE + 1UL, output, 1));
	assert(!read_page(PAGE_PA, SIZE_MAX, output, 1));
	assert(!read_page(PAGE_PA, 1, output, SIZE_MAX));
	assert(!read_page(PAGE_PA, 4090, output, 8));
	assert(stage == 0U && lookups == 0U && lines == 0U);
	missing_page = true;
	assert(!read_page(PAGE_PA, 0, output, 8));
	assert(stage == 0U && lookups == 1U && lines == 0U);
	missing_page = false;
	assert(!read_page(PAGE_PA + 1, 0, output, 8));
	assert(stage == 0U && lookups == 2U && lines == 0U);

	snapshots = stage = lookups = lines = 0;
	memset(cpu, 0x24, sizeof(cpu));
	assert(sync_page_for_device(PAGE_PA));
	assert(stage == 7U && lines == GRANULE_SIZE / LINE);
	assert(memcmp(cpu, gpu, GRANULE_SIZE) == 0);
	stage = lookups = lines = 0;
	memset(gpu, 0x42, sizeof(gpu));
	assert(sync_page_for_cpu(PAGE_PA));
	assert(stage == 7U && lines == GRANULE_SIZE / LINE);
	assert(memcmp(cpu, gpu, GRANULE_SIZE) == 0);
	missing_page = true;
	stage = lookups = lines = 0;
	assert(!sync_page_for_cpu(PAGE_PA));
	assert(!sync_page_for_device(PAGE_PA));
	assert(stage == 0U && lookups == 2U && lines == 0U);
	printf("GPU_CONTROL_CACHE=PASS mode=%s snapshots=%u page_lines=64 small_read_lines=%u\n",
		argv[1], cases + 1U, full_reference ? 64U : 1U);
	return 0;
}
