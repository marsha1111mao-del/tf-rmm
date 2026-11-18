/* SPDX-License-Identifier: BSD-3-Clause */
/* Compare production registration queries with an independent page oracle. */
#include <stdio.h>
#include <opencca_gpu_private.c>

static int owners[2], service;
static unsigned long expected[32768];
static unsigned int count;

static bool source(const void *owner, unsigned long ipa, unsigned long *pa)
{
	if (gpu_private_range_busy(owner, ipa, GPU_PRIVATE_PAGE_SIZE))
		return false;
	*pa = ipa + (owner == &owners[0] ? 0x100000000UL : 0x200000000UL);
	return true;
}

static const struct gpu_private_ops ops = { .source_page = source };

static unsigned long create(unsigned int pages)
{
	struct gpu_private_result r;

	gpu_private_bo_create(&owners[0], &service, pages * 4096UL, 3UL, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	return r.value[0];
}

static struct gpu_private_result append(unsigned long bo, unsigned int first,
		unsigned long *pages, unsigned int n)
{
	struct gpu_private_result r;

	gpu_private_bo_append(&ops, &owners[0], bo, first * 4096UL, pages, n, &r);
	return r;
}

static bool reference(unsigned long ipa, unsigned long size)
{
	if (size == 0UL)
		return false;
	for (unsigned int i = 0U; i < count; i++) {
		unsigned long page = expected[i];

		if (page >= ipa ? page - ipa < size : ipa - page < 4096UL)
			return true;
	}
	return false;
}

static void check(unsigned long ipa, unsigned long size)
{
	assert(gpu_private_range_busy(&owners[0], ipa, size) == reference(ipa, size));
	assert(!gpu_private_range_busy(&owners[1], ipa, size));
}

int main(void)
{
	unsigned long pages[512], bo = create(32768U), second;
	unsigned long rng = 1234567UL;
	unsigned long retry[3] = { 0x10000000UL, 0x10001000UL, 0x10000000UL };
	struct gpu_private_result r;

	/* Holes lie inside the BO bounds but outside every backing block. */
	for (unsigned int block = 0U; block < 64U; block++) {
		for (unsigned int i = 0U; i < 512U; i++)
			pages[i] = 0x40000000UL + (block * 1024UL + i) * 4096UL;
		r = append(bo, count, pages, 512U);
		assert(r.status == GPU_PRIVATE_SUCCESS);
		for (unsigned int i = 0U; i < 512U; i++)
			expected[count++] = pages[i];
	}
	for (unsigned int i = 0U; i < 3000U; i++)
		assert(!gpu_private_range_busy(&owners[0],
			0x40000000UL + ((i % 63U) * 1024UL + 700UL) * 4096UL, 4096UL));
	for (unsigned int i = 0U; i < 2000U; i++) {
		rng = rng * 6364136223846793005UL + 1UL;
		check(0x40000000UL + rng % (64UL * 1024UL * 4096UL),
			(rng >> 32U) % 16385UL);
	}
	check(0UL, ULONG_MAX);
	check(ULONG_MAX - 1024UL, 2048UL);
	check(0x40000000UL - 1UL, 1UL);
	check(0x40000000UL - 1UL, 2UL);

	/* A partial failed append publishes no pages, and a retry may differ. */
	second = create(3U);
	r = append(second, 0U, retry, 3U);
	assert(r.status != GPU_PRIVATE_SUCCESS);
	assert(!gpu_private_range_busy(&owners[0], retry[0], 4096UL));
	retry[0] = 0x80000000UL;
	retry[1] = 0x20000000UL;
	retry[2] = 0x70000000UL;
	r = append(second, 0U, retry, 3U);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	for (unsigned int i = 0U; i < 3U; i++)
		assert(gpu_private_range_busy(&owners[0], retry[i], 4096UL));
	assert(!gpu_private_range_busy(&owners[0], 0x10000000UL, 4096UL));
	gpu_private_bo_destroy(&owners[0], second, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	for (unsigned int i = 0U; i < 3U; i++)
		assert(!gpu_private_range_busy(&owners[0], retry[i], 4096UL));

	/* Bounds may remain conservative during bounded prefix retirement. */
	while (count != 0U) {
		unsigned int old = count;

		gpu_private_bo_destroy(&owners[0], bo, &r);
		count -= count < 512U ? count : 512U;
		assert(r.status == (count != 0U ? GPU_PRIVATE_INCOMPLETE : GPU_PRIVATE_SUCCESS));
		assert(!gpu_private_range_busy(&owners[0], expected[old - 1U], 4096UL));
		if (count != 0U)
			check(expected[count - 1U], 4096UL);
	}
	/* Reusing backing storage must reset its old bounds and ownership. */
	second = create(1U);
	retry[0] = 0x10000000UL;
	r = append(second, 0U, retry, 1U);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	assert(gpu_private_range_busy(&owners[0], retry[0] + 4095UL, 1UL));
	assert(!gpu_private_range_busy(&owners[0], 0x40000000UL, 4096UL));
	gpu_private_bo_destroy(&owners[0], second, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	assert(!gpu_private_range_busy(&owners[0], retry[0], 4096UL));
	/* An append may begin inside a block and continue into the next one. */
	second = create(600U);
	for (unsigned int i = 0U; i < 300U; i++)
		pages[i] = 0x90000000UL + i * 4096UL;
	r = append(second, 0U, pages, 300U);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	for (unsigned int i = 0U; i < 300U; i++)
		pages[i] = 0x10000000UL + i * 4096UL;
	r = append(second, 300U, pages, 300U);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	for (unsigned int i = 0U; i < 300U; i++) {
		assert(gpu_private_range_busy(&owners[0], pages[i], 4096UL));
		assert(gpu_private_range_busy(&owners[0], 0x90000000UL + i * 4096UL, 4096UL));
	}
	gpu_private_bo_destroy(&owners[0], second, &r);
	assert(r.status == GPU_PRIVATE_INCOMPLETE);
	assert(!gpu_private_range_busy(&owners[0], 0x10000000UL, 4096UL));
	assert(gpu_private_range_busy(&owners[0], 0x90000000UL, 4096UL));
	gpu_private_bo_destroy(&owners[0], second, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	/* Interleave every block across the full BO span, then permute it.
	 * Every block range overlaps most misses: an exact index must still
	 * match the page oracle during append and tail retirement.
	 */
	bo = create(32768U);
	count = 0U;
	for (unsigned int i = 0U; i < 32768U; i++)
		expected[i] = 0x40000000UL + i * 8192UL;
	for (unsigned int i = 32768U; i > 1U; i--) {
		unsigned int j;
		unsigned long swap;

		rng = rng * 6364136223846793005UL + 1UL;
		j = (unsigned int)((rng >> 32U) % i);
		swap = expected[i - 1U];
		expected[i - 1U] = expected[j];
		expected[j] = swap;
	}
	while (count != 32768U) {
		for (unsigned int i = 0U; i < 512U; i++)
			pages[i] = expected[count + i];
		r = append(bo, count, pages, 512U);
		assert(r.status == GPU_PRIVATE_SUCCESS);
		count += 512U;
		check(expected[count - 1U], 4096UL);
		check(expected[count - 1U] + 4096UL, 4096UL);
	}
	for (unsigned int i = 0U; i < 2000U; i++) {
		rng = rng * 6364136223846793005UL + 1UL;
		check(0x40000000UL + rng % (32768UL * 8192UL),
			(rng >> 32U) % 16385UL);
	}
	while (count != 0U) {
		unsigned int old = count;

		gpu_private_bo_destroy(&owners[0], bo, &r);
		count -= 512U;
		assert(r.status == (count ? GPU_PRIVATE_INCOMPLETE : GPU_PRIVATE_SUCCESS));
		for (unsigned int i = count; i < old; i++)
			assert(!gpu_private_range_busy(&owners[0], expected[i], 4096UL));
		if (count)
			check(expected[count - 1U], 4096UL);
	}
	puts("GPU_IPA_BOUNDS=PASS independent-oracle/failed-append/partial-release/reuse/permuted-fragmentation MODEL_ONLY");
	return 0;
}
