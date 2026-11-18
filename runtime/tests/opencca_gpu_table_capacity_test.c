/* SPDX-License-Identifier: BSD-3-Clause */
/* Reuse the real-core mapping fixture and its independent PTE-tree audit. */
#define main table_reclaim_existing_main
#include "opencca_gpu_table_reclaim_test.c"
#undef main

int main(int argc, char **argv)
{
	unsigned int scenario = argc == 2 ? (unsigned int)strtoul(argv[1], NULL, 0) : 99U;
	unsigned long ctx[4], bo[4];

	assert(scenario < 2U);
	if (scenario == 0U) {
		/* Retain all four mappings simultaneously; pruning empty tables
		 * cannot make this workload fit in the old 448-table pool.
		 */
		for (unsigned int i = 0U; i < 4U; i++) {
			ctx[i] = make_context(i);
			bo[i] = make_bo(i, 76800U);
			change(i, ctx[i], bo[i], 0x100000UL, 76800UL);
		}
		assert(allocated() > 512U);
		for (unsigned int i = 0U; i < 4U; i++)
			change(i, ctx[i], 0UL, 0x100000UL, 76800UL);
		assert(allocated() == 4U);
	} else {
		/* A maximum-sized mapping starting one page before a 512 GiB
		 * boundary crosses all intermediate levels at their worst offset.
		 */
		unsigned long va = (1UL << 39U) - GPU_PRIVATE_PAGE_SIZE;
		struct gpu_private_result r;

		ctx[0] = make_context(0U);
		bo[0] = make_bo(0U, GPU_PRIVATE_BO_BLOCKS * ENTRIES);
		r = begin(0U, ctx[0], bo[0], va, GPU_PRIVATE_BO_BLOCKS * ENTRIES);
		while (r.status == GPU_PRIVATE_INCOMPLETE && r.value[3] == GPU_PRIVATE_MAP_RESERVE)
			gpu_private_map_step(&ops, &clients[0], r.value[0], r.value[2], &r);
		assert(r.status == GPU_PRIVATE_INCOMPLETE && r.value[3] == GPU_PRIVATE_MAP_APPLY);
		assert(map_transactions[0].reservations == 261U);
		r = finish(0U, r);
		assert(r.status == GPU_PRIVATE_SUCCESS);
		audit();
		change(0U, ctx[0], 0UL, va, GPU_PRIVATE_BO_BLOCKS * ENTRIES);
		assert(allocated() == 1U);
	}
	printf("GPU_TABLE_CAPACITY=PASS scenario=%u pool=%u MODEL_ONLY\n", scenario, GPU_PRIVATE_TABLES);
	return 0;
}
