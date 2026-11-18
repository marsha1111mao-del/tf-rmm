/* SPDX-License-Identifier: BSD-3-Clause */
#include <stdio.h>
#include <opencca_gpu_private.c>

static int owner, other, service;
static unsigned int callbacks;
static bool source(const void *who, unsigned long ipa, unsigned long *pa)
{
	assert(who == &owner);
	*pa = ipa + 0x10000000UL;
	return true;
}
static bool transfer(const void *who, unsigned long ipa, unsigned long pa)
{
	assert(who == &owner && pa == ipa + 0x10000000UL);
	callbacks++;
	return true;
}
static bool sync_page(unsigned long pa)
{
	assert(pa >= 0x10000000UL);
	callbacks++;
	return true;
}
static bool barrier(void) { callbacks++; return true; }
static const struct gpu_private_ops ops = {
	.source_page = source, .hide_page = transfer,
	.restore_page_uncached = transfer, .restore_page = transfer,
	.sync_page_for_device = sync_page, .clear_page = sync_page,
	.cache_barrier = barrier,
};
static void query(unsigned long handle, unsigned long expected)
{
	struct private_bo saved = *bo_lookup(&owner, handle);
	struct gpu_private_result r;
	unsigned int before = callbacks;

	gpu_private_bo_idle(&owner, handle, &r);
	assert(r.status == expected);
	assert(r.value[0] == (expected == GPU_PRIVATE_SUCCESS ? 8192UL : 0UL));
	assert((r.value[1] | r.value[2] | r.value[3]) == 0UL);
	assert(memcmp(&saved, bo_lookup(&owner, handle), sizeof(saved)) == 0);
	assert(before == callbacks);
}
int main(void)
{
	struct gpu_private_result r;
	unsigned long pages[2] = { 0x1000UL, 0x2000UL }, handle;
	struct private_bo *bo;

	gpu_private_bo_create(&owner, &service, 8192UL, 3UL, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	handle = r.value[0]; bo = bo_lookup(&owner, handle);
	query(handle, GPU_PRIVATE_STATE);
	gpu_private_bo_append(&ops, &owner, handle, 0UL, pages, 2U, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	query(handle, GPU_PRIVATE_STATE);
	gpu_private_bo_uncached(&ops, &owner, handle, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	query(handle, GPU_PRIVATE_SUCCESS);
#define REJECT(field, value) do { \
	__typeof__(bo->field) saved = bo->field; bo->field = (value); \
	query(handle, GPU_PRIVATE_STATE); bo->field = saved; \
} while (0)
	REJECT(mapped, 1U); REJECT(pending, 1U); REJECT(control_gpu_refs, 1U);
	REJECT(cache_context, 1UL); REJECT(closing, true); REJECT(uncached, false);
	REJECT(registered, 1U); REJECT(hidden, 1U); REJECT(hidden, NC_PENDING | 1U);
	bo->control = true; query(handle, GPU_PRIVATE_INPUT); bo->control = false;
	bo->resident = true; query(handle, GPU_PRIVATE_INPUT); bo->resident = false;
	gpu_private_bo_idle(&other, handle, &r); assert(r.status == GPU_PRIVATE_INPUT);
	gpu_private_bo_idle(NULL, handle, &r); assert(r.status == GPU_PRIVATE_INPUT);
	/* The query does not remove registration or allow a duplicate page. */
	assert(gpu_private_range_busy(&owner, pages[0], 4096UL));
	query(handle, GPU_PRIVATE_SUCCESS);
	gpu_private_bo_release(&ops, &owner, handle, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	gpu_private_bo_idle(&owner, handle, &r); assert(r.status == GPU_PRIVATE_INPUT);
	gpu_private_bo_create(&owner, &service, 8192UL, 3UL, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS && r.value[0] != handle);
	gpu_private_bo_idle(&owner, handle, &r); assert(r.status == GPU_PRIVATE_INPUT);
	puts("GPU_BO_IDLE=PASS owner, NC, mapping, pending, execution holds, replay, no mutation");
	return 0;
}
