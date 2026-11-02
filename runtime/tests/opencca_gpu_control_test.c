/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <limits.h>
#include <opencca_gpu_private.h>
#include <stdio.h>
#include <string.h>

#define PAGE 4096UL
#define IPA_BASE 0x400000UL
#define PA_BASE 0x60000000UL
#define TEST_PAGES 513U

static unsigned char service, stranger, client;
static unsigned char data[TEST_PAGES][PAGE];
static bool cpu_visible[TEST_PAGES];
static unsigned int hides, restores, clears;
static unsigned int fail_hide = UINT_MAX, fail_restore = UINT_MAX, fail_clear = UINT_MAX;

static unsigned int page_index(unsigned long pa)
{
	assert(pa >= PA_BASE && (pa - PA_BASE) % PAGE == 0UL);
	unsigned long index = (pa - PA_BASE) / PAGE;

	assert(index < TEST_PAGES);
	return (unsigned int)index;
}

static bool source(const void *owner, unsigned long ipa, unsigned long *pa)
{
	if (owner != &service || ipa < IPA_BASE || (ipa - IPA_BASE) % PAGE != 0UL ||
	    (ipa - IPA_BASE) / PAGE >= TEST_PAGES || gpu_private_range_busy(owner, ipa, PAGE))
		return false;
	unsigned int index = (unsigned int)((ipa - IPA_BASE) / PAGE);

	if (!cpu_visible[index])
		return false;
	*pa = PA_BASE + index * PAGE;
	return true;
}

static bool hide(const void *owner, unsigned long ipa, unsigned long pa)
{
	unsigned int index = page_index(pa);

	assert(owner == &service && ipa == IPA_BASE + index * PAGE);
	assert(cpu_visible[index] && gpu_private_range_busy(owner, ipa, PAGE));
	if (index == fail_hide)
		return false;
	cpu_visible[index] = false;
	hides++;
	return true;
}

static bool restore(const void *owner, unsigned long ipa, unsigned long pa)
{
	unsigned int index = page_index(pa);

	assert(owner == &service && ipa == IPA_BASE + index * PAGE);
	assert(!cpu_visible[index] && gpu_private_range_busy(owner, ipa, PAGE));
	for (unsigned int j = 0U; j < PAGE; j++)
		assert(data[index][j] == 0U); /* Scrub precedes CPU restoration. */
	if (index == fail_restore)
		return false;
	cpu_visible[index] = true;
	restores++;
	return true;
}

static bool clear(unsigned long pa)
{
	unsigned int index = page_index(pa);

	assert(!cpu_visible[index]);
	if (index == fail_clear)
		return false;
	memset(data[index], 0, PAGE);
	clears++;
	return true;
}

static void clean(const void *memory, size_t bytes)
{
	assert(memory != NULL && bytes != 0U);
}

static const struct gpu_private_ops ops = {
	.source_page = source, .clean = clean,
	.hide_page = hide, .restore_page = restore, .clear_page = clear
};

static unsigned long create(unsigned int pages)
{
	struct gpu_private_result result;

	gpu_private_control_create(&service, pages * PAGE, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && result.value[0] != 0UL);
	return result.value[0];
}

static void reset_data(void)
{
	memset(data, 0xcc, sizeof(data));
	for (unsigned int i = 0U; i < TEST_PAGES; i++)
		cpu_visible[i] = true;
	hides = restores = clears = 0U;
	fail_hide = fail_restore = fail_clear = UINT_MAX;
}

static void destroy(unsigned long object)
{
	struct gpu_private_result result;

	do {
		gpu_private_control_destroy(&ops, &service, object, &result);
	} while (result.status == GPU_PRIVATE_INCOMPLETE);
	assert(result.status == GPU_PRIVATE_SUCCESS);
}

int main(void)
{
	struct gpu_private_result result;
	unsigned long ipas[GPU_PRIVATE_BATCH], object, normal, pa;
	unsigned int pages = 0U;

	reset_data();
	for (unsigned int i = 0U; i < GPU_PRIVATE_BATCH; i++)
		ipas[i] = IPA_BASE + i * PAGE;
	gpu_private_control_create(NULL, PAGE, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_control_create(&service, PAGE - 1UL, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_control_create(&service, (GPU_PRIVATE_CONTROL_PAGES + 1UL) * PAGE, &result);
	assert(result.status == GPU_PRIVATE_FULL);
	gpu_private_bo_create(&client, &service, PAGE, GPU_PRIVATE_READ, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	normal = result.value[0];
	assert(!gpu_private_control_acquire(&ops, &client, normal, &pages));
	gpu_private_control_append(&ops, &client, normal, 0UL, ipas, 1U, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_bo_destroy(&client, normal, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS);
	object = create(TEST_PAGES);
	gpu_private_bo_append(&ops, &service, object, 0UL, ipas, 1U, &result);
	assert(result.status == GPU_PRIVATE_INPUT && hides == 0U);
	gpu_private_bo_destroy(&service, object, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	gpu_private_control_append(&ops, &stranger, object, 0UL, ipas, 1U, &result);
	assert(result.status == GPU_PRIVATE_INPUT);
	assert(!gpu_private_control_acquire(&ops, &service, object, &pages));
	gpu_private_control_append(&ops, &service, object, 0UL, ipas, GPU_PRIVATE_BATCH, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && hides == GPU_PRIVATE_BATCH);
	assert(!gpu_private_control_acquire(&ops, &service, object, &pages));
	gpu_private_control_append(&ops, &service, object, 0UL, ipas, 1U, &result);
	assert(result.status == GPU_PRIVATE_INPUT); /* Prefix replay. */
	unsigned long last = IPA_BASE + GPU_PRIVATE_BATCH * PAGE;

	gpu_private_control_append(&ops, &service, object, GPU_PRIVATE_BATCH * PAGE, &last, 1U, &result);
	assert(result.status == GPU_PRIVATE_SUCCESS && hides == TEST_PAGES);
	assert(!gpu_private_control_acquire(&ops, &stranger, object, &pages));
	assert(gpu_private_control_acquire(&ops, &service, object, &pages) && pages == TEST_PAGES);
	assert(!gpu_private_control_acquire(&ops, &service, object, &pages));
	assert(gpu_private_control_page(&service, object, TEST_PAGES - 1U, &pa));
	assert(pa == PA_BASE + (TEST_PAGES - 1UL) * PAGE);
	assert(!gpu_private_control_page(&stranger, object, 0U, &pa));
	assert(!gpu_private_control_page(&service, object, TEST_PAGES, &pa));
	gpu_private_control_destroy(&ops, &service, object, &result);
	assert(result.status == GPU_PRIVATE_STATE && restores == 0U);
	memset(data, 0x5a, sizeof(data)); /* Simulated GPU private state. */
	gpu_private_device_revoked(&ops);
	assert(restores == 0U && !cpu_visible[0]);
	assert(gpu_private_control_acquire(&ops, &service, object, &pages));
	for (unsigned int i = 0U; i < sizeof(data); i++)
		assert(((unsigned char *)data)[i] == 0U);
	gpu_private_control_release(&service, object);
	memset(data, 0x5a, sizeof(data));
	gpu_private_control_destroy(&ops, &service, object, &result);
	assert(result.status == GPU_PRIVATE_INCOMPLETE && result.value[0] == 1UL);
	assert(restores == GPU_PRIVATE_BATCH && !cpu_visible[0] && cpu_visible[1]);
	assert(gpu_private_range_busy(&service, IPA_BASE, PAGE));
	destroy(object);
	assert(restores == TEST_PAGES && !gpu_private_owner_busy(&service));
	assert(!gpu_private_control_page(&service, object, 0U, &pa));
	for (unsigned int fault = 0U; fault < 2U; fault++) {
		reset_data();
		object = create(7U);
		fail_hide = fault == 0U ? 3U : UINT_MAX;
		fail_clear = fault == 1U ? 3U : UINT_MAX;
		gpu_private_control_append(&ops, &service, object, 0UL, ipas, 7U, &result);
		assert(result.status == GPU_PRIVATE_STATE && hides == (fault == 0U ? 3U : 4U));
		assert(gpu_private_range_busy(&service, IPA_BASE + 6UL * PAGE, PAGE));
		assert(!gpu_private_control_acquire(&ops, &service, object, &pages));
		gpu_private_control_append(&ops, &service, object, 0UL, ipas, 7U, &result);
		assert(result.status != GPU_PRIVATE_SUCCESS); /* No in-place retry. */
		fail_clear = UINT_MAX;
		fail_restore = 2U;
		gpu_private_control_destroy(&ops, &service, object, &result);
		assert(result.status == GPU_PRIVATE_STATE);
		assert(gpu_private_owner_busy(&service) && !cpu_visible[0] && !cpu_visible[2]);
		fail_restore = UINT_MAX;
		destroy(object);
		assert(!gpu_private_owner_busy(&service));
		for (unsigned int i = 0U; i < 7U; i++)
			assert(cpu_visible[i]);
	}
	unsigned long quota[GPU_PRIVATE_CONTROL_OBJECTS];

	for (unsigned int i = 0U; i < GPU_PRIVATE_CONTROL_OBJECTS; i++)
		quota[i] = create(1U);
	gpu_private_control_create(&service, PAGE, &result);
	assert(result.status == GPU_PRIVATE_FULL);
	for (unsigned int i = 0U; i < GPU_PRIVATE_CONTROL_OBJECTS; i++)
		destroy(quota[i]);
	object = create(GPU_PRIVATE_CONTROL_PAGES);
	gpu_private_control_create(&service, PAGE, &result);
	assert(result.status == GPU_PRIVATE_FULL);
	destroy(object);
	puts("GPU_CONTROL_MEMORY=PASS opaque distinct type, donor binding, 513-page donation, CPU revocation before clear, firmware hold, reset/rebind scrub, bounded restore, partial hide/clear/restore retention, replay and quota rejection");
	return 0;
}
