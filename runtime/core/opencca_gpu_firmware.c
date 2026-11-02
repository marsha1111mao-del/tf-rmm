/* SPDX-License-Identifier: BSD-3-Clause */
#include <debug.h>
#include <assert.h>
#include <opencca_gpu_firmware.h>
#include <string.h>

#define FW_MAGIC UINT32_C(0xc3f13a6e)
#define FW_READ 1U
#define FW_WRITE 2U
#define FW_EXEC 4U
#define FW_PROTECTED 32U
#define FW_SHARED (1U << 30U)
#define FW_ALLOWED (31U | FW_PROTECTED | FW_SHARED | (1U << 31U))
#define FW_SHARED_VA UINT32_C(0x04000000)
#define FW_SHARED_END UINT32_C(0x08000000)
#define PTE_ADDRESS UINT64_C(0x000000fffffff000)
#define PTE_PAGE UINT64_C(3)
#define PTE_AF (UINT64_C(1) << 10U)
#define PTE_NG (UINT64_C(1) << 11U)
#define PTE_USER (UINT64_C(1) << 6U)
#define PTE_RO (UINT64_C(1) << 7U)
#define PTE_XN (UINT64_C(3) << 53U)
#define GROUP_PREFIX UINT64_C(0xcca5000000000000)
#define TASK_PREFIX UINT64_C(0xcca6000000000000)

static const unsigned char approved_digest[32] = {
	0x43, 0xc3, 0xc3, 0x6b, 0x91, 0x4c, 0x03, 0x1d,
	0x88, 0xae, 0x15, 0x2f, 0xd8, 0x90, 0x19, 0xd8,
	0xf9, 0x9a, 0xd4, 0x1d, 0x98, 0x79, 0xfb, 0x5a,
	0xb7, 0x49, 0x6e, 0xd1, 0x3f, 0x7b, 0x37, 0x8b
};
static unsigned char image[GPU_FIRMWARE_IMAGE_SIZE]
	__attribute__((aligned(4096)));
static struct gpu_firmware_section sections[GPU_FIRMWARE_SECTIONS];
static const void *image_service;
static enum gpu_firmware_state state;
static unsigned long received;
static unsigned int section_count;
static unsigned long memory_size;
static unsigned char runtime_pages[GPU_FIRMWARE_RUNTIME_PAGES][4096]
	__attribute__((aligned(4096)));
static uint64_t runtime_tables[GPU_FIRMWARE_TABLES][512]
	__attribute__((aligned(4096)));
static unsigned int table_count;
static unsigned int section_page[GPU_FIRMWARE_SECTIONS];
static unsigned long control_object;
static unsigned int control_pages;

struct fw_group {
	const void *owner;
	unsigned long handle, context;
	unsigned int first, pages, cleared, streams;
	unsigned int ring_first, ring_pages, mapped_streams;
	bool rings_configured, sync_mapped, suspended;
	uint8_t domain_batches;
	uint32_t active_queues;
	unsigned int tasks;
	unsigned long prepared_task;
	unsigned int hardware_csg;
	unsigned int hardware_as;
	struct gpu_firmware_queue_config queues[GPU_FIRMWARE_STREAMS];
	enum gpu_firmware_group_state state;
};
static struct fw_group groups[GPU_FIRMWARE_LOGICAL_GROUPS];
static unsigned short control_user[GPU_PRIVATE_CONTROL_PAGES];
/* Never reset this generation: an old handle must not designate a new group
 * after device reset or a fresh firmware service instance.
 */
static unsigned long group_generation;

/* One unacknowledged event per task. Never accepts a service-supplied MCU
 * pointer. Generation survives reset, like task/group handles.
 */
struct fw_heap_event {
	unsigned long id, address, object, iova;
	uint32_t vt_start;
	uint8_t queue, ack, phase;
};
static unsigned long heap_generation;
#define HEAP_OBSERVED 1U
#define HEAP_MAPPING 2U
#define HEAP_PUBLISHED 3U
#define HEAP_ACCEPTED 4U

struct fw_task {
	const void *owner;
	unsigned long handle;
	bool preparing;
	bool ready;
	bool start_attempted, started;
	bool stop_attempted, quiesced;
	bool cpu_returned;
	bool status_pending, completed, preserve;
	bool launch_pending;
	bool delegated;
	/* Internal anchors are never accepted by a public task lookup. */
	bool internal, live;
	unsigned int retire_cursor;
	unsigned int count;
	uint32_t queue_mask;
	uint32_t observed_members;
	uint32_t published_members;
	uint8_t queue_count[GPU_FIRMWARE_STREAMS];
	struct gpu_firmware_task_resources resources;
	struct gpu_firmware_task_command extra[GPU_PRIVATE_TASK_BATCH - 1U];
	struct fw_heap_event heap;
};
static struct fw_task tasks[GPU_FIRMWARE_TASKS];
/* Survives device reset; cancelled/reset tokens never designate new work. */
static unsigned long task_generation;
static bool group_domain(const struct fw_group *group);
static void task_finish(const struct gpu_firmware_ops *, const struct gpu_private_ops *,
		const void *, const void *, unsigned long, bool, struct gpu_private_result *);
static bool yield_idle_domains(const struct gpu_firmware_ops *, const struct gpu_private_ops *,
		const struct fw_group *);
static void task_start(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long context, unsigned long handle,
		unsigned long token, bool accept_resume, bool internal,
		struct gpu_private_result *result);
static bool task_idle_snapshot(const struct gpu_firmware_ops *, const struct gpu_private_ops *,
		const struct fw_group *, const struct fw_task *, bool *);
static unsigned long hardware_groups[GPU_FIRMWARE_GROUPS];
/* Diagnostic counts only; never consumed by authorization or completion. */
static unsigned long resume_fast, resume_fallback;
static unsigned long suspend_finish_fast, suspend_finish_fallback;

struct fw_iface {
	uint32_t input, output;
};

struct fw_slot {
	struct fw_iface group;
	struct fw_iface stream[GPU_FIRMWARE_STREAMS];
};

static struct {
	uint32_t version, features, groups, instr_features;
	uint32_t streams, stream_features, suspend_size, protm_suspend_size;
	unsigned int section;
	struct fw_iface global;
	struct fw_slot slots[GPU_FIRMWARE_GROUPS];
} interfaces;

/* Boot-time validation scratch is static: the maximum 2049 intervals must
 * not exhaust an REC's stack. The policy lock serializes discovery/reset.
 */
/* Discovery ends before BOOTED, and groups can only be created CONFIGURED.
 * Reuse boot-only scratch for canonical CPU-only queue history afterwards.
 * No arena/GPU word supplies this history. The policy lock serializes both
 * phases; successful discovery and device reset erase the complete storage.
 */
static union {
	struct {
		uint32_t begin, end;
	} ranges[3U + 2U * GPU_FIRMWARE_GROUPS * (1U + GPU_FIRMWARE_STREAMS)];
	struct {
		uint64_t history[GPU_FIRMWARE_LOGICAL_GROUPS][GPU_FIRMWARE_STREAMS];
		/* Frozen while a CSG runs; later batches advance history only. */
		uint64_t origin[GPU_FIRMWARE_LOGICAL_GROUPS][GPU_FIRMWARE_STREAMS];
	};
} fw_storage;
static unsigned int iface_range_count;

_Static_assert(sizeof(fw_storage.history) + sizeof(fw_storage.origin) <= sizeof(fw_storage.ranges),
	"Queue history must fit in existing discovery scratch");

#define GLB_CONFIG_MASK ((1U << 1U) | (1U << 2U) | (1U << 3U))
#define FW_GLOBAL_INPUT_SIZE 0x88U
#define FW_GLOBAL_OUTPUT_SIZE 0x1cU
#define FW_GROUP_INPUT_SIZE 0x58U
#define FW_GROUP_OUTPUT_SIZE 0x20U
#define FW_STREAM_INPUT_SIZE 0x60U
#define FW_STREAM_OUTPUT_SIZE 0xd8U
#define FW_SUSPEND_LIMIT (16U * 1024U * 1024U)

_Static_assert(sizeof(runtime_tables[0]) == 4096U, "MCU hardware table size");
_Static_assert(GPU_FIRMWARE_CONTROL_VA >= FW_SHARED_VA &&
	(uint64_t)GPU_FIRMWARE_CONTROL_VA + GPU_PRIVATE_CONTROL_PAGES * 4096ULL <= FW_SHARED_END,
	"MCU runtime backing must fit in the native shared address window");
_Static_assert(GPU_FIRMWARE_LOGICAL_GROUPS <= UINT16_MAX, "Control-page owner tag size");
_Static_assert(GPU_PRIVATE_TASK_BATCH * GPU_FIRMWARE_TASK_INSTRUCTIONS * 8U <= 4096U,
	"One batch's wrappers fit in the first protected ring page");
_Static_assert(GPU_PRIVATE_TASK_BATCH <= UINT8_MAX, "Per-token queue counter size");

/* Only validated, private interface offsets reach these task paths:
 * runtime_pages is page aligned and iface_range() requires cache-line starts.
 * Preserve full snapshots and callback ordering; expose only the already
 * checked word alignment so freestanding copies need not load every byte.
 */
_Static_assert(GPU_FIRMWARE_CACHE_LINE % _Alignof(uint32_t) == 0U,
	"Validated firmware interfaces must be word aligned");

static inline __attribute__((always_inline)) void interface_words(
		uint32_t *destination, const unsigned char *source, size_t bytes)
{
	const unsigned char *aligned = __builtin_assume_aligned(source, _Alignof(uint32_t));

	/* Every call uses a fixed whole-word interface size (or one ACK).
	 * A word-sized builtin keeps larger copies out of the bytewise libc path.
	 */
	for (size_t i = 0U; i < bytes / sizeof(*destination); i++)
		__builtin_memcpy(destination + i, aligned + i * sizeof(*destination),
			sizeof(*destination));
}

/* Fresh per-call fields; keep the complete output cache invalidation.
 * Heap handling still reads its separate, complete output snapshot.
 */
struct fw_stream_status {
	uint32_t ack;
	uint32_t scoreboards;
	uint32_t blocked_reason;
	uint32_t fault;
	uint32_t fatal;
};

static void stream_status(const struct gpu_firmware_ops *ops,
		const unsigned char *output, struct fw_stream_status *status)
{
	ops->invalidate(output, FW_STREAM_OUTPUT_SIZE);
	output = __builtin_assume_aligned(output, _Alignof(uint32_t));
	__builtin_memcpy(&status->ack, output, sizeof(status->ack));
	__builtin_memcpy(&status->scoreboards, output + 23U * 4U, sizeof(status->scoreboards));
	__builtin_memcpy(&status->blocked_reason, output + 24U * 4U, sizeof(status->blocked_reason));
	__builtin_memcpy(&status->fault, output + 32U * 4U, sizeof(status->fault));
	__builtin_memcpy(&status->fatal, output + 33U * 4U, sizeof(status->fatal));
}

static uint32_t le32(unsigned long offset)
{
	return (uint32_t)image[offset] | ((uint32_t)image[offset + 1UL] << 8U) |
		((uint32_t)image[offset + 2UL] << 16U) |
		((uint32_t)image[offset + 3UL] << 24U);
}

static void init_result(struct gpu_private_result *result)
{
	memset(result, 0, sizeof(*result));
	result->status = GPU_PRIVATE_INPUT;
}

static bool authenticated(const void *service)
{
	return service != NULL && service == image_service;
}

void gpu_firmware_device_revoked(void)
{
	if (resume_fast != 0UL || resume_fallback != 0UL)
		INFO("GPU_RESUME_ACCEPT fast=%lu fallback=%lu\n", resume_fast, resume_fallback);
	resume_fast = resume_fallback = 0UL;
	if (suspend_finish_fast != 0UL || suspend_finish_fallback != 0UL)
		INFO("GPU_SUSPEND_OBSERVE fast=%lu fallback=%lu\n", suspend_finish_fast, suspend_finish_fallback);
	suspend_finish_fast = suspend_finish_fallback = 0UL;
	memset(image, 0, sizeof(image));
	memset(sections, 0, sizeof(sections));
	image_service = NULL;
	state = GPU_FIRMWARE_EMPTY;
	received = 0UL;
	section_count = 0U;
	memory_size = 0UL;
	memset(runtime_pages, 0, sizeof(runtime_pages));
	memset(runtime_tables, 0, sizeof(runtime_tables));
	memset(section_page, 0, sizeof(section_page));
	table_count = 0U;
	memset(&interfaces, 0, sizeof(interfaces));
	memset(&fw_storage, 0, sizeof(fw_storage));
	iface_range_count = 0U;
	control_object = 0UL;
	control_pages = 0U;
	memset(groups, 0, sizeof(groups));
	memset(tasks, 0, sizeof(tasks));
	memset(hardware_groups, 0, sizeof(hardware_groups));
	memset(control_user, 0, sizeof(control_user));
}

void gpu_firmware_begin(const void *service, unsigned long size,
		struct gpu_private_result *result)
{
	init_result(result);
	if (service == NULL || size != sizeof(image))
		return;
	result->status = GPU_PRIVATE_STATE;
	if ((state != GPU_FIRMWARE_EMPTY && state != GPU_FIRMWARE_RECEIVING) ||
	    (image_service != NULL && image_service != service))
		return;
	gpu_firmware_device_revoked();
	image_service = service;
	state = GPU_FIRMWARE_RECEIVING;
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = sizeof(image);
}

void gpu_firmware_write(const void *service, unsigned long offset,
		const void *snapshot, size_t bytes, struct gpu_private_result *result)
{
	init_result(result);
	if (!authenticated(service) || snapshot == NULL || bytes == 0U ||
	    bytes > GPU_PRIVATE_PAGE_SIZE || offset >= sizeof(image) ||
	    bytes > sizeof(image) - offset)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (state != GPU_FIRMWARE_RECEIVING || offset != received)
		return;
	memcpy(image + offset, snapshot, bytes);
	received += bytes;
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = received;
}

/* Parse only the authenticated RMM-private snapshot. Retain the native binary
 * format; never accept service-provided section descriptors or GPU addresses.
 */
static bool parse_sections(void)
{
	unsigned long end, offset = 20UL;
	bool shared = false, executable = false, vectors = false;

	if (le32(0UL) != FW_MAGIC || image[5] != 0U || image[6] != 0U ||
	    image[7] != 0U || le32(12UL) != 0U)
		return false;
	end = le32(16UL);
	if (end < offset || end > sizeof(image) || (end & 3UL) != 0UL)
		return false;
	while (offset < end) {
		uint32_t header = le32(offset);
		unsigned int type = header & 255U;
		unsigned long size = (header >> 8U) & 255U;

		if (size < 4UL || (size & 3UL) != 0UL || size > end - offset)
			return false;
		if (type == 0U) {
			struct gpu_firmware_section section;
			uint32_t va_end, data_end;

			if (size < 24UL || section_count == GPU_FIRMWARE_SECTIONS)
				return false;
			section.flags = le32(offset + 4UL);
			section.va = le32(offset + 8UL);
			va_end = le32(offset + 12UL);
			section.data_offset = le32(offset + 16UL);
			data_end = le32(offset + 20UL);
			if ((section.flags & ~FW_ALLOWED) != 0U || va_end <= section.va ||
			    ((section.va | va_end) & 4095U) != 0U ||
			    data_end < section.data_offset || data_end > sizeof(image))
				return false;
			section.size = va_end - section.va;
			section.data_size = data_end - section.data_offset;
			if (section.data_size > section.size ||
			    (section.data_size != 0U && section.data_offset < end))
				return false;
			/* Protected-mode sections are excluded just as in native Panthor.
			 * They must not turn into ordinary MCU mappings.
			 */
			if ((section.flags & FW_PROTECTED) == 0U) {
				if (section.va < GPU_FIRMWARE_CONTROL_VA +
					GPU_PRIVATE_CONTROL_PAGES * 4096UL &&
				    va_end > GPU_FIRMWARE_CONTROL_VA)
					return false;
				if ((section.flags & FW_READ) == 0U ||
				    (section.flags & (FW_WRITE | FW_EXEC)) == (FW_WRITE | FW_EXEC))
					return false;
				for (unsigned int i = 0U; i < section_count; i++)
					if (section.va < sections[i].va + sections[i].size &&
					    sections[i].va < va_end)
						return false;
				if ((section.flags & FW_SHARED) != 0U) {
					if (shared || section.va != FW_SHARED_VA ||
					    va_end > FW_SHARED_END || (section.flags & FW_EXEC) != 0U)
						return false;
					shared = true;
				} else if (section.va < FW_SHARED_END && va_end > FW_SHARED_VA) {
					return false;
				}
				if (section.va == 0U && section.data_size >= 8U)
					vectors = true;
				executable |= (section.flags & FW_EXEC) != 0U;
				memory_size += section.size;
				sections[section_count++] = section;
			}
		} else if ((type > 4U) && (header & (1U << 31U)) == 0U) {
			return false;
		}
		offset += size;
	}
	return shared && executable && vectors;
}

void gpu_firmware_seal(const struct gpu_firmware_ops *ops, const void *service,
		struct gpu_private_result *result)
{
	unsigned char digest[32];

	init_result(result);
	if (!authenticated(service))
		return;
	result->status = GPU_PRIVATE_STATE;
	if (state != GPU_FIRMWARE_RECEIVING)
		return;
	result->status = GPU_PRIVATE_INCOMPLETE;
	if (received != sizeof(image))
		return;
	/* Neither digest nor size is supplied by Proxy. Hash the very bytes the
	 * trusted loader will consume; the source buffer may change afterward.
	 */
	if (ops == NULL || ops->digest == NULL ||
	    !ops->digest(image, sizeof(image), digest) ||
	    memcmp(digest, approved_digest, sizeof(digest)) != 0 || !parse_sections()) {
		gpu_firmware_device_revoked();
		result->status = GPU_PRIVATE_INPUT;
		return;
	}
	state = GPU_FIRMWARE_VERIFIED;
	gpu_firmware_inspect(service, result);
}

void gpu_firmware_inspect(const void *service, struct gpu_private_result *result)
{
	init_result(result);
	if (service == NULL || (image_service != NULL && !authenticated(service)))
		return;
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = state;
	result->value[1] = received;
	result->value[2] = section_count;
	result->value[3] = memory_size;
}

bool gpu_firmware_section(const void *service, unsigned int index,
		struct gpu_firmware_section *section, const void **data)
{
	if (!authenticated(service) || state != GPU_FIRMWARE_VERIFIED ||
	    index >= section_count || section == NULL || data == NULL)
		return false;
	*section = sections[index];
	*data = image + section->data_offset;
	return true;
}

static bool address_valid(unsigned long address)
{
	return address != 0UL && (address & ~PTE_ADDRESS) == 0UL;
}

static unsigned int leaf_table(const struct gpu_firmware_ops *ops, uint32_t va)
{
	unsigned int table = 0U;

	for (unsigned int level = 0U; level < 3U; level++) {
		unsigned int index = (unsigned int)(((uint64_t)va >> (39U - level * 9U)) & 511U);
		uint64_t pte = runtime_tables[table][index];
		unsigned int child = GPU_FIRMWARE_TABLES;

		if (pte == 0U) {
			if (table_count == GPU_FIRMWARE_TABLES)
				return GPU_FIRMWARE_TABLES;
			child = table_count++;
			runtime_tables[table][index] =
				ops->address(runtime_tables[child]) | PTE_PAGE;
		} else {
			for (unsigned int i = 1U; i < table_count; i++)
				if (pte == (ops->address(runtime_tables[i]) | PTE_PAGE)) {
					child = i;
					break;
				}
		}
		if (child == GPU_FIRMWARE_TABLES)
			return child;
		table = child;
	}
	return table;
}

void gpu_firmware_prepare(const struct gpu_firmware_ops *ops, const void *service,
		struct gpu_private_result *result)
{
	unsigned int used = 0U;

	init_result(result);
	if (!authenticated(service))
		return;
	result->status = GPU_PRIVATE_STATE;
	if (state == GPU_FIRMWARE_PREPARED) {
		gpu_firmware_inspect(service, result);
		return;
	}
	if (state != GPU_FIRMWARE_VERIFIED || ops == NULL ||
	    ops->address == NULL || ops->clean == NULL || memory_size > sizeof(runtime_pages))
		return;
	/* Validate every trusted backing address before building any hardware
	 * descriptor. No allocation or callback is supplied by the service.
	 */
	for (unsigned int i = 0U; i < GPU_FIRMWARE_TABLES; i++) {
		unsigned long pa = ops->address(runtime_tables[i]);

		if (!address_valid(pa))
			return;
		for (unsigned int j = 0U; j < i; j++)
			if (pa == ops->address(runtime_tables[j]))
				return;
	}
	for (unsigned int i = 0U; i < memory_size / 4096UL; i++) {
		unsigned long pa = ops->address(runtime_pages[i]);

		if (!address_valid(pa))
			return;
		for (unsigned int j = 0U; j < i; j++)
			if (pa == ops->address(runtime_pages[j]))
				return;
		for (unsigned int j = 0U; j < GPU_FIRMWARE_TABLES; j++)
			if (pa == ops->address(runtime_tables[j]))
				return;
	}
	memset(runtime_pages, 0, sizeof(runtime_pages));
	memset(runtime_tables, 0, sizeof(runtime_tables));
	table_count = 1U;
	for (unsigned int i = 0U; i < section_count; i++) {
		const struct gpu_firmware_section *section = &sections[i];
		unsigned int pages = section->size / 4096U;

		if (pages > GPU_FIRMWARE_RUNTIME_PAGES - used)
			goto fail;
		section_page[i] = used;
		memcpy((unsigned char *)runtime_pages + used * 4096U,
			image + section->data_offset, section->data_size);
		for (unsigned int j = 0U; j < pages; j++) {
			uint32_t va = section->va + j * 4096U;
			unsigned int table = leaf_table(ops, va);
			uint64_t pte = ops->address(runtime_pages[used + j]) |
				PTE_PAGE | PTE_AF | PTE_NG | PTE_USER;

			if (table == GPU_FIRMWARE_TABLES || runtime_tables[table][(va >> 12U) & 511U] != 0U)
				goto fail;
			if ((section->flags & FW_WRITE) == 0U)
				pte |= PTE_RO;
			if ((section->flags & FW_EXEC) == 0U)
				pte |= PTE_XN;
			/* Match the existing private-root NC/WB attribute indices. */
			if ((section->flags & 24U) == 8U)
				pte |= (UINT64_C(3) << 8U) | (UINT64_C(1) << 2U);
			else
				pte |= UINT64_C(2) << 8U;
			runtime_tables[table][(va >> 12U) & 511U] = pte;
		}
		used += pages;
	}
	ops->clean(runtime_pages, sizeof(runtime_pages));
	ops->clean(runtime_tables, sizeof(runtime_tables));
	state = GPU_FIRMWARE_PREPARED;
	gpu_firmware_inspect(service, result);
	return;
fail:
	/* No root has been exposed to hardware. It is safe to discard preparation
	 * and retain the original authenticated image for a later attempt.
	 */
	memset(runtime_pages, 0, sizeof(runtime_pages));
	memset(runtime_tables, 0, sizeof(runtime_tables));
	table_count = 0U;
}

void gpu_firmware_control_bind(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		unsigned long object, struct gpu_private_result *result)
{
	unsigned int pages, previous_tables, mapped = 0U;
	unsigned long pa;

	init_result(result);
	if (!authenticated(service) || object == 0UL)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (state != GPU_FIRMWARE_PREPARED || ops == NULL ||
	    ops->address == NULL || ops->clean == NULL)
		return;
	if (control_object != 0UL) {
		if (control_object != object)
			return;
		goto success;
	}
	if (!gpu_private_control_acquire(memory_ops, service, object, &pages))
		return;
	previous_tables = table_count;
	if (pages == 0U || pages > GPU_PRIVATE_CONTROL_PAGES)
		goto fail;
	for (unsigned int i = 0U; i < pages; i++)
		if (!gpu_private_control_page(service, object, i, &pa) || !address_valid(pa))
			goto fail;
	for (unsigned int i = 0U; i < pages; i++) {
		uint32_t va = GPU_FIRMWARE_CONTROL_VA + i * 4096U;
		unsigned int table = leaf_table(ops, va);

		if (table == GPU_FIRMWARE_TABLES || runtime_tables[table][(va >> 12U) & 511U] != 0U ||
		    !gpu_private_control_page(service, object, i, &pa))
			goto fail;
		/* Internal MCU data only: RW, XN, NC and inner sharing. Proxy does
		 * not select the VA, attributes, root or any CPU mapping of backing.
		 */
		runtime_tables[table][(va >> 12U) & 511U] = pa |
			PTE_PAGE | PTE_AF | PTE_NG | PTE_USER | PTE_XN | (UINT64_C(2) << 8U);
		mapped++;
	}
	ops->clean(runtime_tables, sizeof(runtime_tables));
	control_object = object;
	control_pages = pages;
success:
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = (unsigned long)control_pages * 4096UL;
	result->value[1] = control_pages;
	return;
fail:
	/* MCU has never seen this root. Undo the bounded pre-boot transaction;
	 * no hardware invalidation or guessed completion is used to drop a hold.
	 */
	for (unsigned int i = 0U; i < mapped; i++) {
		uint32_t va = GPU_FIRMWARE_CONTROL_VA + i * 4096U;
		unsigned int table = leaf_table(ops, va);

		if (table != GPU_FIRMWARE_TABLES)
			runtime_tables[table][(va >> 12U) & 511U] = 0U;
	}
	for (unsigned int i = 0U; i < previous_tables; i++)
		for (unsigned int j = 0U; j < 512U; j++)
			for (unsigned int k = previous_tables; k < table_count; k++)
				if (runtime_tables[i][j] == (ops->address(runtime_tables[k]) | PTE_PAGE))
					runtime_tables[i][j] = 0U;
	for (unsigned int i = previous_tables; i < table_count; i++)
		memset(runtime_tables[i], 0, sizeof(runtime_tables[i]));
	table_count = previous_tables;
	ops->clean(runtime_tables, sizeof(runtime_tables));
	gpu_private_control_release(service, object);
}

static struct fw_group *group_lookup(const void *owner, unsigned long handle)
{
	unsigned long slot = handle & 0xffffUL;
	struct fw_group *group;

	if (owner == NULL || slot == 0UL || slot > GPU_FIRMWARE_LOGICAL_GROUPS)
		return NULL;
	group = &groups[slot - 1UL];
	return group->owner == owner && group->handle == handle ? group : NULL;
}

static bool clear_control(const struct gpu_private_ops *memory_ops, unsigned int index)
{
	unsigned long pa;

	return gpu_private_control_page(image_service, control_object, index, &pa) &&
		memory_ops->clear_page(pa);
}

static bool free_extent(unsigned int pages, unsigned int *first)
{
	unsigned int run = 0U;

	for (unsigned int i = 0U; i < control_pages; i++) {
		if (control_user[i] == 0U) {
			if (run == 0U)
				*first = i;
			if (++run == pages)
				return true;
		} else {
			run = 0U;
		}
	}
	return false;
}

void gpu_firmware_group_create(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long context, unsigned long streams,
		struct gpu_private_result *result)
{
	struct gpu_firmware_config config;
	struct fw_group *group;
	unsigned int count = 0U, slot = GPU_FIRMWARE_LOGICAL_GROUPS;
	unsigned int pages, first = 0U;

	init_result(result);
	if (!authenticated(service) || owner == NULL || owner == service ||
	    context == 0UL || streams == 0UL || streams > GPU_FIRMWARE_STREAMS)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (state != GPU_FIRMWARE_CONFIGURED || control_object == 0UL ||
	    streams > interfaces.streams || ops == NULL || ops->address == NULL ||
	    ops->configuration == NULL || memory_ops == NULL || memory_ops->clear_page == NULL ||
	    !ops->configuration(ops->address(runtime_tables[0]), &config))
		return;
	for (unsigned int i = 0U; i < GPU_FIRMWARE_LOGICAL_GROUPS; i++) {
		if (groups[i].handle == 0UL)
			slot = i;
		else if (groups[i].owner == owner)
			count++;
	}
	result->status = GPU_PRIVATE_FULL;
	if (count >= GPU_FIRMWARE_CLIENT_GROUPS || slot == GPU_FIRMWARE_LOGICAL_GROUPS ||
	    group_generation == UINT32_MAX)
		return;
	/* All logical groups use firmware-discovered ordinary suspend size and
	 * separate 4 KiB input/output pages per stream, as in native Panthor.
	 * Protected-mode buffers and ring commands are not enabled by reservation.
	 */
	pages = (interfaces.suspend_size + 4095U) / 4096U + (unsigned int)streams * 2U;
	if (!free_extent(pages, &first))
		return;
	result->status = GPU_PRIVATE_INPUT;
	if (!gpu_private_context_hold(service, owner, context))
		return;
	group = &groups[slot];
	*group = (struct fw_group) {
		.owner = owner, .handle = GROUP_PREFIX | (++group_generation << 16U) | (slot + 1UL),
		.context = context, .first = first, .pages = pages, .streams = (unsigned int)streams,
		.state = GPU_FIRMWARE_GROUP_QUARANTINED
	};
	memset(fw_storage.history[slot], 0, sizeof(fw_storage.history[slot]));
	memset(fw_storage.origin[slot], 0, sizeof(fw_storage.origin[slot]));
	for (unsigned int i = first; i < first + pages; i++)
		control_user[i] = (unsigned short)(slot + 1U);
	/* Publish the retained lifetime before any trusted clearing. A failure
	 * exposes only a cleanup handle, never usable resources or partial state.
	 */
	result->status = GPU_PRIVATE_STATE;
	result->value[0] = group->handle;
	for (unsigned int i = first; i < first + pages; i++)
		if (!clear_control(memory_ops, i))
			return;
	group->state = GPU_FIRMWARE_GROUP_RESERVED;
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[1] = streams;
	result->value[2] = interfaces.suspend_size;
	result->value[3] = pages;
}

void gpu_firmware_group_configure(const struct gpu_private_ops *memory_ops,
		const void *service, const void *owner, unsigned long handle,
		const struct gpu_firmware_queue_config *queues, unsigned long count,
		struct gpu_private_result *result)
{
	struct fw_group *group = group_lookup(owner, handle);
	unsigned int pages = 1U, first = 0U, slot;

	init_result(result);
	if (!authenticated(service) || group == NULL || queues == NULL || count != group->streams ||
	    memory_ops == NULL || memory_ops->clear_page == NULL)
		return;
	for (unsigned int i = 0U; i < count; i++) {
		uint32_t bytes = queues[i].ring_bytes;

		if (bytes < 4096U || bytes > 65536U || (bytes & (bytes - 1U)) != 0U ||
		    queues[i].priority > 15U)
			return;
		pages += bytes / 4096U;
	}
	result->status = GPU_PRIVATE_STATE;
	if (state != GPU_FIRMWARE_CONFIGURED ||
	    (group->state != GPU_FIRMWARE_GROUP_RESERVED && group->state != GPU_FIRMWARE_GROUP_PREPARED) ||
	    !gpu_private_context_hold(service, owner, group->context))
		return;
	gpu_private_context_put(owner, group->context);
	if (group->rings_configured) {
		if (memcmp(group->queues, queues, count * sizeof(*queues)) != 0)
			return;
		goto success;
	}
	result->status = GPU_PRIVATE_FULL;
	if (!free_extent(pages, &first))
		return;
	slot = (unsigned int)(group - groups + 1);
	group->ring_first = first;
	group->ring_pages = pages;
	memcpy(group->queues, queues, count * sizeof(*queues));
	group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
	for (unsigned int i = first; i < first + pages; i++)
		control_user[i] = (unsigned short)slot;
	result->status = GPU_PRIVATE_STATE;
	for (unsigned int i = first; i < first + pages; i++)
		if (!clear_control(memory_ops, i))
			return;
	for (unsigned int i = 0U; i < count; i++) {
		unsigned int nr = queues[i].ring_bytes / 4096U;

		gpu_private_control_mapping(memory_ops, service, owner, group->context,
			control_object, first, nr, false, true, result);
		if (result->status != GPU_PRIVATE_SUCCESS)
			return;
		group->mapped_streams++;
		first += nr;
	}
	gpu_private_control_mapping(memory_ops, service, owner, group->context,
		control_object, first, 1U, true, true, result);
	if (result->status != GPU_PRIVATE_SUCCESS)
		return;
	group->sync_mapped = true;
	group->rings_configured = true;
	group->state = GPU_FIRMWARE_GROUP_RESERVED;
success:
	init_result(result);
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = count;
	result->value[1] = group->ring_pages;
}

void gpu_firmware_group_queue_validate(const void *service, const void *owner,
		unsigned long handle, unsigned long index, unsigned long ring_bytes,
		unsigned long priority, struct gpu_private_result *result)
{
	struct fw_group *group = group_lookup(owner, handle);

	init_result(result);
	if (!authenticated(service) || group == NULL || index >= group->streams)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (state != GPU_FIRMWARE_CONFIGURED || group->state != GPU_FIRMWARE_GROUP_RESERVED ||
	    !group->rings_configured || !gpu_private_context_hold(service, owner, group->context))
		return;
	gpu_private_context_put(owner, group->context);
	result->status = GPU_PRIVATE_INPUT;
	if (group->queues[index].ring_bytes != ring_bytes || group->queues[index].priority != priority)
		return;
	result->status = GPU_PRIVATE_SUCCESS;
}

void gpu_firmware_group_destroy(const struct gpu_private_ops *memory_ops,
		const void *owner, unsigned long handle, struct gpu_private_result *result)
{
	struct fw_group *group = group_lookup(owner, handle);
	unsigned int budget = GPU_PRIVATE_BATCH;

	init_result(result);
	if (group == NULL || memory_ops == NULL || memory_ops->clear_page == NULL)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (group->tasks != 0U || group->prepared_task != 0UL)
		return; /* Prepared/published groups require trusted hardware retirement. */
	/* Reservations and fully retired, detached groups reach this path.
	 * A saved context has no hardware lease after acknowledged TERMINATE;
	 * remove its aliases and scrub the retained state before extent reuse.
	 */
	group->state = GPU_FIRMWARE_GROUP_CLOSING;
	result->status = GPU_PRIVATE_STATE;
	/* Remove all Client GPU aliases before scrubbing/reusing any ring page.
	 * The private core refuses active contexts; future launch needs trusted
	 * stop/drain before reaching this reservation-only retirement.
	 */
	while (group->mapped_streams != 0U) {
		unsigned int stream = group->mapped_streams - 1U;
		unsigned int first = group->ring_first;

		for (unsigned int i = 0U; i < stream; i++)
			first += group->queues[i].ring_bytes / 4096U;
		gpu_private_control_mapping(memory_ops, image_service, owner, group->context,
			control_object, first, group->queues[stream].ring_bytes / 4096U,
			false, false, result);
		if (result->status != GPU_PRIVATE_SUCCESS)
			return;
		group->mapped_streams--;
	}
	if (group->sync_mapped) {
		gpu_private_control_mapping(memory_ops, image_service, owner, group->context,
			control_object, group->ring_first + group->ring_pages - 1U, 1U,
			true, false, result);
		if (result->status != GPU_PRIVATE_SUCCESS)
			return;
		group->sync_mapped = false;
	}
	unsigned int total = group->pages + group->ring_pages;

	result->status = GPU_PRIVATE_STATE;
	while (group->cleared < total && budget-- != 0U) {
		unsigned int index = group->cleared < group->pages ?
			group->first + group->cleared : group->ring_first + group->cleared - group->pages;

		if (!clear_control(memory_ops, index)) {
			result->value[0] = total - group->cleared;
			return;
		}
		group->cleared++;
	}
	result->value[0] = total - group->cleared;
	if (group->cleared != total) {
		result->status = GPU_PRIVATE_INCOMPLETE;
		return;
	}
	for (unsigned int i = group->first; i < group->first + group->pages; i++)
		control_user[i] = 0U;
	for (unsigned int i = group->ring_first; i < group->ring_first + group->ring_pages; i++)
		control_user[i] = 0U;
	gpu_private_context_put(owner, group->context);
	memset(group, 0, sizeof(*group));
	result->status = GPU_PRIVATE_SUCCESS;
}

void gpu_firmware_group_inspect(const void *service, const void *owner,
		unsigned long handle, struct gpu_private_result *result)
{
	struct fw_group *group = group_lookup(owner, handle);

	init_result(result);
	if (!authenticated(service) || group == NULL)
		return;
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = group->state;
	result->value[1] = group->streams;
	result->value[2] = interfaces.suspend_size;
	result->value[3] = group->pages + group->ring_pages - group->cleared;
}

void gpu_firmware_group_validate(const void *service, const void *owner,
		unsigned long context, unsigned long handle, unsigned long streams,
		struct gpu_private_result *result)
{
	struct fw_group *group = group_lookup(owner, handle);

	init_result(result);
	if (!authenticated(service) || group == NULL || group->context != context ||
	    streams == 0UL || streams != group->streams)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (state != GPU_FIRMWARE_CONFIGURED ||
	    (group->state != GPU_FIRMWARE_GROUP_RESERVED && group->state != GPU_FIRMWARE_GROUP_PREPARED &&
	     !group_domain(group)) ||
	    !gpu_private_context_hold(service, owner, context))
		return;
	gpu_private_context_put(owner, context);
	gpu_firmware_group_inspect(service, owner, handle, result);
}

bool gpu_firmware_group_resources(const void *service, const void *owner,
		unsigned long handle, struct gpu_firmware_group_resources *resources)
{
	struct fw_group *group = group_lookup(owner, handle);
	uint32_t va;

	if (resources == NULL)
		return false;
	memset(resources, 0, sizeof(*resources));
	if (!authenticated(service) || state != GPU_FIRMWARE_CONFIGURED || group == NULL ||
	    (group->state != GPU_FIRMWARE_GROUP_RESERVED && group->state != GPU_FIRMWARE_GROUP_PREPARED &&
	     !group_domain(group)) ||
	    !gpu_private_context_hold(service, owner, group->context))
		return false;
	gpu_private_context_put(owner, group->context);
	resources->context = group->context;
	resources->suspend_va = GPU_FIRMWARE_CONTROL_VA + group->first * 4096U;
	resources->suspend_bytes = interfaces.suspend_size;
	resources->streams = group->streams;
	va = resources->suspend_va + ((interfaces.suspend_size + 4095U) & ~4095U);
	for (unsigned int i = 0U; i < group->streams; i++) {
		resources->input_va[i] = va;
		resources->output_va[i] = va + 4096U;
		va += 8192U;
	}
	if (group->rings_configured) {
		uint64_t ring = GPU_PRIVATE_CONTROL_GPU_VA + (uint64_t)group->ring_first * 4096U;

		for (unsigned int i = 0U; i < group->streams; i++) {
			resources->ring_va[i] = ring;
			resources->ring_bytes[i] = group->queues[i].ring_bytes;
			resources->priority[i] = group->queues[i].priority;
			ring += group->queues[i].ring_bytes;
		}
		resources->sync_va = ring;
	}
	return true;
}

static struct fw_task *task_lookup_raw(const void *owner, unsigned long handle)
{
	unsigned long slot = handle & 0xffffUL;
	struct fw_task *task;

	if (owner == NULL || slot == 0UL || slot > GPU_FIRMWARE_TASKS)
		return NULL;
	task = &tasks[slot - 1UL];
	return task->owner == owner && task->handle == handle ? task : NULL;
}

static struct fw_task *task_lookup(const void *owner, unsigned long handle)
{
	struct fw_task *task = task_lookup_raw(owner, handle);

	return task != NULL && !task->internal ? task : NULL;
}

static bool group_domain(const struct fw_group *group)
{
	struct fw_task *anchor = task_lookup_raw(group->owner, group->prepared_task);

	return group->state == GPU_FIRMWARE_GROUP_STARTED && anchor != NULL &&
		anchor->internal && anchor->resources.group == group->handle &&
		anchor->resources.context == group->context;
}

static void task_wrapper(struct fw_group *group, struct gpu_firmware_task_resources *resource,
		unsigned long queue, unsigned long start, unsigned long bytes,
		unsigned long latest_flush)
{
	unsigned int registers = (interfaces.stream_features & 255U) + 1U;
	unsigned int scoreboards = (interfaces.stream_features >> 8U) & 255U;
	uint64_t addr_reg, val_reg, sync;

	*resource = (struct gpu_firmware_task_resources) {
		.group = group->handle, .context = group->context, .queue = (uint32_t)queue,
		.bytes = (uint32_t)bytes, .latest_flush = (uint32_t)latest_flush
	};
	/* Match native Panthor's 16-instruction CALL/sync/error-barrier wrapper.
	 * Registers/features originate from the pinned firmware's validated CS
	 * interface; sync is computed from this group's protected completion page.
	 * No Proxy-selected instruction, register or completion address is accepted.
	 */
	addr_reg = registers - 4U;
	val_reg = addr_reg + 2U;
	sync = GPU_PRIVATE_CONTROL_GPU_VA +
		(uint64_t)(group->ring_first + group->ring_pages - 1U) * 4096U + queue * 16U;
	uint64_t *instructions = resource->instructions;

	instructions[0] = (UINT64_C(2) << 56U) | (val_reg << 48U) | latest_flush;
	instructions[1] = (UINT64_C(36) << 56U) | (val_reg << 40U) | UINT64_C(0x233);
	instructions[2] = (UINT64_C(1) << 56U) | (addr_reg << 48U) | start;
	instructions[3] = (UINT64_C(2) << 56U) | (val_reg << 48U) | bytes;
	instructions[4] = (UINT64_C(3) << 56U) | (UINT64_C(1) << 16U);
	instructions[5] = (UINT64_C(32) << 56U) | (addr_reg << 40U) | (val_reg << 32U);
	if (bytes == 0UL)
		memset(instructions + 2U, 0, 4U * sizeof(*instructions));
	instructions[6] = (UINT64_C(1) << 56U) | (addr_reg << 48U) | sync;
	/* SYNC_ADD64 adds one completion, rather than the member ordinal. */
	instructions[7] = (UINT64_C(1) << 56U) | (val_reg << 48U) | UINT64_C(1);
	instructions[8] = (UINT64_C(3) << 56U) | (((UINT64_C(1) << scoreboards) - 1U) << 16U);
	instructions[9] = (UINT64_C(51) << 56U) | (addr_reg << 40U) | (val_reg << 32U) | UINT64_C(1);
	instructions[10] = UINT64_C(47) << 56U;
}

static void task_stage(const struct gpu_private_ops *memory_ops,
		const void *service, const void *owner, unsigned long handle,
		const struct gpu_firmware_task_command *commands, unsigned int members,
		bool legacy, bool deferred, struct gpu_private_result *result)
{
	struct fw_group *group = group_lookup(owner, handle);
	struct fw_task *task;
	struct gpu_private_command_range ranges[GPU_PRIVATE_TASK_BATCH];
	unsigned int requested[GPU_FIRMWARE_STREAMS] = {0};
	unsigned int queued[GPU_FIRMWARE_STREAMS] = {0};
	unsigned int slot = GPU_FIRMWARE_TASKS, count = 0U;
	unsigned int registers = (interfaces.stream_features & 255U) + 1U;
	unsigned int scoreboards = (interfaces.stream_features >> 8U) & 255U;

	init_result(result);
	if (!authenticated(service) || group == NULL || commands == NULL ||
	    members == 0U || members > GPU_PRIVATE_TASK_BATCH)
		return;
	for (unsigned int i = 0U; i < members; i++) {
		const struct gpu_firmware_task_command *cmd = &commands[i];

		if (cmd->queue >= group->streams || cmd->pad != 0U ||
		    ((cmd->start | cmd->bytes) & 7UL) != 0UL ||
		    (!legacy && ((cmd->start & 63UL) != 0UL ||
				 ((cmd->bytes == 0U) != (cmd->start == 0U)))) ||
		    (legacy && cmd->bytes == 0U))
			return;
		ranges[i] = (struct gpu_private_command_range) { .start = cmd->start, .bytes = cmd->bytes };
		requested[cmd->queue]++;
	}
	result->status = GPU_PRIVATE_STATE;
	if (state != GPU_FIRMWARE_CONFIGURED ||
	    (group->state != GPU_FIRMWARE_GROUP_RESERVED && !(group_domain(group) && group->tasks == 1U)) ||
	    !group->rings_configured || registers < 4U || scoreboards == 0U || scoreboards > 16U)
		return;
	for (unsigned int i = 0U; i < GPU_FIRMWARE_TASKS; i++) {
		if (tasks[i].handle == 0UL)
			slot = i;
		else if (tasks[i].owner == owner) {
			count++;
			if (!tasks[i].internal && tasks[i].resources.group == handle)
				for (unsigned int q = 0U; q < group->streams; q++)
					queued[q] += tasks[i].queue_count[q];
		}
	}
	result->status = GPU_PRIVATE_FULL;
	if (slot == GPU_FIRMWARE_TASKS || count >= GPU_FIRMWARE_CLIENT_TASKS ||
	    task_generation == UINT32_MAX)
		return;
	for (unsigned int q = 0U; q < group->streams; q++)
		if (queued[q] + requested[q] > group->queues[q].ring_bytes /
				(GPU_FIRMWARE_TASK_INSTRUCTIONS * 8U))
			return;
	result->status = GPU_PRIVATE_STATE;
	bool live = group_domain(group);
	if (live ? !gpu_private_task_hold_live(memory_ops, service, owner, group->context,
			group->prepared_task, ranges, members) :
		!gpu_private_task_hold_batch(memory_ops, service, owner, group->context, ranges, members))
		return;
	task = &tasks[slot];
	*task = (struct fw_task) {
		.owner = owner, .handle = TASK_PREFIX | (++task_generation << 16U) | (slot + 1UL),
		.count = members, .live = live, .published_members = deferred ? 0U : (1U << members) - 1U
	};
	for (unsigned int i = 0U; i < members; i++) {
		const struct gpu_firmware_task_command *cmd = &commands[i];

		task->queue_count[cmd->queue]++;
		if (i == 0U)
			task_wrapper(group, &task->resources, cmd->queue, cmd->start, cmd->bytes,
				cmd->latest_flush);
		else
			task->extra[i - 1U] = *cmd;
		task->queue_mask |= 1U << cmd->queue;
	}
	group->tasks++;
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = task->handle;
	result->value[1] = legacy ? commands[0].queue : members;
	if (!legacy)
		result->value[2] = task->queue_mask;
}

void gpu_firmware_task_stage(const struct gpu_private_ops *memory_ops,
		const void *service, const void *owner, unsigned long handle,
		unsigned long queue, unsigned long start, unsigned long bytes,
		unsigned long latest_flush, struct gpu_private_result *result)
{
	init_result(result);
	if (queue > UINT32_MAX || bytes > UINT32_MAX || latest_flush > UINT32_MAX)
		return;
	const struct gpu_firmware_task_command command = {
		.start = start, .bytes = (uint32_t)bytes, .queue = (uint32_t)queue,
		.latest_flush = (uint32_t)latest_flush
	};

	task_stage(memory_ops, service, owner, handle, &command, 1U, true, false, result);
}

void gpu_firmware_task_stage_batch(const struct gpu_private_ops *memory_ops,
		const void *service, const void *owner, unsigned long handle,
		const struct gpu_firmware_task_command *commands, unsigned int count,
		unsigned long flags, struct gpu_private_result *result)
{
	init_result(result);
	if ((flags & ~(GPU_PRIVATE_TASK_DEFERRED | GPU_PRIVATE_TASK_DELEGATE)) != 0UL ||
	    ((flags & GPU_PRIVATE_TASK_DELEGATE) != 0UL &&
	     (flags & GPU_PRIVATE_TASK_DEFERRED) == 0UL))
		return;
	task_stage(memory_ops, service, owner, handle, commands, count, false,
		(flags & GPU_PRIVATE_TASK_DEFERRED) != 0UL, result);
	if (result->status == GPU_PRIVATE_SUCCESS)
		task_lookup(owner, result->value[0])->delegated =
			(flags & GPU_PRIVATE_TASK_DELEGATE) != 0UL;
}

void gpu_firmware_task_stage_domain(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long handle,
		const struct gpu_firmware_task_command *commands, unsigned int count,
		unsigned long flags, struct gpu_private_result *result)
{
	struct fw_group *group = group_lookup(owner, handle);
	uint32_t requested = 0U;

	init_result(result);
	if (!authenticated(service) || group == NULL || commands == NULL || count == 0U ||
	    count > GPU_PRIVATE_TASK_BATCH ||
	    (flags & ~(GPU_PRIVATE_TASK_DEFERRED | GPU_PRIVATE_TASK_DELEGATE)) != 0UL ||
	    ((flags & GPU_PRIVATE_TASK_DELEGATE) != 0UL &&
	     (flags & GPU_PRIVATE_TASK_DEFERRED) == 0UL))
		return;
	for (unsigned int i = 0U; i < count; i++) {
		const struct gpu_firmware_task_command *cmd = &commands[i];

		if (cmd->queue >= group->streams || cmd->pad != 0U ||
		    (cmd->start & 63UL) != 0UL || (cmd->bytes & 7U) != 0U ||
		    ((cmd->bytes == 0U) != (cmd->start == 0UL)))
			return;
		requested |= 1U << cmd->queue;
	}
	/* Starting a previously inactive queue requires a stopped-slot setup,
	 * not an invented live EXTRACT_INIT or stale STOP snapshot workaround.
	 */
	if (group_domain(group) &&
	    ((requested & ~group->active_queues) != 0U || (flags & GPU_PRIVATE_TASK_DEFERRED) == 0UL)) {
		gpu_firmware_group_yield(ops, memory_ops, owner, handle, result);
		if (result->status != GPU_PRIVATE_SUCCESS) return;
	}
	gpu_firmware_task_stage_batch(memory_ops, service, owner, handle, commands, count, flags, result);
}

void gpu_firmware_task_stage_hint(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long handle,
		const struct gpu_firmware_task_command *commands, unsigned int count,
		unsigned long flags, unsigned long hint, struct gpu_private_result *result)
{
	struct fw_group *group = group_lookup(owner, handle);

	init_result(result);
	if (!authenticated(service) || group == NULL || count != 1U ||
	    (flags & GPU_PRIVATE_TASK_DEFERRED) == 0UL ||
	    !gpu_private_task_hint_check(memory_ops, service, owner, group->context, hint))
		return;
	/* No callback or policy unlock can change the hint mapping between this
	 * check and the original range checks/mapping hold in task_stage().
	 * Never replace start/bytes with the hint's mapped address.
	 */
	gpu_firmware_task_stage_domain(ops, memory_ops, service, owner, handle,
		commands, count, flags, result);
	if (result->status == GPU_PRIVATE_SUCCESS) {
		struct fw_task *task = task_lookup(owner, result->value[0]);
		unsigned int registers = (interfaces.stream_features & 255U) + 1U;
		uint64_t addr_reg = registers - 4U, val_reg = addr_reg + 2U;
		uint64_t *instructions = task->resources.instructions;

		/* Original CALL, WAIT(all), protected SYNC_ADD64 and error propagation
		 * remain unchanged. Add the untrusted data hint before ERROR_BARRIER.
		 * The fixed wrapper is still 16 instructions; no extra RMM storage.
		 */
		instructions[12] = instructions[10];
		instructions[10] = (UINT64_C(1) << 56U) | (addr_reg << 48U) | hint;
		instructions[11] = (UINT64_C(51) << 56U) | (addr_reg << 40U) | (val_reg << 32U) | UINT64_C(1);
	}
}

void gpu_firmware_task_cancel(const void *owner, unsigned long handle,
		struct gpu_private_result *result)
{
	struct fw_task *task = task_lookup(owner, handle);
	struct fw_group *group;

	init_result(result);
	if (task == NULL)
		return;
	group = group_lookup(owner, task->resources.group);
	result->status = GPU_PRIVATE_STATE;
	if (task->preparing || group == NULL || group->tasks == 0U ||
	    !gpu_private_task_put(owner, task->resources.context))
		return;
	/* Only unprepared records reach this cleanup. Published/uncertain work
	 * retains its token until trusted hardware retirement.
	 */
	group->tasks--;
	memset(task, 0, sizeof(*task));
	result->status = GPU_PRIVATE_SUCCESS;
}

void gpu_firmware_task_cancel_staged(const struct gpu_private_ops *memory_ops,
		const void *owner, unsigned long token, struct gpu_private_result *result)
{
	struct fw_task *task = task_lookup(owner, token);
	struct fw_group *group;

	if (task == NULL || !task->live) {
		gpu_firmware_task_cancel(owner, token, result);
		return;
	}
	init_result(result);
	group = group_lookup(owner, task->resources.group);
	result->status = GPU_PRIVATE_STATE;
	if (task->preparing || group == NULL || !group_domain(group) || group->tasks != 2U ||
	    !gpu_private_task_put_live(memory_ops, image_service, owner, group->context, group->prepared_task))
		return;
	group->tasks--;
	memset(task, 0, sizeof(*task));
	result->status = GPU_PRIVATE_SUCCESS;
}

bool gpu_firmware_task_resources(const void *service, const void *owner,
		unsigned long handle, struct gpu_firmware_task_resources *resources)
{
	struct fw_task *task = task_lookup(owner, handle);
	struct fw_group *group;

	if (resources == NULL)
		return false;
	memset(resources, 0, sizeof(*resources));
	if (!authenticated(service) || state != GPU_FIRMWARE_CONFIGURED || task == NULL)
		return false;
	group = group_lookup(owner, task->resources.group);
	if (group == NULL ||
	    (group->state != GPU_FIRMWARE_GROUP_RESERVED && group->state != GPU_FIRMWARE_GROUP_PREPARED &&
	     !(group->state == GPU_FIRMWARE_GROUP_STARTED && task->live)) ||
	    group->tasks == 0U ||
	    !gpu_private_context_hold(service, owner, group->context))
		return false;
	gpu_private_context_put(owner, group->context);
	*resources = task->resources;
	return true;
}

void gpu_firmware_task_validate(const void *service, const void *owner,
		unsigned long context, unsigned long group, unsigned long handle,
		struct gpu_private_result *result)
{
	struct gpu_firmware_task_resources resources;

	init_result(result);
	if (!gpu_firmware_task_resources(service, owner, handle, &resources) ||
	    resources.group != group || resources.context != context)
		return;
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = resources.queue;
	result->value[1] = resources.bytes;
	result->value[2] = resources.latest_flush;
}

static bool write_control(const struct gpu_private_ops *memory_ops, unsigned int page,
		size_t offset, const void *data, size_t bytes)
{
	unsigned long pa;

	return offset <= 4096U && bytes <= 4096U - offset &&
		gpu_private_control_page(image_service, control_object, page, &pa) &&
		memory_ops->write_page(pa, offset, data, bytes);
}

static bool read_control(const struct gpu_private_ops *memory_ops, unsigned int page,
		size_t offset, void *data, size_t bytes)
{
	unsigned long pa;

	return offset <= 4096U && bytes <= 4096U - offset &&
		gpu_private_control_page(image_service, control_object, page, &pa) &&
		memory_ops->read_page(pa, offset, data, bytes);
}

static bool queue_base(const struct fw_group *group,
		unsigned int queue, uint64_t *base)
{
	if (state != GPU_FIRMWARE_CONFIGURED || queue >= group->streams || queue >= GPU_FIRMWARE_STREAMS)
		return false;
	*base = fw_storage.history[group - groups][queue];
	return (*base & 127U) == 0U &&
		*base <= UINT64_MAX - GPU_PRIVATE_TASK_BATCH * 128U;
}

static uint64_t queue_origin(const struct fw_group *group, unsigned int queue)
{
	assert(queue < GPU_FIRMWARE_STREAMS);
	return fw_storage.origin[group - groups][queue];
}

/* Validate all queues before releasing the private-task/cache lease. Once it
 * succeeds, this in-RMM commit has no fallible page callbacks or partial queue
 * publication. Failed retirement leaves every history unchanged. Aborts have
 * scrubbed the arena, so their CPU-only history must also restart at zero.
 */
static bool retire_history(const void *service, const void *owner,
		struct fw_group *group, const struct fw_task *task)
{
	uint64_t *history = fw_storage.history[group - groups];

	if (state != GPU_FIRMWARE_CONFIGURED || group->streams == 0U ||
	    group->streams > GPU_FIRMWARE_STREAMS)
		return false;
	if (task->preserve) {
		for (unsigned int q = 0U; q < group->streams; q++) {
			uint64_t base;

			if (!queue_base(group, q, &base) ||
			    task->queue_count[q] > GPU_PRIVATE_TASK_BATCH)
				return false;
		}
	}
	if (!gpu_private_task_retire(service, owner, group->context, task->handle))
		return false;
	if (task->preserve) {
		for (unsigned int q = 0U; q < group->streams; q++)
			history[q] += task->queue_count[q] * sizeof(task->resources.instructions);
	} else {
		memset(history, 0, sizeof(fw_storage.history[0]));
	}
	return true;
}

static void word64(uint32_t *words, unsigned int index, uint64_t value)
{
	words[index] = (uint32_t)value;
	words[index + 1U] = (uint32_t)(value >> 32U);
}

static unsigned int task_published_count(const struct fw_task *task, unsigned int queue)
{
	unsigned int count = 0U;

	for (unsigned int i = 0U; i < task->count; i++) {
		unsigned int q = i == 0U ? task->resources.queue : task->extra[i - 1U].queue;

		if (q == queue && (task->published_members & (1U << i)) != 0U)
			count++;
	}
	return count;
}

#define TASK_STATUS_UPDATE (1U << 5U)
#define TASK_CS_START (1U | (1U << 4U) | (1U << 8U) | (1U << 10U))
#define TASK_CSG_ACK_MASK (7U | (1U << 4U))
#define TASK_CS_OOM (1U << 26U)
#define TASK_CS_ERRORS ((1U << 27U) | (1U << 30U) | (1U << 31U))

/* FINISH established STATUS + FLUSH_MEM before hiding this anchor. Nothing
 * may advance its protected producers while it stays internal. A valid
 * mapping epoch and retained leases are necessary but insufficient: inspect
 * real configuration/roots and every queue on both sides of page callbacks.
 * This cannot certify a running/public task or establish a new drain.
 */
static bool task_revalidate_idle(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, struct fw_group *group, struct fw_task *anchor)
{
	struct gpu_private_result checked;
	bool pending;

	if (!group_domain(group) || anchor == NULL || !anchor->internal ||
	    !anchor->started || !anchor->ready || anchor->stop_attempted ||
	    anchor->completed || anchor->status_pending ||
	    group->prepared_task != anchor->handle ||
	    !gpu_private_task_is_drained(memory_ops, service, owner, group->context, anchor->handle))
		return false;
	task_start(ops, memory_ops, service, owner, group->context,
		group->handle, anchor->handle, false, true, &checked);
	if (checked.status != GPU_PRIVATE_SUCCESS ||
	    !task_idle_snapshot(ops, memory_ops, group, anchor, &pending) || pending)
		return false;
	task_start(ops, memory_ops, service, owner, group->context,
		group->handle, anchor->handle, false, true, &checked);
	return checked.status == GPU_PRIVATE_SUCCESS &&
		gpu_private_task_is_drained(memory_ops, service, owner, group->context, anchor->handle);
}

/* No GPU-visible INSERT/EXTRACT_INIT is changed here. The old idle
 * context owns the hardware throughout private ring preparation and the
 * callback-free commit of history, cache token and task ownership.
 */
static void task_prepare_live(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, struct fw_group *group, struct fw_task *task,
		struct gpu_private_result *result)
{
	struct fw_task *anchor = task_lookup_raw(owner, group->prepared_task);
	struct gpu_firmware_group_resources resources;
	uint64_t next[GPU_FIRMWARE_STREAMS] = {0};

	if (!group_domain(group) || anchor == task || group->tasks != 2U ||
	    !task->live || task->preparing || task->published_members != 0U ||
	    (task->queue_mask & ~group->active_queues) != 0U ||
	    memory_ops->write_page == NULL || memory_ops->read_page == NULL)
		return;
	if (!task_revalidate_idle(ops, memory_ops, service, owner, group, anchor))
		goto failed;
	if (!gpu_firmware_group_resources(service, owner, group->handle, &resources))
		return;
	for (unsigned int q = 0U; q < group->streams; q++) {
		uint64_t base;

		if (!queue_base(group, q, &base) ||
		    anchor->queue_count[q] > GPU_PRIVATE_TASK_BATCH ||
		    task->queue_count[q] > group->queues[q].ring_bytes / 128U)
			return;
		next[q] = base + anchor->queue_count[q] * sizeof(task->resources.instructions);
		if (next[q] > UINT64_MAX - GPU_PRIVATE_TASK_BATCH * 128U)
			return;
	}
	/* Page callbacks can fail after a partial write. Keep both references
	 * and quarantine before the first one; cancellation cannot discard them.
	 */
	group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
	task->preparing = true;
	uint64_t offset[GPU_FIRMWARE_STREAMS];
	memcpy(offset, next, sizeof(offset));
	for (unsigned int i = 0U; i < task->count; i++) {
		struct gpu_firmware_task_resources generated;
		const struct gpu_firmware_task_resources *member = &task->resources;

		if (i != 0U) {
			const struct gpu_firmware_task_command *cmd = &task->extra[i - 1U];

			task_wrapper(group, &generated, cmd->queue, cmd->start, cmd->bytes, cmd->latest_flush);
			member = &generated;
		}
		unsigned int q = member->queue;
		unsigned int page = (resources.ring_va[q] - GPU_PRIVATE_CONTROL_GPU_VA) / 4096U;
		unsigned int at = (unsigned int)(offset[q] & (resources.ring_bytes[q] - 1U));

		if (!write_control(memory_ops, page + at / 4096U, at % 4096U,
				member->instructions, sizeof(member->instructions)))
			goto failed;
		offset[q] += sizeof(member->instructions);
	}
	/* The hidden anchor's drain has just been revalidated under this lock.
	 * Only unpublished protected ring bytes were written since:
	 * INSERT, EXTRACT_INIT, CS/CSG inputs and doorbells remain unchanged.
	 * There is no new GPU work to drain or flush again. Recheck actual roots
	 * and configuration on both sides of the all-queue read callbacks. The
	 * handoff consumes the certificate before Client READY or publication.
	 */
	group->state = GPU_FIRMWARE_GROUP_STARTED;
	if (!task_revalidate_idle(ops, memory_ops, service, owner, group, anchor) ||
	    !gpu_private_task_handoff_live(memory_ops, service, owner, group->context,
			anchor->handle, task->handle))
		goto failed;
	/* No callbacks/unlock/publication between these metadata updates. */
	memcpy(fw_storage.history[group - groups], next, group->streams * sizeof(next[0]));
	group->prepared_task = task->handle;
	group->tasks--;
	memset(anchor, 0, sizeof(*anchor));
	/* The CSG remains running; publication is still Client READY-gated. */
	task->start_attempted = task->started = true;
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = GPU_FIRMWARE_GROUP_PREPARED;
	result->value[1] = task->resources.queue;
	return;
failed:
	gpu_private_task_clear_drained(service, owner, group->context, anchor->handle);
	group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
}

void gpu_firmware_task_prepare(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long context, unsigned long handle,
		unsigned long token, struct gpu_private_result *result)
{
	struct fw_task *task = task_lookup(owner, token);
	struct fw_group *group = group_lookup(owner, handle);
	struct gpu_firmware_group_resources resources;
	struct gpu_firmware_config config;
	unsigned int csg, as, cores = 0U;
	unsigned long root;
	unsigned char *shared;
	uint32_t group_input[FW_GROUP_INPUT_SIZE / 4U] = {0};
	uint32_t stream_input[FW_STREAM_INPUT_SIZE / 4U] = {0};
	uint64_t ring_input[2] = {0};

	init_result(result);
	if (!authenticated(service) || group == NULL || task == NULL ||
	    group->context != context || task->resources.group != handle ||
	    task->resources.context != context)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (state == GPU_FIRMWARE_CONFIGURED && task->live &&
	    group->state == GPU_FIRMWARE_GROUP_STARTED) {
		if (ops == NULL || ops->address == NULL || memory_ops == NULL || !group->rings_configured)
			return;
		if (task->preparing && group->prepared_task == token) {
			gpu_private_context_prepare(memory_ops, service, owner, context,
				ops->address(runtime_tables[0]), result);
			if (result->status == GPU_PRIVATE_SUCCESS) {
				init_result(result);
				result->status = GPU_PRIVATE_SUCCESS;
				result->value[0] = GPU_FIRMWARE_GROUP_PREPARED;
				result->value[1] = task->resources.queue;
			}
		} else {
			task_prepare_live(ops, memory_ops, service, owner, group, task, result);
		}
		return;
	}
	if (state != GPU_FIRMWARE_CONFIGURED || !group->rings_configured ||
	    ops == NULL || ops->address == NULL || ops->configuration == NULL ||
	    ops->clean == NULL || ops->invalidate == NULL || memory_ops == NULL ||
	    memory_ops->write_page == NULL || memory_ops->read_page == NULL ||
	    (group->state != GPU_FIRMWARE_GROUP_RESERVED && group->state != GPU_FIRMWARE_GROUP_PREPARED))
		return;
	root = ops->address(runtime_tables[0]);
	if (!ops->configuration(root, &config) || config.shader_mask == 0U)
		return;
	if (group->state == GPU_FIRMWARE_GROUP_PREPARED) {
		if (group->prepared_task != token)
			return;
		gpu_private_context_prepare(memory_ops, service, owner, context, root, result);
		if (result->status != GPU_PRIVATE_SUCCESS)
			return;
		goto success; /* Exact replay checks hardware but publishes nothing. */
	}
	if (!yield_idle_domains(ops, memory_ops, group))
		return;
	/* Cache ownership currently serializes tasks per GPUVM. Do not expose a
	 * second group using the same AS before the first has trusted retirement.
	 */
	for (unsigned int i = 0U; i < GPU_FIRMWARE_LOGICAL_GROUPS; i++)
		if (&groups[i] != group && groups[i].owner == owner &&
		    groups[i].context == context && groups[i].prepared_task != 0UL)
			return;
	if (!gpu_firmware_group_resources(service, owner, handle, &resources))
		return;
	for (csg = 0U; csg < interfaces.groups; csg++)
		if (hardware_groups[csg] == 0UL)
			break;
	result->status = GPU_PRIVATE_FULL;
	if (csg == interfaces.groups)
		return;
	shared = runtime_pages[section_page[interfaces.section]];
	struct fw_slot *slot = &interfaces.slots[csg];
	uint32_t req, ack;

	/* No old group/stream may still be running on a software-free slot. All
	 * offsets are boot-time private snapshots, never followed live here.
	 */
	result->status = GPU_PRIVATE_STATE;
	ops->invalidate(shared + slot->group.output, FW_GROUP_OUTPUT_SIZE);
	memcpy(&ack, shared + slot->group.output, sizeof(ack));
	memcpy(&req, shared + slot->group.input, sizeof(req));
	/* Acknowledged TERMINATE or SUSPEND makes this slot nonexecuting.
	 * SUSPEND preserves native queue state; its CS output can remain START
	 * until the next group's fresh STATUS_UPDATE. Inputs are RMM-private.
	 */
	unsigned int stopped_state = req & 7U;

	if ((stopped_state != 0U && stopped_state != 2U) ||
	    ((req ^ ack) & (TASK_CSG_ACK_MASK | TASK_STATUS_UPDATE)) != 0U)
		return;
	for (unsigned int i = 0U; i < interfaces.streams; i++) {
		ops->invalidate(shared + slot->stream[i].output, FW_STREAM_OUTPUT_SIZE);
		memcpy(&ack, shared + slot->stream[i].output, sizeof(ack));
		memcpy(&req, shared + slot->stream[i].input, sizeof(req));
		if ((req & 7U) != 0U ||
		    (stopped_state == 0U ? (ack & 7U) != 0U : (ack & 7U) > 1U) ||
		    (ack & TASK_CS_ERRORS) != 0U)
			return;
	}
	/* Reserve all identities before any hardware or shared-input write. A
	 * failure cannot permit another group to reuse partially configured state.
	 */
	hardware_groups[csg] = handle;
	group->hardware_csg = csg;
	group->prepared_task = token;
	group->active_queues = (group->suspended ? group->active_queues : 0U) | task->queue_mask;
	group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
	task->preparing = true;
	gpu_private_context_prepare(memory_ops, service, owner, context, root, result);
	if (result->status != GPU_PRIVATE_SUCCESS)
		return;
	as = (unsigned int)result->value[0];
	group->hardware_as = as;
	init_result(result);
	result->status = GPU_PRIVATE_STATE;
	memcpy(fw_storage.origin[group - groups], fw_storage.history[group - groups],
		sizeof(fw_storage.origin[0]));
	uint64_t offsets[GPU_FIRMWARE_STREAMS] = {0};
	for (unsigned int q = 0U; q < group->streams; q++)
		if (!queue_base(group, q, &offsets[q]))
			return;

	for (unsigned int i = 0U; i < task->count; i++) {
		struct gpu_firmware_task_resources generated;
		const struct gpu_firmware_task_resources *member = &task->resources;
		unsigned int q;

		if (i != 0U) {
			const struct gpu_firmware_task_command *cmd = &task->extra[i - 1U];

			task_wrapper(group, &generated, cmd->queue, cmd->start, cmd->bytes,
				cmd->latest_flush);
			member = &generated;
		}
		q = member->queue;
		unsigned int ring_page = (unsigned int)((resources.ring_va[q] -
			GPU_PRIVATE_CONTROL_GPU_VA) / 4096U);

		/* Append in original queue order; each 128-byte wrapper is aligned
		 * and cannot cross a page. Mask only the ring storage offset, never
		 * the monotonic producer/consumer or trusted completion history.
		 */
		unsigned int ring_offset = (unsigned int)(offsets[q] & (resources.ring_bytes[q] - 1U));

		if (!write_control(memory_ops, ring_page + ring_offset / 4096U, ring_offset % 4096U, member->instructions,
				 sizeof(member->instructions)))
			return;
		offsets[q] += sizeof(member->instructions);
	}
	for (unsigned int i = 0U; i < interfaces.streams; i++) {
		memset(stream_input, 0, sizeof(stream_input));
		/* An acknowledged event toggle can remain set after a prior task.
		 * Mirror it while STOP, so the next task does not inherit a fake OOM.
		 */
		memcpy(&stream_input[0], shared + slot->stream[i].output, sizeof(uint32_t));
		stream_input[0] &= 1U << 26U;
		if (i < group->streams) {
			unsigned int io_page = (resources.input_va[i] - GPU_FIRMWARE_CONTROL_VA) / 4096U;

			uint64_t base;

			if (!queue_base(group, i, &base))
				return;
			ring_input[0] = base + task_published_count(task, i) * sizeof(task->resources.instructions);
			ring_input[1] = base;
			if (!write_control(memory_ops, io_page, 0U, ring_input, sizeof(ring_input)))
				return;
			stream_input[1] = resources.priority[i] | ((csg + 1U) << 8U);
			word64(stream_input, 4U, resources.ring_va[i]);
			stream_input[6] = resources.ring_bytes[i];
			word64(stream_input, 12U, resources.input_va[i]);
			word64(stream_input, 14U, resources.output_va[i]);
		}
		/* req is STOP, IRQ mask and instrumentation are zero. In particular
		 * no parent/child notification is toggled by this preparation API.
		 */
		memcpy(shared + slot->stream[i].input, stream_input, sizeof(stream_input));
		ops->clean(shared + slot->stream[i].input, sizeof(stream_input));
	}
	for (uint64_t mask = config.shader_mask; mask != 0U; mask >>= 1U)
		cores += (unsigned int)(mask & 1U);
	/* A stopped hardware slot retains acknowledged endpoint/status toggles.
	 * Mirror both: clearing endpoint can manufacture a pending configuration
	 * before PUBLISH. START explicitly toggles endpoint for the new group.
	 */
	memcpy(&group_input[0], shared + slot->group.output, sizeof(uint32_t));
	group_input[0] &= TASK_STATUS_UPDATE | (1U << 4U) | 7U;
	word64(group_input, 8U, config.shader_mask);
	word64(group_input, 10U, config.shader_mask);
	group_input[12] = 1U; /* Ordinary tiler 0; protected mode remains disabled. */
	/* Reusing a stopped CSG must start from its last child ACKs. Clearing
	 * these toggles would manufacture an unfinished notification on reuse.
	 */
	memcpy(&group_input[2], shared + slot->group.output + 8U, sizeof(uint32_t));
	group_input[13] = cores | (cores << 8U) | (1U << 16U);
	word64(group_input, 16U, resources.suspend_va);
	group_input[20] = as;
	memcpy(shared + slot->group.input, group_input, sizeof(group_input));
	ops->clean(shared + slot->group.input, sizeof(group_input));
	if (!ops->configuration(root, &config))
		return;
	group->state = GPU_FIRMWARE_GROUP_PREPARED;
success:
	init_result(result);
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = GPU_FIRMWARE_GROUP_PREPARED;
	result->value[1] = task->resources.queue;
}

void gpu_firmware_task_prepare_launch(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long context, unsigned long handle,
		unsigned long token, struct gpu_private_result *result)
{
	struct fw_task *task = task_lookup(owner, token);

	init_result(result);
	if (!authenticated(service) || service == owner || task == NULL)
		return;
	result->status = GPU_PRIVATE_STATE;
	/* The actual service makes a fresh, exact selection, before Client
	 * readiness. Never upgrade an old/partial preparation or rearm a token.
	 * PREPARE still establishes every hardware slot and context invariant.
	 */
	if (task->preparing || task->ready || task->launch_pending ||
	    task->published_members != 0U || task->start_attempted || task->started ||
	    task->stop_attempted || task->quiesced || task->completed || task->cpu_returned)
		return;
	gpu_firmware_task_prepare(ops, memory_ops, service, owner, context, handle, token, result);
	if (result->status == GPU_PRIVATE_SUCCESS)
		task->launch_pending = true;
}

void gpu_firmware_task_ready(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long token, struct gpu_private_result *result)
{
	struct fw_task *task = task_lookup(owner, token);
	struct fw_group *group;
	struct gpu_firmware_config config;
	unsigned long root, pages;

	init_result(result);
	if (!authenticated(service) || task == NULL)
		return;
	group = group_lookup(owner, task->resources.group);
	result->status = GPU_PRIVATE_STATE;
	if (state != GPU_FIRMWARE_CONFIGURED || group == NULL ||
	    (group->state != GPU_FIRMWARE_GROUP_PREPARED &&
	     !(task->live && group->state == GPU_FIRMWARE_GROUP_STARTED)) || group->prepared_task != token ||
	    !task->preparing || ops == NULL || ops->address == NULL ||
	    ops->configuration == NULL || memory_ops == NULL ||
	    memory_ops->sync_page_for_device == NULL)
		return;
	root = ops->address(runtime_tables[0]);
	if (!ops->configuration(root, &config)) {
		group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
		return;
	}
	/* Root replay is check-only: no CPU flush may be mistaken for repairing
	 * a missing or changed AS. Readiness is established by the cache walk;
	 * no caller-supplied assertion can replace it.
	 */
	gpu_private_context_prepare(memory_ops, service, owner, group->context, root, result);
	if (result->status != GPU_PRIVATE_SUCCESS) {
		group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
		return;
	}
	gpu_private_task_cache(memory_ops, service, owner, group->context, token, result);
	if (result->status != GPU_PRIVATE_SUCCESS && result->status != GPU_PRIVATE_INCOMPLETE) {
		group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
		return;
	}
	pages = result->value[0];
	if (!ops->configuration(root, &config)) {
		group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
		init_result(result);
		result->status = GPU_PRIVATE_STATE;
		return;
	}
	if (result->status == GPU_PRIVATE_SUCCESS)
		task->ready = true;
	memset(result->value, 0, sizeof(result->value));
	result->value[0] = task->ready ? 1UL : 0UL;
	result->value[1] = task->resources.queue;
	result->value[2] = pages;
}



void gpu_firmware_task_ready_publish(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long token, struct gpu_private_result *result)
{
	struct fw_task *task = task_lookup(owner, token);
	struct gpu_private_result published;

	init_result(result);
	if (!authenticated(service) || service == owner || task == NULL)
		return;
	result->status = GPU_PRIVATE_STATE;
	/* Zero publication distinguishes deferred batches from legacy tasks.
	 * No caller-selected mask or execution state is accepted. The caller is
	 * the actual Client, or an exact-task delegation consumed by DISPATCH,
	 * under the same policy lock as READY and PUBLISH.
	 */
	if (task->count == 0U || task->count > GPU_PRIVATE_TASK_BATCH ||
	    task->published_members != 0U || (!task->live && (task->start_attempted || task->started)) ||
	    task->stop_attempted || task->quiesced || task->status_pending ||
	    task->completed || task->cpu_returned)
		return;
	gpu_firmware_task_ready(ops, memory_ops, service, owner, token, result);
	if (result->status != GPU_PRIVATE_SUCCESS)
		return; /* In particular, one incomplete cache slice never publishes. */
	gpu_firmware_task_publish(ops, memory_ops, service, owner, token,
		(1UL << task->count) - 1UL, &published);
	if (published.status != GPU_PRIVATE_SUCCESS)
		*result = published; /* Never turn failed publication into READY success. */
}


void gpu_firmware_task_ready_launch(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long token, struct gpu_private_result *result)
{
	struct fw_task *task = task_lookup(owner, token);
	struct gpu_private_result started;

	init_result(result);
	if (!authenticated(service) || service == owner || task == NULL)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (!task->launch_pending)
		return;
	/* One bounded Client cache slice. INCOMPLETE cannot publish or launch;
	 * full readiness retains every independent publication/START check.
	 */
	gpu_firmware_task_ready_publish(ops, memory_ops, service, owner, token, result);
	if (result->status != GPU_PRIVATE_SUCCESS) {
		if (result->status != GPU_PRIVATE_INCOMPLETE)
			task->launch_pending = false;
		return;
	}
	/* Consume before the first possible hardware publication. A failed or
	 * uncertain START retains its original holds and cannot be relaunched.
	 * The task's private context/group, not caller parameters, select START.
	 */
	task->launch_pending = false;
	task_start(ops, memory_ops, service, owner,
		task->resources.context, task->resources.group, token, true, false, &started);
	if (started.status != GPU_PRIVATE_SUCCESS)
		*result = started;
}


void gpu_firmware_task_dispatch(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long context, unsigned long handle,
		unsigned long token, struct gpu_private_result *result)
{
	struct fw_task *task = task_lookup(owner, token);

	init_result(result);
	if (!authenticated(service) || service == owner || task == NULL ||
	    task->resources.context != context || task->resources.group != handle)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (!task->delegated)
		return;
	/* Only STAGE under the actual Client identity grants this permission.
	 * Consume before preparation: no partial failure or lost response can
	 * rearm it. Capacity retries require trusted unprepared cancellation and
	 * a newly staged token. Existing PREPARE enforces exact service binding.
	 */
	task->delegated = false;
	gpu_firmware_task_prepare_launch(ops, memory_ops, service, owner,
		context, handle, token, result);
	if (result->status != GPU_PRIVATE_SUCCESS)
		return;
	gpu_firmware_task_ready_launch(ops, memory_ops, service, owner, token, result);
	if (result->status == GPU_PRIVATE_SUCCESS || result->status == GPU_PRIVATE_INCOMPLETE) {
		/* Incomplete cache work stays with the original Client READY cursor;
		 * the service never loops or receives a completion assertion.
		 */
		unsigned long accepted = result->status == GPU_PRIVATE_SUCCESS ?
			GPU_FIRMWARE_GROUP_STARTED : GPU_FIRMWARE_GROUP_PREPARED;

		init_result(result);
		result->status = GPU_PRIVATE_SUCCESS;
		result->value[0] = accepted;
		result->value[1] = task->resources.queue;
	}
}

static void task_start(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long context, unsigned long handle,
		unsigned long token, bool accept_resume, bool internal,
		struct gpu_private_result *result)
{
	struct fw_task *task = internal ? task_lookup_raw(owner, token) : task_lookup(owner, token);
	struct fw_group *group = group_lookup(owner, handle);
	struct gpu_private_result checked;
	struct gpu_firmware_config config;
	unsigned char *shared;
	struct fw_slot *slot;
	unsigned long root, start;
	unsigned int csg, queue, step = 1U;
	bool status_requested = false;
	uint32_t csg_mask, cs_mask, csg_req, cs_doorbell, global_doorbell;
	uint32_t unacked = 0U, active_ack = 0U;
	uint32_t glb_in[FW_GLOBAL_INPUT_SIZE / 4U], glb_out[FW_GLOBAL_OUTPUT_SIZE / 4U];
	uint32_t csg_in[FW_GROUP_INPUT_SIZE / 4U], csg_out[FW_GROUP_OUTPUT_SIZE / 4U];
	struct fw_stream_status cs_out;
	uint32_t cs_in[FW_STREAM_INPUT_SIZE / 4U];

	init_result(result);
	if (!authenticated(service) || group == NULL || task == NULL ||
	    group->context != context || task->resources.context != context ||
	    task->resources.group != handle)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (state != GPU_FIRMWARE_CONFIGURED || !task->ready ||
	    group->prepared_task != token || !task->preparing ||
	    ops == NULL || ops->address == NULL || ops->configuration == NULL ||
	    ops->clean == NULL || ops->invalidate == NULL || ops->notify == NULL ||
	    ops->clock == NULL || memory_ops == NULL ||
	    (group->state != GPU_FIRMWARE_GROUP_PREPARED && group->state != GPU_FIRMWARE_GROUP_STARTED))
		return;
	step = 2U;
	csg = group->hardware_csg;
	queue = task->resources.queue;
	if (csg >= interfaces.groups || hardware_groups[csg] != handle || queue >= group->streams)
		goto failed;
	step = 3U;
	root = ops->address(runtime_tables[0]);
	step = 4U;
	if (memory_ops->check_running_as != NULL) {
		gpu_private_context_check_running(memory_ops, service, owner, context, root, &config, &checked);
		if (checked.status != GPU_PRIVATE_SUCCESS || config.ack_timeout_ticks == 0UL)
			goto failed;
	} else {
		/* Legacy trusted adapters, including pure firmware-core models, do
		 * not combine the platform register checks.
		 */
		if (!ops->configuration(root, &config) || config.ack_timeout_ticks == 0UL)
			goto failed;
		gpu_private_context_prepare(memory_ops, service, owner, context, root, &checked);
	}
	if (checked.status != GPU_PRIVATE_SUCCESS)
		goto failed;
	shared = runtime_pages[section_page[interfaces.section]];
	slot = &interfaces.slots[csg];
	csg_mask = 1U << csg;
	cs_mask = group->active_queues;
	interface_words(glb_in, shared + interfaces.global.input, sizeof(glb_in));
	interface_words(csg_in, shared + slot->group.input, sizeof(csg_in));
	ops->invalidate(shared + interfaces.global.output, sizeof(glb_out));
	ops->invalidate(shared + slot->group.output, sizeof(csg_out));
	interface_words(glb_out, shared + interfaces.global.output, sizeof(glb_out));
	interface_words(csg_out, shared + slot->group.output, sizeof(csg_out));
	step = 5U;
	if (csg_in[20] != checked.value[0] || glb_out[4] != 0U ||
	    ((glb_in[0] ^ glb_out[0]) & GLB_CONFIG_MASK) != 0U ||
	    ((glb_in[2] ^ glb_out[2]) & csg_mask) != 0U ||
	    ((csg_in[2] ^ csg_out[2]) & cs_mask) != 0U ||
	    (!task->start_attempted && ((csg_in[0] ^ csg_out[0]) & TASK_STATUS_UPDATE) != 0U))
		goto failed;
	step = 6U;
	bool suspended_slot = !task->start_attempted && (csg_in[0] & 7U) == 2U &&
		((csg_in[0] ^ csg_out[0]) & TASK_CSG_ACK_MASK) == 0U;

	for (unsigned int i = 0U; i < interfaces.streams; i++) {
		uint32_t req, expected = task->started && (cs_mask & (1U << i)) != 0U ? 1U : 0U;

		stream_status(ops, shared + slot->stream[i].output, &cs_out);
		interface_words(&req, shared + slot->stream[i].input, sizeof(req));
		if ((req & 7U) != expected ||
		    (suspended_slot ? (cs_out.ack & 7U) > 1U : (cs_out.ack & 7U) != expected) ||
		    (expected == 0U && ((req ^ cs_out.ack) & TASK_CS_OOM) != 0U) ||
		    (cs_out.ack & TASK_CS_ERRORS) != 0U || cs_out.fault != 0U || cs_out.fatal != 0U)
			goto failed;
	}
	step = 7U;
	if (task->start_attempted) {
		if (!task->started || group->state != GPU_FIRMWARE_GROUP_STARTED ||
		    (csg_in[0] & 7U) != (group->suspended ? 3U : 1U) || ((csg_out[0] ^ csg_in[0]) & TASK_CSG_ACK_MASK) != 0U)
			goto failed;
		goto accepted; /* Retry observes acceptance; never repeats publication. */
	}
	step = 8U;
	if (group->state != GPU_FIRMWARE_GROUP_PREPARED ||
	    (!suspended_slot && ((csg_in[0] | csg_out[0]) & 7U) != 0U))
		goto failed;
	csg_req = (csg_in[0] & ~TASK_CSG_ACK_MASK) | (group->suspended ? 3U : 1U) | ((csg_out[0] ^ (1U << 4U)) & (1U << 4U));
	cs_doorbell = (csg_in[2] & ~cs_mask) | ((csg_out[2] ^ cs_mask) & cs_mask);
	global_doorbell = (glb_in[2] & ~csg_mask) | ((glb_out[2] ^ csg_mask) & csg_mask);
	/* The MCU can consume shared input before an MMIO notification. Retain
	 * the exact token and all backing BEFORE publishing the first CS request.
	 */
	task->start_attempted = true;
	group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
	for (unsigned int i = 0U; i < group->streams; i++) {
		if ((cs_mask & (1U << i)) == 0U)
			continue;
		interface_words(cs_in, shared + slot->stream[i].input, sizeof(cs_in));
		cs_in[0] = TASK_CS_START | (cs_in[0] & TASK_CS_OOM);
		memcpy(shared + slot->stream[i].input, cs_in, sizeof(cs_in));
		ops->clean(shared + slot->stream[i].input, sizeof(cs_in));
	}
	csg_in[0] = csg_req;
	csg_in[2] = cs_doorbell;
	memcpy(shared + slot->group.input, csg_in, sizeof(csg_in));
	ops->clean(shared + slot->group.input, sizeof(csg_in));
	glb_in[2] = global_doorbell;
	memcpy(shared + interfaces.global.input, glb_in, sizeof(glb_in));
	ops->clean(shared + interfaces.global.input, sizeof(glb_in));
	step = 9U;
	if (!ops->notify(root))
		goto failed;
	step = 10U;
	start = ops->clock();
	do {
		ops->invalidate(shared + interfaces.global.output, sizeof(glb_out));
		ops->invalidate(shared + slot->group.output, sizeof(csg_out));
		interface_words(glb_out, shared + interfaces.global.output, sizeof(glb_out));
		interface_words(csg_out, shared + slot->group.output, sizeof(csg_out));
		bool streams_acked = true;

		unacked = 0U;

		if (glb_out[4] != 0U)
			goto failed;
		for (unsigned int i = 0U; i < interfaces.streams; i++) {
			unsigned int expected = (cs_mask & (1U << i)) != 0U ? 1U : 0U;

			stream_status(ops, shared + slot->stream[i].output, &cs_out);
			if ((cs_out.ack & TASK_CS_ERRORS) != 0U || cs_out.fault != 0U || cs_out.fatal != 0U)
				goto failed;
			if (i == queue)
				active_ack = cs_out.ack;
			if ((cs_out.ack & 7U) != expected)
				unacked |= 1U << i;
			streams_acked &= (cs_out.ack & 7U) == expected;
		}
		if (((glb_out[2] ^ global_doorbell) & csg_mask) == 0U &&
		    ((csg_out[2] ^ cs_doorbell) & cs_mask) == 0U &&
		    ((csg_out[0] ^ csg_req) & TASK_CSG_ACK_MASK) == 0U) {
			/* The compound Client operation promises launch acceptance,
			 * not completion. A genuinely suspended group can retain exact
			 * START stream snapshots. With all new parent/group/doorbell
			 * ACKs and every stream matching, no extra STATUS is needed to
			 * establish that acceptance. Fresh COMPLETE/PROGRESS STATUS,
			 * errors, quiescence and cache/retirement remain mandatory.
			 * A stale STOP snapshot falls back to the original handshake.
			 */
			if (accept_resume && group->suspended && streams_acked && !status_requested)
				goto launch_checked;
			if (!status_requested) {
				/* START/doorbell ACKs do not refresh the CS snapshot.
				 * Request STATUS_UPDATE only after START was accepted, then
				 * require its new ACK before trusting the stream states.
				 * The existing start-attempt hold covers this publication too.
				 */
				csg_req ^= TASK_STATUS_UPDATE;
				global_doorbell ^= csg_mask;
				csg_in[0] = csg_req;
				glb_in[2] = global_doorbell;
				memcpy(shared + slot->group.input, csg_in, sizeof(csg_in));
				ops->clean(shared + slot->group.input, sizeof(csg_in));
				memcpy(shared + interfaces.global.input, glb_in, sizeof(glb_in));
				ops->clean(shared + interfaces.global.input, sizeof(glb_in));
				status_requested = true;
				if (!ops->notify(root))
					goto failed;
				continue;
			}
			if (((csg_out[0] ^ csg_req) & TASK_STATUS_UPDATE) != 0U || !streams_acked)
				continue;
launch_checked:
			step = 11U;
			if (memory_ops->check_running_as != NULL) {
				gpu_private_context_check_running(memory_ops, service, owner, context,
					root, &config, &checked);
			} else {
				if (!ops->configuration(root, &config))
					goto failed;
				gpu_private_context_prepare(memory_ops, service, owner, context, root, &checked);
			}
			if (checked.status != GPU_PRIVATE_SUCCESS || checked.value[0] != csg_in[20])
				goto failed;
			task->started = true;
			group->state = GPU_FIRMWARE_GROUP_STARTED;
			if (accept_resume && group->suspended) {
				if (status_requested)
					resume_fallback++;
				else
					resume_fast++;
			}
			goto accepted;
		}
	} while (ops->clock() - start < config.ack_timeout_ticks);
	/* Timed out: publication is not retried or treated as cancelled. */
failed:
	/* Fixed protocol bits only: never print Client addresses, roots, command
	 * pointers or exception data. Failure remains quarantined and retained.
	 */
	if (step == 10U)
		(void)ops->configuration(root, &config); /* Diagnose faults even without a CS ACK. */
	if (step == 10U)
		ERROR("GPU START wait cs=%x child=%x csg=%x active=%x\n", unacked,
			(csg_out[2] ^ cs_doorbell) & cs_mask,
			(csg_out[0] ^ csg_req) & (TASK_CSG_ACK_MASK | TASK_STATUS_UPDATE), active_ack);
	if (step >= 6U)
		ERROR("GPU START fail step=%u cs=%x fault=%x fatal=%x\n", step, cs_out.ack,
			cs_out.fault & 255U, cs_out.fatal & 255U);
	else
		ERROR("GPU START fail step=%u attempted=%u\n", step, task->start_attempted);
	if (step >= 5U)
		ERROR("GPU START db=%x/%x child=%x/%x csg=%x/%x halt=%x\n",
			glb_in[2], glb_out[2], csg_in[2], csg_out[2],
			csg_in[0], csg_out[0], glb_out[4]);
	group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
	return;
accepted:
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = GPU_FIRMWARE_GROUP_STARTED;
	result->value[1] = queue;
}

void gpu_firmware_task_start(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long context, unsigned long handle,
		unsigned long token, struct gpu_private_result *result)
{
	task_start(ops, memory_ops, service, owner, context, handle, token, false, false, result);
}

static bool heap_live(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, struct fw_task *task, struct fw_group *group)
{
	struct gpu_private_result checked;

	if (state != GPU_FIRMWARE_CONFIGURED || group == NULL || !task->ready ||
	    !task->started || task->stop_attempted || task->status_pending ||
	    task->completed || group->state != GPU_FIRMWARE_GROUP_STARTED ||
	    group->prepared_task != task->handle)
		return false;
	/* Started-token replay checks real roots, binding, every CS, and the
	 * global/child handshakes. It performs no publication or MMIO writes.
	 */
	gpu_firmware_task_start(ops, memory_ops, service, owner, group->context,
		group->handle, task->handle, &checked);
	return checked.status == GPU_PRIVATE_SUCCESS;
}

static bool heap_output(const struct gpu_firmware_ops *ops, struct fw_task *task,
		struct fw_group *group, unsigned int queue, uint32_t output[54])
{
	unsigned char *shared = runtime_pages[section_page[interfaces.section]];
	struct fw_iface *stream = &interfaces.slots[group->hardware_csg].stream[queue];
	uint32_t request;
	unsigned long address;

	ops->invalidate(shared + stream->output, FW_STREAM_OUTPUT_SIZE);
	memcpy(output, shared + stream->output, FW_STREAM_OUTPUT_SIZE);
	memcpy(&request, shared + stream->input, sizeof(request));
	if (((request ^ output[0]) & TASK_CS_OOM) == 0U)
		return false;
	address = output[52] | ((unsigned long)output[53] << 32U);
	if (task->queue_count[queue] == 0U || (address & 63UL) != 0UL || address == 0UL ||
	    address >= GPU_PRIVATE_CONTROL_GPU_VA || output[51] > output[49] ||
	    output[49] >= output[48]) {
		group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
		return false;
	}
	return true;
}

void gpu_firmware_task_heap_event(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long token, struct gpu_private_result *result)
{
	struct fw_task *task = task_lookup(owner, token);
	struct fw_group *group;
	uint32_t output[FW_STREAM_OUTPUT_SIZE / 4U];

	init_result(result);
	if (!authenticated(service) || service == owner || task == NULL)
		return;
	group = group_lookup(owner, task->resources.group);
	result->status = GPU_PRIVATE_STATE;
	if (!heap_live(ops, memory_ops, service, owner, task, group))
		return;
	if (task->heap.phase == HEAP_PUBLISHED)
		return; /* Uncertain publication is never rediscovered or replayed. */
	if (task->heap.phase != 0U && task->heap.phase != HEAP_ACCEPTED) {
		if (!heap_output(ops, task, group, task->heap.queue, output) ||
		    ((output[0] >> 26U) & 1U) != task->heap.ack ||
		    (output[52] | ((unsigned long)output[53] << 32U)) != task->heap.address ||
		    output[48] != task->heap.vt_start) {
			group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
			return;
		}
		goto found;
	}
	for (unsigned int q = 0U; q < interfaces.streams; q++) {
		if (!heap_output(ops, task, group, q, output)) {
			if (group->state != GPU_FIRMWARE_GROUP_STARTED)
				return;
			continue;
		}
		if (heap_generation == ~0UL)
			return;
		memset(&task->heap, 0, sizeof(task->heap));
		task->heap.id = ++heap_generation;
		task->heap.address = output[52] | ((unsigned long)output[53] << 32U);
		task->heap.vt_start = output[48];
		task->heap.queue = (uint8_t)q;
		task->heap.ack = (uint8_t)((output[0] >> 26U) & 1U);
		task->heap.phase = HEAP_OBSERVED;
		goto found;
	}
	result->status = GPU_PRIVATE_SUCCESS; /* No pending event: all zeros. */
	return;
found:
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = task->heap.id;
	result->value[1] = task->heap.address;
	/* Fragment work can advance while this queue is stalled. Report fresh
	 * validated counts, rather than retaining duplicate stale counters.
	 */
	result->value[2] = (output[48] - output[51]) | ((unsigned long)(output[49] - output[51]) << 32U);
	result->value[3] = task->heap.queue;
}

void gpu_firmware_task_heap_grow(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long token, unsigned long event,
		unsigned long object, unsigned long iova, struct gpu_private_result *result)
{
	struct fw_task *task = task_lookup(owner, token);
	struct fw_group *group;
	struct gpu_private_result checked;
	struct gpu_firmware_config config;
	struct fw_slot *slot;
	struct fw_heap_event *heap;
	unsigned char *shared;
	unsigned long root, chunk = 0UL, pages = 0UL, start;
	uint32_t output[FW_STREAM_OUTPUT_SIZE / 4U], cs[FW_STREAM_INPUT_SIZE / 4U];
	uint32_t csg[FW_GROUP_INPUT_SIZE / 4U], global[FW_GLOBAL_INPUT_SIZE / 4U];
	uint32_t group_out[FW_GROUP_OUTPUT_SIZE / 4U], glb_out[FW_GLOBAL_OUTPUT_SIZE / 4U];
	uint32_t parent, child;

	init_result(result);
	if (!authenticated(service) || service == owner || task == NULL || event == 0UL ||
	    event != task->heap.id || (object == 0UL && iova != 0UL))
		return;
	heap = &task->heap;
	if (heap->phase != HEAP_OBSERVED && (heap->object != object || heap->iova != iova))
		return; /* A continuation never substitutes another BO or VA. */
	group = group_lookup(owner, task->resources.group);
	result->status = GPU_PRIVATE_STATE;
	if (!heap_live(ops, memory_ops, service, owner, task, group))
		return;
	root = ops->address(runtime_tables[0]);
	if (heap->phase == HEAP_ACCEPTED) {
		if (object != 0UL) {
			gpu_private_bo_inspect(service, owner, object, &checked);
			if (checked.status != GPU_PRIVATE_SUCCESS)
				return;
			pages = checked.value[0] / GPU_PRIVATE_PAGE_SIZE;
		}
		goto accepted; /* Exact retry checks live state, with no publication. */
	}
	if (heap->phase == HEAP_PUBLISHED ||
	    !heap_output(ops, task, group, heap->queue, output) ||
	    ((output[0] >> 26U) & 1U) != heap->ack ||
	    (output[52] | ((unsigned long)output[53] << 32U)) != heap->address ||
	    output[48] != heap->vt_start)
		goto failed;
	if (object != 0UL) {
		gpu_private_bo_inspect(service, owner, object, &checked);
		pages = checked.value[0] / GPU_PRIVATE_PAGE_SIZE;
		if (checked.status != GPU_PRIVATE_SUCCESS || pages < 32UL || pages > 2048UL ||
		    (checked.value[1] & 3UL) != 3UL || (iova & 4095UL) != 0UL ||
		    iova >= GPU_PRIVATE_CONTROL_GPU_VA ||
		    pages > (GPU_PRIVATE_CONTROL_GPU_VA - iova) / GPU_PRIVATE_PAGE_SIZE)
			return;
		if (heap->phase == HEAP_OBSERVED) {
			heap->object = object;
			heap->iova = iova;
			heap->phase = HEAP_MAPPING;
		}
		gpu_private_task_extend(memory_ops, service, owner, group->context, token,
			object, iova, root, &checked);
		if (checked.status != GPU_PRIVATE_SUCCESS && checked.status != GPU_PRIVATE_INCOMPLETE)
			goto failed;
		if (checked.status == GPU_PRIVATE_INCOMPLETE) {
			result->status = GPU_PRIVATE_INCOMPLETE;
			result->value[1] = event;
			result->value[2] = checked.value[0];
			result->value[3] = heap->queue;
			return;
		}
		chunk = iova | pages; /* Native chunk address + size in low 12 bits. */
	}
	/* No new root, firmware pointer, raw HPA or command buffer is accepted.
	 * object=VA=0 is native ENOMEM fallback, before any extension starts.
	 */
	if (!heap_live(ops, memory_ops, service, owner, task, group) ||
	    !ops->configuration(root, &config) || config.ack_timeout_ticks == 0UL)
		goto failed;
	if (!heap_output(ops, task, group, heap->queue, output) ||
	    ((output[0] >> 26U) & 1U) != heap->ack ||
	    (output[52] | ((unsigned long)output[53] << 32U)) != heap->address ||
	    output[48] != heap->vt_start)
		goto failed;
	shared = runtime_pages[section_page[interfaces.section]];
	slot = &interfaces.slots[group->hardware_csg];
	parent = 1U << group->hardware_csg;
	child = 1U << heap->queue;
	memcpy(cs, shared + slot->stream[heap->queue].input, sizeof(cs));
	memcpy(csg, shared + slot->group.input, sizeof(csg));
	memcpy(global, shared + interfaces.global.input, sizeof(global));
	ops->invalidate(shared + slot->group.output, sizeof(group_out));
	ops->invalidate(shared + interfaces.global.output, sizeof(glb_out));
	memcpy(group_out, shared + slot->group.output, sizeof(group_out));
	memcpy(glb_out, shared + interfaces.global.output, sizeof(glb_out));
	cs[8] = cs[10] = (uint32_t)chunk;
	cs[9] = cs[11] = (uint32_t)(chunk >> 32U);
	cs[0] = (cs[0] & ~TASK_CS_OOM) | ((uint32_t)heap->ack << 26U);
	csg[2] = (csg[2] & ~child) | ((group_out[2] ^ child) & child);
	global[2] = (global[2] & ~parent) | ((glb_out[2] ^ parent) & parent);
	heap->phase = HEAP_PUBLISHED;
	group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
	memcpy(shared + slot->stream[heap->queue].input, cs, sizeof(cs));
	ops->clean(shared + slot->stream[heap->queue].input, sizeof(cs));
	memcpy(shared + slot->group.input, csg, sizeof(csg));
	ops->clean(shared + slot->group.input, sizeof(csg));
	memcpy(shared + interfaces.global.input, global, sizeof(global));
	ops->clean(shared + interfaces.global.input, sizeof(global));
	if (!ops->notify(root))
		return;
	start = ops->clock();
	do {
		ops->invalidate(shared + slot->group.output, sizeof(group_out));
		ops->invalidate(shared + interfaces.global.output, sizeof(glb_out));
		memcpy(group_out, shared + slot->group.output, sizeof(group_out));
		memcpy(glb_out, shared + interfaces.global.output, sizeof(glb_out));
		if (glb_out[4] != 0U)
			return;
		if (((global[2] ^ glb_out[2]) & parent) != 0U ||
		    ((csg[2] ^ group_out[2]) & child) != 0U)
			continue;
		if (!ops->configuration(root, &config))
			return;
		group->state = GPU_FIRMWARE_GROUP_STARTED;
		if (!heap_live(ops, memory_ops, service, owner, task, group))
			goto failed;
		heap->phase = HEAP_ACCEPTED;
		goto accepted;
	} while (ops->clock() - start < config.ack_timeout_ticks);
	return;
failed:
	group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
	return;
accepted:
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = 1UL;
	result->value[1] = event;
	result->value[2] = pages;
	result->value[3] = heap->queue;
}



void gpu_firmware_task_publish(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long token, unsigned long members,
		struct gpu_private_result *result)
{
	struct fw_task *task = task_lookup(owner, token);
	struct fw_group *group;
	struct gpu_private_result checked;
	struct gpu_firmware_config config;
	uint32_t counts[GPU_FIRMWARE_STREAMS] = {0};
	uint32_t blocked = 0U, changed = 0U;
	unsigned int step = 1U;
	uint32_t input[4], glb_in[FW_GLOBAL_INPUT_SIZE / 4U], glb_out[FW_GLOBAL_OUTPUT_SIZE / 4U];
	uint32_t csg_in[FW_GROUP_INPUT_SIZE / 4U], csg_out[FW_GROUP_OUTPUT_SIZE / 4U];
	unsigned long root, start;
	unsigned char *shared;
	struct fw_slot *slot;
	uint32_t parent, doorbell, child;

	init_result(result);
	if (!authenticated(service) || service == owner || task == NULL ||
	    (members & ~((1UL << task->count) - 1UL)) != 0UL ||
	    (task->published_members & ~members) != 0UL)
		return;
	/* A later array member on another queue can run first. A later member
	 * on the SAME queue cannot bypass an unpublished predecessor.
	 */
	for (unsigned int i = 0U; i < task->count; i++) {
		unsigned int q = i == 0U ? task->resources.queue : task->extra[i - 1U].queue;

		if ((members & (1UL << i)) == 0UL)
			blocked |= 1U << q;
		else if ((blocked & (1U << q)) != 0U)
			return;
		else
			counts[q]++;
	}
	group = group_lookup(owner, task->resources.group);
	result->status = GPU_PRIVATE_STATE;
	if (state != GPU_FIRMWARE_CONFIGURED || group == NULL || !task->ready ||
	    !task->preparing || task->stop_attempted || task->status_pending || task->completed ||
	    group->prepared_task != token ||
	    (group->state != GPU_FIRMWARE_GROUP_PREPARED && group->state != GPU_FIRMWARE_GROUP_STARTED) ||
	    ops == NULL || ops->address == NULL || ops->configuration == NULL ||
	    ops->clean == NULL || ops->invalidate == NULL || ops->notify == NULL || ops->clock == NULL ||
	    memory_ops == NULL || memory_ops->read_page == NULL || memory_ops->write_page == NULL)
		return;
	if (task->started)
		gpu_firmware_task_start(ops, memory_ops, service, owner, group->context,
			group->handle, token, &checked);
	else
		gpu_firmware_task_prepare(ops, memory_ops, service, owner, group->context,
			group->handle, token, &checked);
	if (checked.status != GPU_PRIVATE_SUCCESS) {
		ERROR("GPU PUBLISH context status=%lu\n", checked.status);
		goto failed;
	}
	step = 2U;
	root = ops->address(runtime_tables[0]);
	if (!ops->configuration(root, &config) || config.ack_timeout_ticks == 0UL)
		goto failed;
	/* Preflight every queue before changing any INSERT. Never repair an
	 * unexpected old cursor or trust a service-provided queue/address.
	 */
	for (unsigned int q = 0U; q < group->streams; q++) {
		unsigned int io = group->first + (interfaces.suspend_size + 4095U) / 4096U + q * 2U;
		unsigned int old = task_published_count(task, q);

		uint64_t base;
		bool read = queue_base(group, q, &base) &&
			read_control(memory_ops, io, 0U, input, sizeof(input));
		uint32_t mismatch = !read ? 16U :
			(uint32_t)((input[0] | ((uint64_t)input[1] << 32U)) !=
				base + old * sizeof(task->resources.instructions)) |
			(((input[2] | ((uint64_t)input[3] << 32U)) != queue_origin(group, q)) << 1U);

		if (mismatch != 0U) {
			ERROR("GPU PUBLISH cursor q=%u mismatch=%x\n", q, mismatch);
			goto failed;
		}
		if (counts[q] != old)
			changed |= 1U << q;
	}
	step = 3U;
	shared = runtime_pages[section_page[interfaces.section]];
	slot = &interfaces.slots[group->hardware_csg];
	parent = 1U << group->hardware_csg;
	memcpy(glb_in, shared + interfaces.global.input, sizeof(glb_in));
	memcpy(csg_in, shared + slot->group.input, sizeof(csg_in));
	ops->invalidate(shared + interfaces.global.output, sizeof(glb_out));
	ops->invalidate(shared + slot->group.output, sizeof(csg_out));
	memcpy(glb_out, shared + interfaces.global.output, sizeof(glb_out));
	memcpy(csg_out, shared + slot->group.output, sizeof(csg_out));
	if (glb_out[4] != 0U || ((glb_in[0] ^ glb_out[0]) & GLB_CONFIG_MASK) != 0U ||
	    ((glb_in[2] ^ glb_out[2]) & parent) != 0U ||
	    ((csg_in[2] ^ csg_out[2]) & task->queue_mask) != 0U ||
	    ((csg_in[0] ^ csg_out[0]) & (TASK_CSG_ACK_MASK | (1U << 5U))) != 0U) {
		ERROR("GPU PUBLISH ack glb=%x parent=%x child=%x csg=%x halt=%x\n",
			(glb_in[0] ^ glb_out[0]) & GLB_CONFIG_MASK,
			(glb_in[2] ^ glb_out[2]) & parent,
			(csg_in[2] ^ csg_out[2]) & task->queue_mask,
			(csg_in[0] ^ csg_out[0]) & (TASK_CSG_ACK_MASK | TASK_STATUS_UPDATE), glb_out[4]);
		goto failed;
	}
	if (changed == 0U)
		goto success; /* Exact replay still checks parent/child/status ACKs. */
	child = (csg_in[2] & ~changed) | ((csg_out[2] ^ changed) & changed);
	doorbell = (glb_in[2] & ~parent) | ((glb_out[2] ^ parent) & parent);
	/* INSERT can be consumed before MMIO. Retain the cumulative target and
	 * quarantine BEFORE the first write; uncertain publication is not retried.
	 */
	group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
	task->published_members = (uint32_t)members;
	for (unsigned int q = 0U; q < group->streams; q++) {
		unsigned int io = group->first + (interfaces.suspend_size + 4095U) / 4096U + q * 2U;
		uint64_t base, insert;

		if (!queue_base(group, q, &base))
			return;
		insert = base + counts[q] * sizeof(task->resources.instructions);

		if ((changed & (1U << q)) != 0U &&
		    !write_control(memory_ops, io, 0U, &insert, sizeof(insert)))
			return;
	}
	if (!task->started) {
		if (!ops->configuration(root, &config))
			return;
		gpu_private_context_prepare(memory_ops, service, owner, group->context, root, &checked);
		if (checked.status != GPU_PRIVATE_SUCCESS)
			return;
		group->state = GPU_FIRMWARE_GROUP_PREPARED;
		goto success;
	}
	csg_in[2] = child;
	memcpy(shared + slot->group.input, csg_in, sizeof(csg_in));
	ops->clean(shared + slot->group.input, sizeof(csg_in));
	glb_in[2] = doorbell;
	memcpy(shared + interfaces.global.input, glb_in, sizeof(glb_in));
	ops->clean(shared + interfaces.global.input, sizeof(glb_in));
	if (!ops->notify(root))
		return;
	start = ops->clock();
	do {
		ops->invalidate(shared + interfaces.global.output, sizeof(glb_out));
		ops->invalidate(shared + slot->group.output, sizeof(csg_out));
		memcpy(glb_out, shared + interfaces.global.output, sizeof(glb_out));
		memcpy(csg_out, shared + slot->group.output, sizeof(csg_out));
		if (glb_out[4] != 0U)
			return;
		if (((glb_out[2] ^ doorbell) & parent) == 0U &&
		    ((csg_out[2] ^ child) & changed) == 0U) {
			group->state = GPU_FIRMWARE_GROUP_STARTED;
			gpu_firmware_task_start(ops, memory_ops, service, owner, group->context,
				group->handle, token, &checked);
			if (checked.status != GPU_PRIVATE_SUCCESS)
				goto failed;
			goto success;
		}
	} while (ops->clock() - start < config.ack_timeout_ticks);
	return;
failed:
	ERROR("GPU PUBLISH fail step=%u\n", step);
	group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
	return;
success:
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = task->published_members;
	result->value[1] = task->count;
	result->value[2] = task->queue_mask;
}

static void task_quiesce(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long context, unsigned long handle,
		unsigned long token, unsigned long started_root,
		const struct gpu_firmware_config *started_config,
		struct gpu_private_result *result)
{
	struct fw_task *task = task_lookup_raw(owner, token);
	struct fw_group *group = group_lookup(owner, handle);
	struct gpu_private_result checked;
	struct gpu_firmware_config config;
	unsigned char *shared;
	struct fw_slot *slot;
	unsigned long root, start;
	unsigned int csg, queue, step = 1U;
	uint32_t parent, child;
	uint32_t glb_in[FW_GLOBAL_INPUT_SIZE / 4U], glb_out[FW_GLOBAL_OUTPUT_SIZE / 4U];
	uint32_t csg_in[FW_GROUP_INPUT_SIZE / 4U], csg_out[FW_GROUP_OUTPUT_SIZE / 4U];
	struct fw_stream_status cs_out;
	uint32_t cs_in[FW_STREAM_INPUT_SIZE / 4U];

	init_result(result);
	if (!authenticated(service) || group == NULL || task == NULL ||
	    group->context != context || task->resources.context != context ||
	    task->resources.group != handle)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (task->launch_pending && !task->start_attempted) {
		/* An explicit service abort revokes a pending selection even before
		 * the Client has handed off its data. Do not claim hardware quiescence
		 * or release partly acquired cache/backing holds; trusted reset owns
		 * their recovery. Every later READY/START sees quarantine.
		 */
		task->launch_pending = false;
		group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
		return;
	}
	if (state != GPU_FIRMWARE_CONFIGURED || !task->started || !task->ready ||
	    group->prepared_task != token || !task->start_attempted ||
	    ops == NULL || ops->address == NULL || ops->configuration == NULL ||
	    ops->clean == NULL || ops->invalidate == NULL || ops->notify == NULL ||
	    ops->clock == NULL || memory_ops == NULL || memory_ops->detach_as == NULL ||
	    (group->state != GPU_FIRMWARE_GROUP_STARTED && group->state != GPU_FIRMWARE_GROUP_QUIESCED))
		return;
	/* An AS is shared by all groups in one GPUVM. Stopping one CSG must not
	 * disable an AS still installed in another prepared/running group.
	 */
	for (unsigned int i = 0U; i < GPU_FIRMWARE_LOGICAL_GROUPS; i++)
		if (&groups[i] != group && groups[i].owner == owner &&
		    groups[i].context == context && groups[i].prepared_task != 0UL)
			return;
	csg = group->hardware_csg;
	queue = task->resources.queue;
	if (csg >= interfaces.groups || hardware_groups[csg] != handle || queue >= group->streams)
		goto failed;
	root = started_config != NULL ? started_root : ops->address(runtime_tables[0]);
	if (started_config != NULL) {
		/* Internal COMPLETE path only: its post-read START replay just
		 * validated this exact task/root and every stream. No callback,
		 * input publication or unlock may separate that replay from here.
		 * The timeout came from this same observation's trusted config.
		 */
		if (!task->preserve || task->stop_attempted || task->quiesced ||
		    started_config->ack_timeout_ticks == 0UL)
			goto failed;
		config = *started_config;
	} else if (!task->quiesced &&
	    (!ops->configuration(root, &config) || config.ack_timeout_ticks == 0UL))
		goto failed;
	if (!task->stop_attempted) {
		/* START replay is a read-only check of the live root and every stream,
		 * never a new launch. It must precede the first stop publication.
		 */
		if (started_config == NULL) {
			task_start(ops, memory_ops, service, owner, context, handle, token, false, true, &checked);
			if (checked.status != GPU_PRIVATE_SUCCESS)
				goto failed;
		}
	} else if (!task->quiesced || group->state != GPU_FIRMWARE_GROUP_QUIESCED) {
		goto failed;
	}
	step = 2U;
	shared = runtime_pages[section_page[interfaces.section]];
	slot = &interfaces.slots[csg];
	parent = 1U << csg;
	child = group->active_queues;
	interface_words(glb_in, shared + interfaces.global.input, sizeof(glb_in));
	interface_words(csg_in, shared + slot->group.input, sizeof(csg_in));
	ops->invalidate(shared + interfaces.global.output, sizeof(glb_out));
	ops->invalidate(shared + slot->group.output, sizeof(csg_out));
	interface_words(glb_out, shared + interfaces.global.output, sizeof(glb_out));
	interface_words(csg_out, shared + slot->group.output, sizeof(csg_out));
	if (glb_out[4] != 0U || csg_in[20] != group->hardware_as ||
	    ((glb_in[0] ^ glb_out[0]) & GLB_CONFIG_MASK) != 0U ||
	    ((glb_in[2] ^ glb_out[2]) & parent) != 0U ||
	    ((csg_in[2] ^ csg_out[2]) & child) != 0U)
		goto failed;
	if (task->quiesced) {
		if ((csg_in[0] & 7U) != (task->preserve ? 2U : 0U) ||
		    ((csg_in[0] ^ csg_out[0]) & (TASK_CSG_ACK_MASK | TASK_STATUS_UPDATE)) != 0U)
			goto failed;
		for (unsigned int i = 0U; i < interfaces.streams; i++) {
			uint32_t req;

			interface_words(&req, shared + slot->stream[i].input, sizeof(req));
			stream_status(ops, shared + slot->stream[i].output, &cs_out);
			if ((req & 7U) != 0U ||
			    (task->preserve ? (cs_out.ack & 7U) > 1U : (cs_out.ack & 7U) != 0U) ||
			    (cs_out.ack & TASK_CS_ERRORS) != 0U ||
			    cs_out.fault != 0U || cs_out.fatal != 0U)
				goto failed;
		}
		goto detach;
	}
	if (task->preserve) {
		step = 3U;
		/* Successful batches retain the native CS register/heap/exception
		 * state. Only an idle, fully observed batch reaches this branch.
		 * SUSPEND ACK is the native nonexecution barrier; no subsequent
		 * TERMINATE or CS STOP notification is valid on this suspended slot.
		 * A later task RESUMEs this group's protected buffer only.
		 */
		task->stop_attempted = true;
		group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
		csg_in[0] = (csg_in[0] & ~7U) | 2U;
		glb_in[2] = (glb_in[2] & ~parent) | ((glb_out[2] ^ parent) & parent);
		memcpy(shared + slot->group.input, csg_in, sizeof(csg_in));
		ops->clean(shared + slot->group.input, sizeof(csg_in));
		memcpy(shared + interfaces.global.input, glb_in, sizeof(glb_in));
		ops->clean(shared + interfaces.global.input, sizeof(glb_in));
		if (!ops->notify(root))
			goto failed;
		step = 4U;
		start = ops->clock();
		do {
			ops->invalidate(shared + interfaces.global.output, sizeof(glb_out));
			ops->invalidate(shared + slot->group.output, sizeof(csg_out));
			interface_words(glb_out, shared + interfaces.global.output, sizeof(glb_out));
			interface_words(csg_out, shared + slot->group.output, sizeof(csg_out));
			if (glb_out[4] != 0U)
				goto failed;
			if (((glb_in[2] ^ glb_out[2]) & parent) == 0U &&
			    ((csg_in[0] ^ csg_out[0]) & (TASK_CSG_ACK_MASK | TASK_STATUS_UPDATE)) == 0U)
				break;
		} while (ops->clock() - start < config.ack_timeout_ticks);
		if (((glb_in[2] ^ glb_out[2]) & parent) != 0U ||
		    ((csg_in[2] ^ csg_out[2]) & child) != 0U ||
		    ((csg_in[0] ^ csg_out[0]) & (TASK_CSG_ACK_MASK | TASK_STATUS_UPDATE)) != 0U)
			goto failed;
		/* Like native cs_slot_reset_locked(), reset only CS requests after
		 * SUSPEND. The group/parent ACK and root remain mandatory, and all
		 * stream errors are checked before the AS flush/detach barrier.
		 */
		for (unsigned int i = 0U; i < interfaces.streams; i++) {
			stream_status(ops, shared + slot->stream[i].output, &cs_out);
			if ((cs_out.ack & 7U) > 1U || (cs_out.ack & TASK_CS_ERRORS) != 0U ||
			    cs_out.fault != 0U || cs_out.fatal != 0U)
				goto failed;
			interface_words(cs_in, shared + slot->stream[i].input, sizeof(cs_in));
			cs_in[0] &= ~7U;
			memcpy(shared + slot->stream[i].input, cs_in, sizeof(cs_in));
			ops->clean(shared + slot->stream[i].input, sizeof(cs_in));
		}
		goto detach;
	}
	step = 5U;
	/* MCU may observe memory without MMIO. Record ambiguity before CS STOP. */
	task->stop_attempted = true;
	group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
	csg_in[0] &= ~7U;
	csg_in[2] = (csg_in[2] & ~child) | ((csg_out[2] ^ child) & child);
	glb_in[2] = (glb_in[2] & ~parent) | ((glb_out[2] ^ parent) & parent);
	for (unsigned int i = 0U; i < group->streams; i++) {
		if ((child & (1U << i)) == 0U)
			continue;
		interface_words(cs_in, shared + slot->stream[i].input, sizeof(cs_in));
		cs_in[0] &= ~7U;
		memcpy(shared + slot->stream[i].input, cs_in, sizeof(cs_in));
		ops->clean(shared + slot->stream[i].input, sizeof(cs_in));
	}
	memcpy(shared + slot->group.input, csg_in, sizeof(csg_in));
	ops->clean(shared + slot->group.input, sizeof(csg_in));
	memcpy(shared + interfaces.global.input, glb_in, sizeof(glb_in));
	ops->clean(shared + interfaces.global.input, sizeof(glb_in));
	if (!ops->notify(root))
		goto failed;
	step = 6U;
	start = ops->clock();
	do {
		ops->invalidate(shared + interfaces.global.output, sizeof(glb_out));
		ops->invalidate(shared + slot->group.output, sizeof(csg_out));
		interface_words(glb_out, shared + interfaces.global.output, sizeof(glb_out));
		interface_words(csg_out, shared + slot->group.output, sizeof(csg_out));
		bool streams_acked = true;

		if (glb_out[4] != 0U)
			goto failed;
		for (unsigned int i = 0U; i < interfaces.streams; i++) {
			stream_status(ops, shared + slot->stream[i].output, &cs_out);
			if ((cs_out.ack & TASK_CS_ERRORS) != 0U || cs_out.fault != 0U || cs_out.fatal != 0U)
				goto failed;
			streams_acked &= (cs_out.ack & 7U) == 0U;
		}
		if (((glb_in[2] ^ glb_out[2]) & parent) == 0U &&
		    ((csg_in[2] ^ csg_out[2]) & child) == 0U &&
		    ((csg_in[0] ^ csg_out[0]) & TASK_CSG_ACK_MASK) == 0U && streams_acked)
			goto detach;
	} while (ops->clock() - start < config.ack_timeout_ticks);
	goto failed;
detach:
	step = 7U;
	/* Detached replay validates the full live configuration in detach_as.
	 * The first STOP still uses the configuration checks around its handshake.
	 */
	if (!task->quiesced && !ops->configuration(root, &config))
		goto failed;
	gpu_private_context_quiesce(memory_ops, service, owner, context, token, root, &checked);
	if (checked.status != GPU_PRIVATE_SUCCESS)
		goto failed;
	task->quiesced = true;
	group->state = GPU_FIRMWARE_GROUP_QUIESCED;
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = GPU_FIRMWARE_GROUP_QUIESCED;
	result->value[1] = queue;
	return;
failed:
	ERROR("GPU QUIESCE fail step=%u preserve=%u\n", step, task->preserve);
	if (step >= 2U) {
		uint32_t streams = 0U;

		for (unsigned int i = 0U; i < interfaces.streams; i++) {
			uint32_t req, ack;

			interface_words(&req, shared + slot->stream[i].input, sizeof(req));
			ops->invalidate(shared + slot->stream[i].output, sizeof(ack));
			interface_words(&ack, shared + slot->stream[i].output, sizeof(ack));
			if (((req | ack) & 7U) != 0U) streams |= 1U << i;
		}
		ERROR("GPU QUIESCE csg=%x/%x parent=%x child=%x streams=%x\n",
			csg_in[0], csg_out[0], (glb_in[2] ^ glb_out[2]) & parent,
			(csg_in[2] ^ csg_out[2]) & child, streams);
	}
	group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
}

void gpu_firmware_task_quiesce(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long context, unsigned long handle,
		unsigned long token, struct gpu_private_result *result)
{
	init_result(result);
	if (task_lookup(owner, token) == NULL)
		return;
	/* No external caller can provide a prior START proof. */
	task_quiesce(ops, memory_ops, service, owner, context, handle, token, 0UL, NULL, result);
}

static void task_observe(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long token, bool finish, bool internal,
		struct gpu_private_result *result)
{
	struct fw_task *task = internal ? task_lookup_raw(owner, token) : task_lookup(owner, token);
	struct fw_group *group;
	struct gpu_private_result checked;
	struct gpu_firmware_config config;
	unsigned int csg, sync_page, step = 1U;
	bool pending_work = false;
	unsigned long root, start;
	unsigned char *shared;
	struct fw_slot *slot;
	uint32_t parent, wanted, doorbell;
	uint32_t glb_in[FW_GLOBAL_INPUT_SIZE / 4U], glb_out[FW_GLOBAL_OUTPUT_SIZE / 4U];
	uint32_t csg_in[FW_GROUP_INPUT_SIZE / 4U], csg_out[FW_GROUP_OUTPUT_SIZE / 4U];
	struct fw_stream_status cs_out;
	uint32_t input[4], output[4], completion[4];
	uint64_t insert, extract, sequence;
	uint32_t observed_members = 0U;

	init_result(result);
	if (!authenticated(service) || service == owner || task == NULL)
		return;
	group = group_lookup(owner, task->resources.group);
	result->status = GPU_PRIVATE_STATE;
	if (state != GPU_FIRMWARE_CONFIGURED || group == NULL || !task->started || !task->ready ||
	    group->prepared_task != token || ops == NULL || ops->address == NULL ||
	    ops->configuration == NULL || ops->clean == NULL || ops->invalidate == NULL ||
	    ops->notify == NULL || ops->clock == NULL || memory_ops == NULL ||
	    memory_ops->read_page == NULL || memory_ops->detach_as == NULL)
		return;
	if (task->completed) {
		/* Exact token replay cannot turn a later root/firmware fault into a
		 * cached success. It performs no STATUS_UPDATE or data-page access.
		 */
		task_quiesce(ops, memory_ops, service, owner, group->context,
			group->handle, token, 0UL, NULL, &checked);
		if (checked.status != GPU_PRIVATE_SUCCESS)
			return;
		goto success;
	}
	if (task->stop_attempted || task->status_pending || group->state != GPU_FIRMWARE_GROUP_STARTED)
		return; /* An explicit abort/ambiguous observation is never success. */
	if (task->heap.phase != 0U && task->heap.phase != HEAP_ACCEPTED)
		goto pending;
	task_start(ops, memory_ops, service, owner, group->context,
		group->handle, token, false, internal, &checked);
	if (checked.status != GPU_PRIVATE_SUCCESS)
		goto failed;
	step = 2U;
	csg = group->hardware_csg;
	root = ops->address(runtime_tables[0]);
	if (!ops->configuration(root, &config) || config.ack_timeout_ticks == 0UL)
		goto failed;
	shared = runtime_pages[section_page[interfaces.section]];
	slot = &interfaces.slots[csg];
	parent = 1U << csg;
	interface_words(glb_in, shared + interfaces.global.input, sizeof(glb_in));
	interface_words(csg_in, shared + slot->group.input, sizeof(csg_in));
	ops->invalidate(shared + slot->group.output, sizeof(csg_out));
	interface_words(csg_out, shared + slot->group.output, sizeof(csg_out));
	if (((csg_in[0] ^ csg_out[0]) & TASK_STATUS_UPDATE) != 0U)
		goto pending; /* A prior stopped-slot status request may still settle. */
	wanted = csg_in[0] ^ TASK_STATUS_UPDATE;
	ops->invalidate(shared + interfaces.global.output, sizeof(glb_out));
	interface_words(glb_out, shared + interfaces.global.output, sizeof(glb_out));
	doorbell = (glb_in[2] & ~parent) | ((glb_out[2] ^ parent) & parent);
	/* The MCU can observe input before MMIO. Record uncertainty before the
	 * first status request and retain all references on any partial failure.
	 */
	task->status_pending = true;
	group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
	csg_in[0] = wanted;
	memcpy(shared + slot->group.input, csg_in, sizeof(csg_in));
	ops->clean(shared + slot->group.input, sizeof(csg_in));
	glb_in[2] = doorbell;
	memcpy(shared + interfaces.global.input, glb_in, sizeof(glb_in));
	ops->clean(shared + interfaces.global.input, sizeof(glb_in));
	step = 3U;
	if (!ops->notify(root))
		goto failed;
	step = 4U;
	start = ops->clock();
	do {
		ops->invalidate(shared + interfaces.global.output, sizeof(glb_out));
		ops->invalidate(shared + slot->group.output, sizeof(csg_out));
		interface_words(glb_out, shared + interfaces.global.output, sizeof(glb_out));
		interface_words(csg_out, shared + slot->group.output, sizeof(csg_out));
		if (glb_out[4] != 0U)
			goto failed;
		for (unsigned int i = 0U; i < interfaces.streams; i++) {
			stream_status(ops, shared + slot->stream[i].output, &cs_out);
			if ((cs_out.ack & TASK_CS_ERRORS) != 0U || cs_out.fault != 0U || cs_out.fatal != 0U) {
				ERROR("GPU OBSERVE cs=%u ack=%x fault=%x fatal=%x\n", i,
					cs_out.ack, cs_out.fault & 255U, cs_out.fatal & 255U);
				goto failed;
			}
		}
		if (((glb_out[2] ^ doorbell) & parent) == 0U &&
		    ((csg_out[0] ^ wanted) & (TASK_CSG_ACK_MASK | TASK_STATUS_UPDATE)) == 0U)
			goto observed;
	} while (ops->clock() - start < config.ack_timeout_ticks);
	goto failed; /* Never republish an ambiguously timed-out status observation. */
observed:
	step = 5U;
	task->status_pending = false;
	group->state = GPU_FIRMWARE_GROUP_STARTED;
	/* Queue I/O exists only in the protected MCU arena; derive pages from
	 * the group record, never live firmware pointers or caller addresses.
	 */
	sync_page = group->ring_first + group->ring_pages - 1U;
	for (unsigned int queue = 0U; queue < group->streams; queue++) {
		if ((group->active_queues & (1U << queue)) == 0U)
			continue;
		unsigned int io_page = group->first + ((interfaces.suspend_size + 4095U) / 4096U) + queue * 2U;

		stream_status(ops, shared + slot->stream[queue].output, &cs_out);
		uint32_t request;

		interface_words(&request, shared + slot->stream[queue].input, sizeof(request));
		if (((request ^ cs_out.ack) & TASK_CS_OOM) != 0U)
			goto pending; /* A pending heap event cannot become a fence. */
		if (!read_control(memory_ops, io_page, 0U, input, sizeof(input)) ||
		    !read_control(memory_ops, io_page + 1U, 0U, output, sizeof(output)) ||
		    !read_control(memory_ops, sync_page, queue * 16U, completion, sizeof(completion)))
			goto failed;
		insert = input[0] | ((uint64_t)input[1] << 32U);
		extract = output[0] | ((uint64_t)output[1] << 32U);
		sequence = completion[0] | ((uint64_t)completion[1] << 32U);
		unsigned int published = task_published_count(task, queue);
		uint64_t base, first_sequence;

		if (!queue_base(group, queue, &base))
			goto failed;
		first_sequence = base / sizeof(task->resources.instructions);
		if (insert != base + published * sizeof(task->resources.instructions) ||
		    (input[2] | ((uint64_t)input[3] << 32U)) != queue_origin(group, queue) || extract < base || extract > insert ||
		    sequence < first_sequence || sequence > first_sequence + published || completion[2] != 0U || completion[3] != 0U)
			goto failed;
		/* Array order and per-queue order are distinct. A sequence of 1 on
		 * queue 0 cannot complete an earlier member from queue 1, nor a
		 * second member on queue 0. The protected wrapper's scoreboard wait
		 * precedes its sequence write; consumer position is checked as well.
		 * This is execution progress, not CPU-cache return or safe release.
		 */
		unsigned int ordinal = 0U;

		for (unsigned int i = 0U; i < task->count; i++) {
			unsigned int member_queue = i == 0U ? task->resources.queue : task->extra[i - 1U].queue;

			if (member_queue != queue)
				continue;
			ordinal++;
			if ((task->published_members & (1U << i)) != 0U &&
			    sequence >= first_sequence + ordinal && extract >= base + ordinal * sizeof(task->resources.instructions))
				observed_members |= 1U << i;
		}
		/* Validate every queue even if an earlier queue is still busy. */
		pending_work |= extract != insert || cs_out.scoreboards != 0U || cs_out.blocked_reason != 0U ||
			sequence != first_sequence + task->queue_count[queue];
	}
	task_start(ops, memory_ops, service, owner, group->context,
		group->handle, token, false, internal, &checked);
	if (checked.status != GPU_PRIVATE_SUCCESS)
		goto failed;
	/* Publish nothing until every queue, the live root and the firmware have
	 * passed this fresh observation. A regressed prefix is a failed invariant,
	 * not a reason to reuse an earlier success mask.
	 */
	if ((task->observed_members & ~observed_members) != 0U)
		goto failed;
	task->observed_members = observed_members;
	if (!finish)
		goto success;
	/* Native Panthor queue-idle fields, but only after our own fresh status
	 * ACK. The writable sequence/error is supplementary evidence, not sole
	 * authority to recycle a mapping or declare another Client's task done.
	 */
	if (pending_work)
		goto pending;
	step = 6U;
	task->preserve = true;
	/* The full post-read START replay above is the first-stop precheck.
	 * Only private metadata tests occur between it and this internal call.
	 */
	task_quiesce(ops, memory_ops, service, owner, group->context,
		group->handle, token, root, &config, &checked);
	if (checked.status != GPU_PRIVATE_SUCCESS)
		goto failed;
	step = 7U;
	for (unsigned int queue = 0U; queue < group->streams; queue++) {
		if (task->queue_count[queue] == 0U)
			continue;
		uint64_t base;

		if (!queue_base(group, queue, &base) ||
		    !read_control(memory_ops, sync_page, queue * 16U, completion, sizeof(completion)) ||
		    (completion[0] | ((uint64_t)completion[1] << 32U)) !=
			base / sizeof(task->resources.instructions) + task->queue_count[queue] ||
		    completion[2] != 0U || completion[3] != 0U)
			goto failed;
	}
	task_quiesce(ops, memory_ops, service, owner, group->context,
		group->handle, token, 0UL, NULL, &checked);
	if (checked.status != GPU_PRIVATE_SUCCESS)
		goto failed;
	task->completed = true;
success:
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = finish ? 1UL : (task->completed ? (1UL << task->count) - 1UL : observed_members);
	result->value[1] = finish ? task->resources.queue : task->count;
	result->value[2] = finish ? 0UL : task->queue_mask;
	return;
pending:
	result->status = GPU_PRIVATE_INCOMPLETE;
	result->value[1] = finish ? task->resources.queue : task->count;
	result->value[2] = finish ? 0UL : task->queue_mask;
	return;
failed:
	ERROR("GPU OBSERVE fail step=%u finish=%u\n", step, finish);
	group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
}

void gpu_firmware_task_complete(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long token, struct gpu_private_result *result)
{
	task_observe(ops, memory_ops, service, owner, token, true, false, result);
}

void gpu_firmware_task_progress(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long token, struct gpu_private_result *result)
{
	task_observe(ops, memory_ops, service, owner, token, false, false, result);
}

/* This supplements STATUS, or revalidates an already drained hidden anchor
 * whose producers have stayed protected and unchanged. It cannot establish
 * a new drain. Re-read every active queue across callbacks; a completion
 * bitmap alone omits idle/blocked state.
 */
static bool task_idle_snapshot(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const struct fw_group *group,
		const struct fw_task *task, bool *pending)
{
	unsigned int sync_page = group->ring_first + group->ring_pages - 1U;
	unsigned char *shared = runtime_pages[section_page[interfaces.section]];
	struct fw_slot *slot = &interfaces.slots[group->hardware_csg];

	*pending = task->published_members != (1U << task->count) - 1U ||
		(task->heap.phase != 0U && task->heap.phase != HEAP_ACCEPTED);
	for (unsigned int q = 0U; q < group->streams; q++) {
		struct fw_stream_status status;
		uint32_t input[4], output[4], completion[4], request;
		uint64_t base, insert, extract, sequence, first;
		unsigned int published = task_published_count(task, q);
		unsigned int io_page;

		if ((group->active_queues & (1U << q)) == 0U)
			continue;
		io_page = group->first + ((interfaces.suspend_size + 4095U) / 4096U) + q * 2U;
		stream_status(ops, shared + slot->stream[q].output, &status);
		interface_words(&request, shared + slot->stream[q].input, sizeof(request));
		if ((status.ack & TASK_CS_ERRORS) != 0U || status.fault != 0U || status.fatal != 0U ||
		    !queue_base(group, q, &base) ||
		    !read_control(memory_ops, io_page, 0U, input, sizeof(input)) ||
		    !read_control(memory_ops, io_page + 1U, 0U, output, sizeof(output)) ||
		    !read_control(memory_ops, sync_page, q * 16U, completion, sizeof(completion)))
			return false;
		insert = input[0] | ((uint64_t)input[1] << 32U);
		extract = output[0] | ((uint64_t)output[1] << 32U);
		sequence = completion[0] | ((uint64_t)completion[1] << 32U);
		first = base / sizeof(task->resources.instructions);
		if (insert != base + published * sizeof(task->resources.instructions) ||
		    (input[2] | ((uint64_t)input[3] << 32U)) != queue_origin(group, q) || extract < base || extract > insert ||
		    sequence < first || sequence > first + published || completion[2] != 0U || completion[3] != 0U)
			return false;
		*pending |= extract != insert || sequence != first + task->queue_count[q] ||
			status.scoreboards != 0U || status.blocked_reason != 0U ||
			((request ^ status.ack) & TASK_CS_OOM) != 0U;
	}
	return true;
}

void gpu_firmware_task_drain(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long token, struct gpu_private_result *result)
{
	struct fw_task *task = task_lookup_raw(owner, token);
	struct fw_group *group;
	struct gpu_private_result checked;
	bool pending;

	init_result(result);
	if (!authenticated(service) || service == owner || task == NULL)
		return;
	group = group_lookup(owner, task->resources.group);
	result->status = GPU_PRIVATE_STATE;
	if (group != NULL && group->prepared_task == token)
		gpu_private_task_clear_drained(service, owner, group->context, token);
	if (state != GPU_FIRMWARE_CONFIGURED || group == NULL || group->prepared_task != token ||
	    group->state != GPU_FIRMWARE_GROUP_STARTED || !task->started || !task->ready ||
	    task->completed || task->stop_attempted || task->status_pending ||
	    ops == NULL || ops->address == NULL || memory_ops == NULL || memory_ops->flush_as == NULL)
		return;
	/* No previous successful idle observation survives a new attempt. This
	 * includes a legal pending snapshot, not only an explicit hardware fault.
	 */
	if (!gpu_private_task_live_eligible(memory_ops, service, owner, group->context, token))
		return;
	task_observe(ops, memory_ops, service, owner, token, false, true, result);
	if (result->status != GPU_PRIVATE_SUCCESS)
		return;
	if (result->value[0] != (1UL << task->count) - 1UL)
		goto incomplete;
	if (!task_idle_snapshot(ops, memory_ops, group, task, &pending))
		goto failed;
	if (pending)
		goto incomplete;
	task_start(ops, memory_ops, service, owner, group->context,
		group->handle, token, false, true, &checked);
	if (checked.status != GPU_PRIVATE_SUCCESS ||
	    !gpu_private_task_flush_live(memory_ops, service, owner, group->context,
			token, ops->address(runtime_tables[0])))
		goto failed;
	/* A physical callback cannot carry an earlier root/queue proof forward.
	 * Pending work after the flush is unexpected: retain and quarantine.
	 */
	if (!task_idle_snapshot(ops, memory_ops, group, task, &pending) || pending)
		goto failed;
	task_start(ops, memory_ops, service, owner, group->context,
		group->handle, token, false, true, &checked);
	if (checked.status != GPU_PRIVATE_SUCCESS ||
	    !gpu_private_task_mark_drained(memory_ops, service, owner, group->context, token))
		goto failed;
	init_result(result);
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = 1UL;
	result->value[1] = task->count;
	result->value[2] = task->queue_mask;
	return;
incomplete:
	init_result(result);
	result->status = GPU_PRIVATE_INCOMPLETE;
	result->value[1] = task->count;
	result->value[2] = task->queue_mask;
	return;
failed:
	group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
	init_result(result);
	result->status = GPU_PRIVATE_STATE;
}

static void task_return(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long token, bool completed_checked,
		struct gpu_private_result *result)
{
	struct fw_task *task = task_lookup_raw(owner, token);
	struct fw_group *group;
	struct gpu_private_result checked;
	unsigned long pages, status;

	init_result(result);
	if (!authenticated(service) || task == NULL || service == owner)
		return;
	group = group_lookup(owner, task->resources.group);
	result->status = GPU_PRIVATE_STATE;
	if (state != GPU_FIRMWARE_CONFIGURED || group == NULL || !task->quiesced ||
	    group->state != GPU_FIRMWARE_GROUP_QUIESCED || group->prepared_task != token ||
	    (completed_checked && (!task->completed || !task->preserve)) ||
	    ops == NULL || ops->address == NULL || ops->configuration == NULL ||
	    memory_ops == NULL || memory_ops->sync_page_for_cpu == NULL)
		return;
	/* Every public entry/continuation checks the exact stop/suspend ACK and
	 * disabled AS. Only FINISH can reuse the adjacent successful COMPLETE's
	 * final full check, without a callback, publication or unlock in between.
	 */
	if (!completed_checked) {
		task_quiesce(ops, memory_ops, service, owner, group->context,
			group->handle, token, 0UL, NULL, result);
		if (result->status != GPU_PRIVATE_SUCCESS)
			return;
	}
	if (task->cpu_returned) {
		/* Already-returned replay is pure metadata validation. A single
		 * fresh STOP/disabled-AS observation above suffices: no physical
		 * callback or hardware publication can occur before returning.
		 * RETIRE calls us at both sides of its scrub boundary as before.
		 */
		gpu_private_task_returned(service, owner, group->context, token, result);
		if (result->status != GPU_PRIVATE_SUCCESS)
			goto failed;
		pages = result->value[0];
		status = GPU_PRIVATE_SUCCESS;
		goto returned;
	}
	gpu_private_task_return(memory_ops, service, owner, group->context, token, result);
	if (result->status != GPU_PRIVATE_SUCCESS && result->status != GPU_PRIVATE_INCOMPLETE)
		goto failed;
	pages = result->value[0];
	status = result->status;
	task_quiesce(ops, memory_ops, service, owner, group->context,
		group->handle, token, 0UL, NULL, &checked);
	if (checked.status != GPU_PRIVATE_SUCCESS)
		goto failed;
	/* A cache callback may fail after partial work or observe a device fault.
	 * No successful CPU-ownership assertion is published on that ambiguity.
	 */
returned:
	result->value[0] = status == GPU_PRIVATE_SUCCESS ? 1UL : 0UL;
	result->value[1] = task->resources.queue;
	result->value[2] = pages;
	result->value[3] = 0UL;
	if (status == GPU_PRIVATE_SUCCESS)
		task->cpu_returned = true;
	return;
failed:
	group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
	init_result(result);
	result->status = GPU_PRIVATE_STATE;
}

void gpu_firmware_task_return(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long token, struct gpu_private_result *result)
{
	init_result(result);
	if (task_lookup(owner, token) == NULL) return;
	task_return(ops, memory_ops, service, owner, token, false, result);
}

static void task_retire(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long token, bool returned_checked,
		struct gpu_private_result *result)
{
	struct fw_task *task = task_lookup_raw(owner, token);
	struct fw_group *group;
	struct gpu_private_result checked;
	unsigned int total, csg, queue, budget = GPU_PRIVATE_BATCH;
	unsigned char *shared;
	struct fw_slot *slot;

	init_result(result);
	if (!authenticated(service) || service == owner || task == NULL)
		return;
	group = group_lookup(owner, task->resources.group);
	result->status = GPU_PRIVATE_STATE;
	if (state != GPU_FIRMWARE_CONFIGURED || group == NULL || !task->cpu_returned ||
	    !task->quiesced || group->state != GPU_FIRMWARE_GROUP_QUIESCED ||
	    group->prepared_task != token || group->tasks == 0U ||
	    (returned_checked && (!task->completed || !task->preserve)) ||
	    memory_ops == NULL || memory_ops->clear_page == NULL ||
	    ops == NULL || ops->clean == NULL)
		return;
	csg = group->hardware_csg;
	queue = task->resources.queue;
	total = task->preserve ? 0U : group->pages + group->ring_pages;
	/* An empty scrub has no callback or publication between these two
	 * boundaries. Use the mandatory check below before clearing inputs or
	 * releasing any lease. Real scrubbing still checks both sides, including
	 * continuations: a page callback can observe or cause a device failure.
	 */
	if (total != 0U) {
		task_return(ops, memory_ops, service, owner, token, false, &checked);
		if (checked.status != GPU_PRIVATE_SUCCESS)
			goto failed;
	}
	while (task->retire_cursor < total && budget-- != 0U) {
		unsigned int index = task->retire_cursor < group->pages ?
			group->first + task->retire_cursor :
			group->ring_first + task->retire_cursor - group->pages;

		if (!clear_control(memory_ops, index))
			goto failed;
		task->retire_cursor++;
	}
	/* Fresh full STOP/SUSPEND, all streams, firmware/root and disabled-AS
	 * checks remain mandatory even when no page needed clearing. Only the
	 * internal compound path can bring that exact check from adjacent RETURN.
	 */
	if (!returned_checked || total != 0U) {
		task_return(ops, memory_ops, service, owner, token, false, &checked);
		if (checked.status != GPU_PRIVATE_SUCCESS)
			goto failed;
	}
	result->value[1] = queue;
	result->value[2] = task->retire_cursor;
	if (task->retire_cursor != total) {
		result->status = GPU_PRIVATE_INCOMPLETE;
		return;
	}
	/* Remove stale AS/ring/IO addresses while this CSG remains nonexecuting. No
	 * doorbell, new launch, mapping edit or service-selected address is used.
	 */
	shared = runtime_pages[section_page[interfaces.section]];
	slot = &interfaces.slots[csg];
	for (unsigned int i = 0U; i < group->streams; i++) {
		memset(shared + slot->stream[i].input, 0, FW_STREAM_INPUT_SIZE);
		ops->clean(shared + slot->stream[i].input, FW_STREAM_INPUT_SIZE);
	}
	uint32_t retained_req, retained_child;

	memcpy(&retained_req, shared + slot->group.input, sizeof(retained_req));
	memcpy(&retained_child, shared + slot->group.input + 8U, sizeof(retained_child));
	memset(shared + slot->group.input, 0, FW_GROUP_INPUT_SIZE);
	/* Preserve the acknowledged suspension/toggles, never stale addresses.
	 * Clearing SUSPEND to TERMINATE without ACK would forge a free slot.
	 */
	retained_req &= TASK_CSG_ACK_MASK | TASK_STATUS_UPDATE;
	memcpy(shared + slot->group.input, &retained_req, sizeof(retained_req));
	memcpy(shared + slot->group.input + 8U, &retained_child, sizeof(retained_child));
	ops->clean(shared + slot->group.input, FW_GROUP_INPUT_SIZE);
	if (!retire_history(service, owner, group, task))
		goto failed;
	hardware_groups[csg] = 0UL;
	group->hardware_csg = group->hardware_as = 0U;
	group->prepared_task = 0UL;
	group->domain_batches = 0U;
	group->suspended = task->preserve;
	if (!group->suspended)
		group->active_queues = 0U;
	group->tasks--;
	group->state = GPU_FIRMWARE_GROUP_RESERVED;
	memset(task, 0, sizeof(*task)); /* Old generation cannot refer to future work. */
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = 1UL;
	return;
failed:
	group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
	init_result(result);
	result->status = GPU_PRIVATE_STATE;
}

void gpu_firmware_task_retire(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long token, struct gpu_private_result *result)
{
	init_result(result);
	if (task_lookup(owner, token) == NULL) return;
	task_retire(ops, memory_ops, service, owner, token, false, result);
}

void gpu_firmware_task_reclaim(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long token, struct gpu_private_result *result)
{
	struct fw_task *task = task_lookup(owner, token);
	unsigned long queue;

	init_result(result);
	if (!authenticated(service) || service == owner || task == NULL)
		return;
	result->status = GPU_PRIVATE_STATE;
	/* This compound operation is successful-execution cleanup only. Explicit
	 * aborts retain independent RETURN/RETIRE with their scrub boundaries.
	 * Completion, ownership and the live disabled AS are never caller claims.
	 */
	if (!task->completed || !task->preserve)
		return;
	queue = task->resources.queue;
	gpu_firmware_task_return(ops, memory_ops, service, owner, token, result);
	if (result->status != GPU_PRIVATE_SUCCESS) {
		if (result->status == GPU_PRIVATE_INCOMPLETE) {
			/* Bounded RETURN progress; no hardware wait or release yet. */
			memset(result->value, 0, sizeof(result->value));
			result->value[1] = queue;
		}
		return;
	}
	/* RETURN ends with a fresh complete stop/root/stream/disabled-AS check.
	 * Only private metadata lies between that check and this call, under
	 * the same policy lock. No callback, shared publication or unlock may
	 * be inserted here. Retained state has no physical scrub callbacks.
	 */
	task_retire(ops, memory_ops, service, owner, token, true, result);
}

/* A native SUSPEND refreshes the queue snapshot just like STATUS_UPDATE.
 * Only the internal FINISH path can use it as both the fresh observation and
 * nonexecution barrier. Hints merely select that path, never establish success.
 */
static bool task_finish_by_suspend(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, struct fw_task *task, struct gpu_private_result *result)
{
	struct fw_group *group = group_lookup(owner, task->resources.group);
	struct gpu_firmware_config config;
	struct gpu_private_result checked;
	unsigned int sync_page;
	unsigned long root;
	uint32_t input[4], output[4], completion[4];

	if (group == NULL || state != GPU_FIRMWARE_CONFIGURED || !task->started || !task->ready ||
	    group->state != GPU_FIRMWARE_GROUP_STARTED || group->prepared_task != task->handle ||
	    task->completed || task->stop_attempted || task->status_pending ||
	    task->count == 0U || task->count > GPU_PRIVATE_TASK_BATCH ||
	    task->published_members != (1U << task->count) - 1U ||
	    (task->heap.phase != 0U && task->heap.phase != HEAP_ACCEPTED) ||
	    ops == NULL || ops->address == NULL || ops->configuration == NULL ||
	    memory_ops == NULL || memory_ops->read_page == NULL)
		return false;
	sync_page = group->ring_first + group->ring_pages - 1U;
	/* Before stopping, require exact current input/consumer/terminal values on
	 * every active queue. Stale/malformed/unavailable hints use the original
	 * fresh STATUS path, which independently validates every field again.
	 */
	for (unsigned int queue = 0U; queue < group->streams; queue++) {
		unsigned int io_page, published;
		uint64_t base, end, sequence;

		if ((group->active_queues & (1U << queue)) == 0U)
			continue;
		io_page = group->first + ((interfaces.suspend_size + 4095U) / 4096U) + queue * 2U;
		published = task_published_count(task, queue);
		if (!queue_base(group, queue, &base) ||
		    !read_control(memory_ops, io_page, 0U, input, sizeof(input)) ||
		    !read_control(memory_ops, io_page + 1U, 0U, output, sizeof(output)) ||
		    !read_control(memory_ops, sync_page, queue * 16U, completion, sizeof(completion)))
			return false;
		end = base + published * sizeof(task->resources.instructions);
		sequence = base / sizeof(task->resources.instructions) + task->queue_count[queue];
		if ((input[0] | ((uint64_t)input[1] << 32U)) != end ||
		    (input[2] | ((uint64_t)input[3] << 32U)) != queue_origin(group, queue) ||
		    (output[0] | ((uint64_t)output[1] << 32U)) != end ||
		    (completion[0] | ((uint64_t)completion[1] << 32U)) != sequence ||
		    completion[2] != 0U || completion[3] != 0U)
			return false;
	}
	/* Capture timeout before the complete START/root/all-stream replay. No
	 * callback, input publication or unlock separates that proof from STOP.
	 */
	root = ops->address(runtime_tables[0]);
	if (!ops->configuration(root, &config) || config.ack_timeout_ticks == 0UL)
		goto failed;
	task_start(ops, memory_ops, service, owner, group->context,
		group->handle, task->handle, false, true, &checked);
	if (checked.status != GPU_PRIVATE_SUCCESS)
		goto failed;
	task->preserve = true;
	task_quiesce(ops, memory_ops, service, owner, group->context,
		group->handle, task->handle, root, &config, &checked);
	if (checked.status != GPU_PRIVATE_SUCCESS)
		goto failed;
	/* The acknowledged SUSPEND is now a new firmware snapshot. Re-read all
	 * protected queue data after the real AS flush/disable, including queues
	 * not used by this batch but still retained in the native group.
	 */
	for (unsigned int queue = 0U; queue < group->streams; queue++) {
		unsigned int io_page;
		struct fw_stream_status status;
		uint64_t base, end;

		if ((group->active_queues & (1U << queue)) == 0U)
			continue;
		io_page = group->first + ((interfaces.suspend_size + 4095U) / 4096U) + queue * 2U;
		stream_status(ops, runtime_pages[section_page[interfaces.section]] +
			interfaces.slots[group->hardware_csg].stream[queue].output, &status);
		if (!queue_base(group, queue, &base) ||
		    !read_control(memory_ops, io_page, 0U, input, sizeof(input)) ||
		    !read_control(memory_ops, io_page + 1U, 0U, output, sizeof(output)) ||
		    !read_control(memory_ops, sync_page, queue * 16U, completion, sizeof(completion)))
			goto failed;
		end = base + task_published_count(task, queue) * sizeof(task->resources.instructions);
		if ((input[0] | ((uint64_t)input[1] << 32U)) != end ||
		    (input[2] | ((uint64_t)input[3] << 32U)) != queue_origin(group, queue) ||
		    (output[0] | ((uint64_t)output[1] << 32U)) != end ||
		    (completion[0] | ((uint64_t)completion[1] << 32U)) !=
			base / sizeof(task->resources.instructions) + task->queue_count[queue] ||
		    completion[2] != 0U || completion[3] != 0U ||
		    status.scoreboards != 0U || status.blocked_reason != 0U)
			goto failed;
	}
	/* Check heap ACK edges on every stream, including inactive streams. A
	 * new event after the hint must not be hidden by stopping the group.
	 */
	for (unsigned int queue = 0U; queue < interfaces.streams; queue++) {
		struct fw_stream_status status;
		uint32_t request;
		unsigned char *shared = runtime_pages[section_page[interfaces.section]];

		interface_words(&request, shared +
			interfaces.slots[group->hardware_csg].stream[queue].input, sizeof(request));
		stream_status(ops, shared + interfaces.slots[group->hardware_csg].stream[queue].output, &status);
		if (((request ^ status.ack) & TASK_CS_OOM) != 0U)
			goto failed;
	}
	/* Callbacks above cannot carry a stop/root proof across their boundary.
	 * Recheck all streams, global state and disabled AS before publication.
	 */
	task_quiesce(ops, memory_ops, service, owner, group->context,
		group->handle, task->handle, 0UL, NULL, &checked);
	if (checked.status != GPU_PRIVATE_SUCCESS)
		goto failed;
	task->observed_members = (1U << task->count) - 1U;
	task->completed = true;
	suspend_finish_fast++;
	init_result(result);
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = 1UL;
	result->value[1] = task->resources.queue;
	return true;
failed:
	group->state = GPU_FIRMWARE_GROUP_QUARANTINED;
	init_result(result);
	result->status = GPU_PRIVATE_STATE;
	return true; /* An attempted stop never falls back or manufactures success. */
}

static void task_finish(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long token, bool internal, struct gpu_private_result *result)
{
	struct fw_task *task = internal ? task_lookup_raw(owner, token) : task_lookup(owner, token);
	unsigned long queue;
	bool completed_checked = false;

	init_result(result);
	if (!authenticated(service) || service == owner || task == NULL)
		return;
	queue = task->resources.queue;
	if (!task->completed) {
		if (!task_finish_by_suspend(ops, memory_ops, service, owner, task, result)) {
			suspend_finish_fallback++;
			task_observe(ops, memory_ops, service, owner, token, true, internal, result);
		}
		if (result->status != GPU_PRIVATE_SUCCESS)
			return;
		completed_checked = true;
	}
	result->status = GPU_PRIVATE_STATE;
	if (!task->preserve)
		return; /* Explicit aborts cannot turn into successful execution. */
	/* A proof is local to this call only. Already-completed entries and all
	 * bounded continuations take RETURN's fresh full precheck. Cache callbacks
	 * always have a full postcheck, even on partial return or callback failure.
	 */
	task_return(ops, memory_ops, service, owner, token, completed_checked, result);
	if (result->status != GPU_PRIVATE_SUCCESS) {
		if (result->status == GPU_PRIVATE_INCOMPLETE) {
			memset(result->value, 0, sizeof(result->value));
			result->value[1] = queue;
			result->value[3] = 1UL; /* CPU return progress, not a GPU wait. */
		}
		return;
	}
	/* Same callback-free RETURN/RETIRE boundary as RECLAIM. Only a successful
	 * exact retirement may be exposed to the Client as fence completion.
	 */
	task_retire(ops, memory_ops, service, owner, token, true, result);
}

void gpu_firmware_task_finish(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long token, struct gpu_private_result *result)
{
	task_finish(ops, memory_ops, service, owner, token, false, result);
}

/* Only RMM-admitted task records affect retention, never a service hint or
 * merely allocated group. A group waiting for hardware preparation gets the
 * next completed boundary; running or already-preparing groups retain the
 * existing eight-batch quantum. A prepared task already owns its CSG/AS and
 * does not need this group to yield before its own Client READY. Solo
 * traffic can amortize cold stop/resume over 32 batches. These are task-count
 * bounds, not elapsed-time guarantees or substitutes for trusted completion.
 */
static unsigned int task_domain_quantum(const struct fw_task *current)
{
	unsigned int quantum = 32U;

	for (unsigned int i = 0U; i < GPU_FIRMWARE_TASKS; i++) {
		const struct fw_task *other = &tasks[i];
		const struct fw_group *group;

		if (other->handle == 0UL || other->internal || other == current ||
		    other->resources.group == current->resources.group)
			continue;
		group = group_lookup(other->owner, other->resources.group);
		/* A quarantined/closing group cannot consume a newly freed slot.
		 * Keep its holds; do not mistake an uncertain successor for a
		 * runnable admission request or repair it as a scheduling action.
		 */
		if (!other->started && !other->preparing && group != NULL &&
		    group->state == GPU_FIRMWARE_GROUP_RESERVED)
			return 1U;
		quantum = 8U;
	}
	return quantum;
}

/* Used by the existing RSI FINISH operation; no new Guest ABI. An old
 * external task becomes an internal lifetime anchor only after real drain.
 * Public lookup rejects it even when the Client remembers its old handle.
 */
void gpu_firmware_task_finish_domain(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long token, struct gpu_private_result *result)
{
	struct fw_task *task = task_lookup(owner, token);
	struct fw_group *group;

	init_result(result);
	if (!authenticated(service) || service == owner || task == NULL)
		return;
	group = group_lookup(owner, task->resources.group);
	if (group == NULL) return;
	if ((unsigned int)group->domain_batches + 1U >= task_domain_quantum(task) ||
	    !gpu_private_task_live_eligible(memory_ops, service, owner, group->context, token)) {
		task_finish(ops, memory_ops, service, owner, token, false, result);
		return;
	}
	gpu_firmware_task_drain(ops, memory_ops, service, owner, token, result);
	if (result->status != GPU_PRIVATE_SUCCESS) {
		if (result->status == GPU_PRIVATE_INCOMPLETE) {
			memset(result->value, 0, sizeof(result->value));
			result->value[1] = task->resources.queue;
		}
		return;
	}
	/* No callback or publication after drain and before token retirement. */
	task->internal = true;
	group->domain_batches++;
	init_result(result);
	result->status = GPU_PRIVATE_SUCCESS;
	result->value[0] = 1UL;
	result->value[1] = task->resources.queue;
}

static bool yield_idle_domains(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const struct fw_group *except)
{
	for (unsigned int i = 0U; i < GPU_FIRMWARE_LOGICAL_GROUPS; i++) {
		struct fw_group *group = &groups[i];
		struct gpu_private_result result;

		if (group == except || !group_domain(group) || group->tasks != 1U)
			continue;
		task_finish(ops, memory_ops, image_service, group->owner,
			group->prepared_task, true, &result);
		if (result.status != GPU_PRIVATE_SUCCESS)
			return false;
	}
	return true;
}

void gpu_firmware_context_yield(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *owner,
		unsigned long context, struct gpu_private_result *result)
{
	init_result(result);
	if (owner == NULL || owner == image_service) return;
	result->status = GPU_PRIVATE_STATE;
	for (unsigned int i = 0U; i < GPU_FIRMWARE_LOGICAL_GROUPS; i++) {
		struct fw_group *group = &groups[i];

		if (group->owner != owner || group->context != context || group->prepared_task == 0UL)
			continue;
		if (!group_domain(group) || group->tasks != 1U)
			return;
		task_finish(ops, memory_ops, image_service, owner, group->prepared_task, true, result);
		if (result->status != GPU_PRIVATE_SUCCESS) return;
	}
	init_result(result);
	result->status = GPU_PRIVATE_SUCCESS;
}

void gpu_firmware_group_yield(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *owner,
		unsigned long handle, struct gpu_private_result *result)
{
	struct fw_group *group = group_lookup(owner, handle);

	init_result(result);
	if (group == NULL) return;
	gpu_firmware_context_yield(ops, memory_ops, owner, group->context, result);
}

static bool iface_range(uint32_t va, uint32_t size, uint32_t *offset)
{
	const struct gpu_firmware_section *section = &sections[interfaces.section];
	uint32_t begin;

	/* CPU clean/invalidate operates on whole cache lines. Byte-disjoint
	 * interfaces sharing a line could still clobber MCU-owned output.
	 */
	size = (size + GPU_FIRMWARE_CACHE_LINE - 1U) & ~(GPU_FIRMWARE_CACHE_LINE - 1U);
	if (va < section->va || (va & (GPU_FIRMWARE_CACHE_LINE - 1U)) != 0U ||
	    iface_range_count == sizeof(fw_storage.ranges) / sizeof(fw_storage.ranges[0]))
		return false;
	begin = va - section->va;
	if (begin > section->size || size > section->size - begin)
		return false;
	for (unsigned int i = 0U; i < iface_range_count; i++)
		if (begin < fw_storage.ranges[i].end && fw_storage.ranges[i].begin < begin + size)
			return false;
	fw_storage.ranges[iface_range_count].begin = begin;
	fw_storage.ranges[iface_range_count++].end = begin + size;
	if (offset != NULL)
		*offset = begin;
	return true;
}

static bool shared_ready(const struct gpu_firmware_ops *ops)
{
	uint32_t global[8], first_group[7] = {0};
	unsigned char *shared = NULL;
	uint32_t bytes = 0U;

	if (state != GPU_FIRMWARE_INSTALLED)
		return false; /* Runtime history must never become discovery scratch. */
	memset(&interfaces, 0, sizeof(interfaces));
	iface_range_count = 0U;
	for (unsigned int i = 0U; i < section_count; i++) {
		if ((sections[i].flags & FW_SHARED) != 0U) {
			interfaces.section = i;
			shared = runtime_pages[section_page[i]];
			bytes = sections[i].size;
			break;
		}
	}
	if (shared == NULL || bytes < sizeof(global))
		return false;
	/* Metadata is consumed once from protected backing, not followed live
	 * after validation. Firmware owns output bytes; Proxy owns neither.
	 */
	ops->invalidate(shared, bytes);
	memcpy(global, shared, sizeof(global));
	if ((global[0] >> 24U) != 1U || global[4] < 3U ||
	    global[4] > GPU_FIRMWARE_GROUPS || global[5] < 64U ||
	    (global[5] & 3U) != 0U ||
	    4096ULL + (uint64_t)global[4] * global[5] > bytes)
		return false;
	/* Reserve the complete descriptor area so no input/output can alias
	 * metadata, another stream, another group, or the global interface.
	 */
	fw_storage.ranges[0].begin = 0U;
	fw_storage.ranges[0].end = 4096U + global[4] * global[5];
	iface_range_count = 1U;
	if (!iface_range(global[2], FW_GLOBAL_INPUT_SIZE, &interfaces.global.input) ||
	    !iface_range(global[3], FW_GLOBAL_OUTPUT_SIZE, &interfaces.global.output))
		return false;
	interfaces.version = global[0];
	interfaces.features = global[1];
	interfaces.groups = global[4];
	interfaces.instr_features = global[0] >= UINT32_C(0x01010000) ? global[7] : 0U;
	for (unsigned int g = 0U; g < interfaces.groups; g++) {
		uint32_t group[7];
		uint32_t base = 4096U + g * global[5];

		memcpy(group, shared + base, sizeof(group));
		if (group[5] < 8U || group[5] > GPU_FIRMWARE_STREAMS ||
		    group[6] < 12U || (group[6] & 3U) != 0U ||
		    64ULL + (uint64_t)group[5] * group[6] > global[5] ||
		    group[3] == 0U || group[3] > FW_SUSPEND_LIMIT || group[4] > FW_SUSPEND_LIMIT ||
	    !iface_range(group[1], FW_GROUP_INPUT_SIZE, &interfaces.slots[g].group.input) ||
	    !iface_range(group[2], FW_GROUP_OUTPUT_SIZE, &interfaces.slots[g].group.output))
			return false;
		if (g == 0U) {
			memcpy(first_group, group, sizeof(group));
			interfaces.streams = group[5];
			interfaces.suspend_size = group[3];
			interfaces.protm_suspend_size = group[4];
		} else if (group[0] != first_group[0] || group[3] != first_group[3] ||
			   group[4] != first_group[4] || group[5] != first_group[5]) {
			return false;
		}
		for (unsigned int s = 0U; s < interfaces.streams; s++) {
			uint32_t stream[3];

			memcpy(stream, shared + base + 64U + s * group[6], sizeof(stream));
			if (!iface_range(stream[1], FW_STREAM_INPUT_SIZE, &interfaces.slots[g].stream[s].input) ||
			    !iface_range(stream[2], FW_STREAM_OUTPUT_SIZE, &interfaces.slots[g].stream[s].output))
				return false;
			if (g == 0U && s == 0U)
				interfaces.stream_features = stream[0];
			else if (interfaces.stream_features != stream[0])
				return false;
		}
	}
	/* Only the validated private interface snapshot survives discovery. */
	memset(&fw_storage, 0, sizeof(fw_storage));
	iface_range_count = 0U;
	return true;
}

void gpu_firmware_boot(const struct gpu_firmware_ops *ops, const void *service,
		struct gpu_private_result *result)
{
	unsigned long root;

	init_result(result);
	if (!authenticated(service))
		return;
	result->status = GPU_PRIVATE_STATE;
	if (state == GPU_FIRMWARE_BOOTED || state == GPU_FIRMWARE_CONFIGURED) {
		gpu_firmware_inspect(service, result);
		return;
	}
	if (state != GPU_FIRMWARE_PREPARED || ops == NULL || ops->address == NULL ||
	    ops->install == NULL || ops->boot == NULL || ops->invalidate == NULL)
		return;
	root = ops->address(runtime_tables[0]);
	state = GPU_FIRMWARE_QUARANTINED;
	if (!ops->install(root))
		return;
	state = GPU_FIRMWARE_INSTALLED;
	/* Even a failed boot may have begun memory accesses. Never free or
	 * reconstruct the runtime backing based on a service's "not started".
	 */
	if (!ops->boot(root) || !shared_ready(ops)) {
		state = GPU_FIRMWARE_QUARANTINED;
		return;
	}
	state = GPU_FIRMWARE_BOOTED;
	gpu_firmware_inspect(service, result);
}

void gpu_firmware_properties(const void *service, unsigned long record,
		struct gpu_private_result *result)
{
	init_result(result);
	if (!authenticated(service) || record > 1UL)
		return;
	result->status = GPU_PRIVATE_STATE;
	if (state != GPU_FIRMWARE_BOOTED && state != GPU_FIRMWARE_CONFIGURED)
		return;
	result->status = GPU_PRIVATE_SUCCESS;
	if (record == 0UL) {
		result->value[0] = interfaces.version;
		result->value[1] = interfaces.features;
		result->value[2] = interfaces.groups;
		result->value[3] = interfaces.instr_features;
	} else {
		result->value[0] = interfaces.streams;
		result->value[1] = interfaces.stream_features;
		result->value[2] = interfaces.suspend_size;
		result->value[3] = interfaces.protm_suspend_size;
	}
}

void gpu_firmware_configure(const struct gpu_firmware_ops *ops, const void *service,
		struct gpu_private_result *result)
{
	struct gpu_firmware_config config;
	unsigned long root, start;
	unsigned char *shared;
	uint32_t input[FW_GLOBAL_INPUT_SIZE / sizeof(uint32_t)] = {0};
	uint32_t ack, expected;

	init_result(result);
	if (!authenticated(service))
		return;
	result->status = GPU_PRIVATE_STATE;
	if (state == GPU_FIRMWARE_CONFIGURED) {
		gpu_firmware_inspect(service, result);
		return;
	}
	if (state != GPU_FIRMWARE_BOOTED || ops == NULL || ops->address == NULL ||
	    ops->configuration == NULL || ops->notify == NULL || ops->clock == NULL ||
	    ops->clean == NULL || ops->invalidate == NULL)
		return;
	root = ops->address(runtime_tables[0]);
	if (!ops->configuration(root, &config) || config.shader_mask == 0U ||
	    config.ack_timeout_ticks == 0UL)
		return;
	shared = runtime_pages[section_page[interfaces.section]];
	ops->invalidate(shared + interfaces.global.output, FW_GLOBAL_OUTPUT_SIZE);
	memcpy(&ack, shared + interfaces.global.output, sizeof(ack));
	expected = (~ack) & GLB_CONFIG_MASK;
	input[0] = expected;
	input[4] = 2560000U; /* Native five-second progress budget in 1024 cycles. */
	input[5] = config.poweroff_timer;
	input[6] = (uint32_t)config.shader_mask;
	input[7] = (uint32_t)(config.shader_mask >> 32U);
	input[33] = config.idle_timer;
	/* IRQ delivery and Client scheduling are not active yet. In particular,
	 * never enable counters, protected mode, instrumentation or user groups.
	 */
	state = GPU_FIRMWARE_QUARANTINED;
	memcpy(shared + interfaces.global.input, input, sizeof(input));
	ops->clean(shared + interfaces.global.input, sizeof(input));
	if (!ops->notify(root))
		return;
	start = ops->clock();
	do {
		ops->invalidate(shared + interfaces.global.output, FW_GLOBAL_OUTPUT_SIZE);
		memcpy(&ack, shared + interfaces.global.output, sizeof(ack));
		if ((ack & GLB_CONFIG_MASK) == expected) {
			/* A matching memory word alone cannot override a stopped/faulted
			 * MCU or changed root/configuration detected by the backend.
			 */
			if (!ops->configuration(root, &config))
				return;
			state = GPU_FIRMWARE_CONFIGURED;
			gpu_firmware_inspect(service, result);
			return;
		}
	} while (ops->clock() - start < config.ack_timeout_ticks);
}
