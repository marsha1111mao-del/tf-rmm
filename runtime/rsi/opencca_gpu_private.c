/* SPDX-License-Identifier: BSD-3-Clause */
#include <arch_helpers.h>
#include <buffer.h>
#include <cpuid.h>
#include <granule.h>
#include <opencca_gpu.h>
#include <opencca_gpu_firmware.h>
#include <opencca_gpu_private.h>
#include <opencca_gpu_lease.h>
#include <opencca_iommu.h>
#include <mbedtls/sha256.h>
#include <realm.h>
#include <rec.h>
#include <rsi-handler.h>
#include <string.h>
#include <simd.h>
#include <xshm_endpoint.h>
#include <xshm_runtime.h>

/* Private snapshots, not a shared descriptor consumed after validation. */
static unsigned long input_pages[MAX_CPUS][GPU_PRIVATE_BATCH];
static struct gpu_firmware_queue_config input_queues[MAX_CPUS][GPU_FIRMWARE_STREAMS];
static struct gpu_firmware_task_command input_commands[MAX_CPUS][GPU_PRIVATE_TASK_BATCH];

_Static_assert(CACHE_WRITEBACK_GRANULE == GPU_FIRMWARE_CACHE_LINE,
	"Firmware interfaces must not share CPU cache-maintenance lines");

static bool source_page(const void *owner, unsigned long ipa, unsigned long *pa)
{
	/* A private GPU BO cannot reuse a CPU-shared source/borrowed alias or
	 * register a page already held by another private BO.
	 */
	if (xshm_memory_range_busy(owner, ipa, GRANULE_SIZE) ||
	    gpu_private_range_busy(owner, ipa, GRANULE_SIZE) ||
	    opencca_iommu_range_busy(owner, ipa, GRANULE_SIZE))
		return false;
	return xshm_rtt_ops.source_page(owner, ipa, pa) && !opencca_gpu_page_busy(*pa);
}

static bool clear_page(unsigned long pa)
{
	struct granule *data = find_lock_granule(pa, GRANULE_STATE_DATA);
	void *memory;

	if (data == NULL)
		return false;
	memory = buffer_granule_map(data, SLOT_RSI_CALL);
	inv_dcache_range((uintptr_t)memory, GRANULE_SIZE);
	memset(memory, 0, GRANULE_SIZE);
	clean_dcache_range((uintptr_t)memory, GRANULE_SIZE);
	dsb(sy);
	buffer_unmap(memory);
	granule_unlock(data);
	return true;
}

static bool write_page(unsigned long pa, size_t offset, const void *source, size_t bytes)
{
	struct granule *data;
	void *memory;

	if (source == NULL || bytes == 0U || offset > GRANULE_SIZE || bytes > GRANULE_SIZE - offset)
		return false;
	data = find_lock_granule(pa, GRANULE_STATE_DATA);
	if (data == NULL)
		return false;
	memory = buffer_granule_map(data, SLOT_RSI_CALL);
	/* Fully donated pages have no untrusted CPU aliases. The firmware core
	 * owns this range: ring preparation requires STOP or a drained producer
	 * that cannot reach the new wrappers until a separate Client publication.
	 */
	inv_dcache_range((uintptr_t)memory + offset, bytes);
	memcpy((unsigned char *)memory + offset, source, bytes);
	clean_dcache_range((uintptr_t)memory + offset, bytes);
	dsb(sy);
	buffer_unmap(memory);
	granule_unlock(data);
	return true;
}

static bool sync_page_for_device(unsigned long pa)
{
	struct granule *data = find_lock_granule(pa, GRANULE_STATE_DATA);
	void *memory;

	if (data == NULL)
		return false;
	memory = buffer_granule_map(data, SLOT_RSI_CALL);
	/* Client backing remains private. Use a trusted WB temporary mapping,
	 * clean dirty CPU data and invalidate to PoC before the device accesses
	 * it. Neither an RPC fence nor a CPU memory barrier replaces this step.
	 */
	flush_dcache_range((uintptr_t)memory, GRANULE_SIZE);
	dsb(sy);
	buffer_unmap(memory);
	granule_unlock(data);
	return true;
}

static bool sync_page_for_cpu(unsigned long pa)
{
	struct granule *data = find_lock_granule(pa, GRANULE_STATE_DATA);
	void *memory;

	if (data == NULL)
		return false;
	memory = buffer_granule_map(data, SLOT_RSI_CALL);
	/* GPU FLUSH_MEM and AS disable precede this operation. Discard stale CPU
	 * lines, including speculative fills, without writing them over GPU data.
	 * Client must honor DMA ownership until the entire return has succeeded.
	 */
	inv_dcache_range((uintptr_t)memory, GRANULE_SIZE);
	dsb(sy);
	buffer_unmap(memory);
	granule_unlock(data);
	return true;
}

static bool cache_barrier(void)
{
	dsb(sy);
	return true;
}

static bool read_page(unsigned long pa, size_t offset, void *destination, size_t bytes)
{
	struct granule *data;
	void *memory;

	if (destination == NULL || bytes == 0U || offset > GRANULE_SIZE || bytes > GRANULE_SIZE - offset)
		return false;
	data = find_lock_granule(pa, GRANULE_STATE_DATA);
	if (data == NULL)
		return false;
	memory = buffer_granule_map(data, SLOT_RSI_CALL);
	/* All callers resolve CPU-hidden, donated control pages from trusted
	 * records. Discard speculative/stale CPU cache lines before the snapshot.
	 */
	inv_dcache_range((uintptr_t)memory, GRANULE_SIZE);
	dsb(sy);
	memcpy(destination, (const unsigned char *)memory + offset, bytes);
	buffer_unmap(memory);
	granule_unlock(data);
	return true;
}

static unsigned long table_pa(const void *table)
{
	return (unsigned long)table;
}

static void clean(const void *table, size_t bytes)
{
	clean_dcache_range((uintptr_t)table, bytes);
	dsb(sy);
}

static bool activate(unsigned long context, unsigned long root, unsigned int slot)
{
	(void)context;
	return opencca_gpu_private_pt_install(root, slot);
}

static bool synchronize(unsigned long context, unsigned long root)
{
	(void)context;
	return opencca_gpu_private_pt_sync(root);
}

/* All MMU operations require revoked raw MMIO. Legacy installation/flush
 * require a stopped MCU/GPU; trusted preparation selects an unused Client AS
 * while the authenticated MCU runs, leaving all group/stream requests STOP.
 */
static const struct gpu_private_ops operations = {
	.source_page = source_page,
	.table_pa = table_pa,
	.clean = clean,
	.activate = activate,
	.synchronize = synchronize,
	.hide_page = gpu_control_rtt_hide,
	.restore_page = gpu_control_rtt_restore,
	.restore_page_uncached = gpu_private_rtt_restore_uncached,
	.cache_barrier = cache_barrier,
	.clear_page = clear_page,
	.prepare_as = opencca_gpu_private_pt_prepare,
	.check_running_as = opencca_gpu_private_pt_check_running,
	.extend_as = opencca_gpu_private_pt_extend,
	.write_page = write_page,
	.sync_page_for_device = sync_page_for_device,
	.detach_as = opencca_gpu_private_pt_detach,
	.flush_as = opencca_gpu_private_pt_flush_live,
	.sync_page_for_cpu = sync_page_for_cpu,
	.read_page = read_page,
	.protected_mapping_summary = true
};

void opencca_gpu_private_device_revoked(void)
{
	gpu_private_device_revoked(&operations);
	gpu_firmware_device_revoked();
}

void opencca_gpu_private_reclaim(unsigned long rd_addr,
		struct gpu_private_result *result)
{
	struct granule *owner;
	struct rd *rd;
	bool dead;

	memset(result, 0, sizeof(*result));
	result->status = GPU_PRIVATE_INPUT;
	owner = find_lock_granule(rd_addr, GRANULE_STATE_RD);
	if (owner == NULL)
		return;
	/* RD refs count existing RECs, including stopped RECs. The monotonic
	 * rd->rec_count is a creation index, not a live-REC count.
	 */
	dead = granule_refcount_read(owner) == 0U;
	rd = buffer_granule_map(owner, SLOT_RD);
	dead = dead && (get_rd_state_locked(rd) == REALM_ACTIVE ||
		       get_rd_state_locked(rd) == REALM_SYSTEM_OFF);
	buffer_unmap(rd);
	granule_unlock(owner);
	/* RMI dispatch holds xshm_policy_lock. No RD/REC creation or destruction
	 * can race after unlocking; a non-NEW RD cannot acquire new RECs later.
	 * Restore takes RD->RTT->DATA locks itself; never call it with RD locked.
	 */
	if (!gpu_private_owner_busy(owner)) {
		result->status = GPU_PRIVATE_SUCCESS;
		return;
	}
	if (!dead)
		return;
	result->status = GPU_PRIVATE_STATE;
	/* After the old service RD is destroyed, UNOWNED/OFF also have no
	 * MMIO owner. Core preflight still requires every related context to
	 * carry the trusted revocation mark; a state enum alone is no proof.
	 */
	if (opencca_gpu_state() != OPENCCA_GPU_REVOKED &&
	    opencca_gpu_state() != OPENCCA_GPU_UNOWNED &&
	    opencca_gpu_state() != OPENCCA_GPU_OFF)
		return;
	gpu_private_owner_reclaim(&operations, owner, result);
}

static bool firmware_digest(const void *image, size_t bytes, unsigned char output[32])
{
	int status;

	SIMD_FPU_ALLOW(status = mbedtls_sha256(image, bytes, output, 0));
	return status == 0;
}

static void invalidate(const void *memory, size_t bytes)
{
	inv_dcache_range((uintptr_t)memory, bytes);
	dsb(sy);
}

static const struct gpu_firmware_ops firmware_operations = {
	.digest = firmware_digest,
	.address = table_pa,
	.clean = clean,
	.invalidate = invalidate,
	.install = opencca_gpu_firmware_install,
	.boot = opencca_gpu_firmware_boot,
	.configuration = opencca_gpu_firmware_configuration,
	.notify = opencca_gpu_firmware_notify,
	.clock = read_cntpct_el0
};

static bool copy_page_input(struct rec *rec, unsigned long ipa, size_t bytes,
		void *snapshot, struct rsi_result *res)
{
	struct s2_walk_result walk;
	enum s2_walk_status status;
	struct granule *granule;
	void *input;

	if (bytes == 0U || bytes > GRANULE_SIZE || !GRANULE_ALIGNED(ipa) ||
	    !addr_in_rec_par(rec, ipa))
		return false;
	status = realm_ipa_to_pa(rec, ipa, &walk);
	if (status != WALK_SUCCESS) {
		if (status == WALK_FAIL && walk.ripas_val != RIPAS_EMPTY) {
			res->action = STAGE_2_TRANSLATION_FAULT;
			res->rtt_level = walk.rtt_level;
		}
		return false;
	}
	granule = find_granule(walk.pa);
	input = buffer_granule_map(granule, SLOT_RSI_CALL);
	inv_dcache_range((uintptr_t)input, bytes);
	memcpy(snapshot, input, bytes);
	buffer_unmap(input);
	granule_unlock(walk.llt);
	return true;
}

/* The owner is the actual REC's RD, never a field copied from a request. */
static void task_heap_call(struct rec *rec, struct gpu_private_result *result)
{
	const void *owner = rec->realm_info.g_rd;
	unsigned long op = rec->regs[1], peer_id;
	const void *service;

	if (rec->regs[7] != 0UL ||
	    (op != GPU_PRIVATE_TASK_HEAP_EVENT && op != GPU_PRIVATE_TASK_HEAP_GROW) ||
	    (op == GPU_PRIVATE_TASK_HEAP_EVENT &&
	    (rec->regs[4] | rec->regs[5] | rec->regs[6]) != 0UL))
		return;
	service = xshm_endpoint_peer(owner, rec->regs[3], &peer_id);
	if (service == NULL || !opencca_gpu_service_isolated(service))
		return;
	if (op == GPU_PRIVATE_TASK_HEAP_EVENT)
		gpu_firmware_task_heap_event(&firmware_operations, &operations,
			service, owner, rec->regs[2], result);
	else
		gpu_firmware_task_heap_grow(&firmware_operations, &operations,
			service, owner, rec->regs[2], rec->regs[4], rec->regs[5], rec->regs[6], result);
}

void handle_rsi_opencca_gpu_private(struct rec *rec, struct rsi_result *res)
{
	struct gpu_private_result result = {.status = GPU_PRIVATE_INPUT};
	const void *owner = rec->realm_info.g_rd;
	const void *service;
	const void *client;
	unsigned long op = rec->regs[1], handle = rec->regs[2];
	unsigned long a = rec->regs[3], b = rec->regs[4], c = rec->regs[5];
	unsigned long d = rec->regs[6], e = rec->regs[7], peer_id;
	unsigned int cpu = my_cpuid();

	res->action = UPDATE_REC_RETURN_TO_REALM;
	xshm_policy_lock();
	switch (op) {
	case GPU_PRIVATE_VERSION:
		if ((handle | a | b | c | d | e) == 0UL) {
			result.status = GPU_PRIVATE_SUCCESS;
			result.value[0] = GPU_PRIVATE_ABI;
			/* Registration + actual PT construction; no device execution
			 * capability and no hardware-GPC enforcement claim yet.
			 */
			result.value[1] = GPU_PRIVATE_CAP_REGISTRATION |
				GPU_PRIVATE_CAP_PAGE_TABLES | GPU_PRIVATE_CAP_SERVICE_MAPPING |
				GPU_PRIVATE_CAP_MAPPING_AUTH | GPU_PRIVATE_CAP_CONTROL_HANDOFF |
				GPU_PRIVATE_CAP_PT_INSTALL | GPU_PRIVATE_CAP_FW_SNAPSHOT |
				GPU_PRIVATE_CAP_FW_PREPARE | GPU_PRIVATE_CAP_FW_BOOT |
				GPU_PRIVATE_CAP_FW_CONFIG | GPU_PRIVATE_CAP_CONTROL_MEMORY |
				GPU_PRIVATE_CAP_GROUP_MEMORY | GPU_PRIVATE_CAP_GROUP_VALIDATION |
				GPU_PRIVATE_CAP_GROUP_RINGS | GPU_PRIVATE_CAP_TASK_STAGING |
				GPU_PRIVATE_CAP_TASK_PREPARE | GPU_PRIVATE_CAP_TASK_READY |
				GPU_PRIVATE_CAP_TASK_START | GPU_PRIVATE_CAP_TASK_QUIESCE |
				GPU_PRIVATE_CAP_TASK_RETURN | GPU_PRIVATE_CAP_TASK_RETIRE |
				GPU_PRIVATE_CAP_TASK_COMPLETE | GPU_PRIVATE_CAP_MAPPING_CHECK |
				GPU_PRIVATE_CAP_TASK_BATCH | GPU_PRIVATE_CAP_UNMAP_BO |
				GPU_PRIVATE_CAP_TASK_PROGRESS | GPU_PRIVATE_CAP_TASK_PUBLISH |
				GPU_PRIVATE_CAP_TASK_HEAP | GPU_PRIVATE_CAP_BO_RESIDENT |
				GPU_PRIVATE_CAP_BO_UNCACHED | GPU_PRIVATE_CAP_TASK_RECLAIM |
				GPU_PRIVATE_CAP_TASK_READY_PUBLISH | GPU_PRIVATE_CAP_TASK_READY_LAUNCH |
				GPU_PRIVATE_CAP_TASK_FINISH | GPU_PRIVATE_CAP_TASK_DISPATCH | GPU_PRIVATE_CAP_TASK_STAGE_HINT;
			result.value[2] = GPU_PRIVATE_BATCH;
			result.value[3] = GPU_PRIVATE_OBJECTS;
		}
		break;
	case GPU_PRIVATE_BO_CREATE:
	case GPU_PRIVATE_CONTEXT_CREATE:
		if ((c | d | e) != 0UL ||
		    (op == GPU_PRIVATE_CONTEXT_CREATE && (a | b) != 0UL))
			break;
		service = xshm_endpoint_peer(owner, handle, &peer_id);
		/* The peer must be the platform-designated GPU service instance,
		 * not a guest-provided numeric VMID or an arbitrary Realm.
		 */
		if (service == NULL || !opencca_gpu_service_running(service))
			break;
		/* Do not admit private data while the service can still program
		 * arbitrary GPU roots/firmware. Registration is not an opt-out from
		 * the trusted-control boundary, even before the first activation.
		 */
		if (!opencca_gpu_service_isolated(service)) {
			result.status = GPU_PRIVATE_STATE;
			break;
		}
		if (op == GPU_PRIVATE_BO_CREATE)
			gpu_private_bo_create(owner, service, a, b, &result);
		else
			gpu_private_context_create(&operations, owner, service, &result);
		break;
	case GPU_PRIVATE_BO_APPEND:
	case GPU_PRIVATE_CONTROL_APPEND:
		if ((d | e) == 0UL && cpu < MAX_CPUS && b > 0UL &&
		    b <= GPU_PRIVATE_BATCH &&
		    (op != GPU_PRIVATE_CONTROL_APPEND || opencca_gpu_service_isolated(owner)) &&
		    copy_page_input(rec, a, b * sizeof(unsigned long), input_pages[cpu], res)) {
			if (op == GPU_PRIVATE_CONTROL_APPEND)
				gpu_private_control_append(&operations, owner, handle, c,
					input_pages[cpu], b, &result);
			else
				gpu_private_bo_append(&operations, owner, handle, c,
					input_pages[cpu], b, &result);
		}
		break;
	case GPU_PRIVATE_CONTROL_CREATE:
		if ((handle | b | c | d | e) == 0UL && opencca_gpu_service_isolated(owner))
			gpu_private_control_create(owner, a, &result);
		break;
	case GPU_PRIVATE_CONTROL_DESTROY:
		/* Scrub/restore is also needed after trusted RELEASE, when the
		 * service no longer owns an active isolated GPU session. Actual RD
		 * identity and the private control-object type remain mandatory.
		 */
		if ((a | b | c | d | e) == 0UL)
			gpu_private_control_destroy(&operations, owner, handle, &result);
		break;
	case GPU_PRIVATE_BO_DESTROY:
		if ((a | b | c | d | e) == 0UL)
			gpu_private_bo_destroy(owner, handle, &result);
		break;
	case GPU_PRIVATE_BO_SEAL:
		if ((a | b | c | d | e) == 0UL)
			gpu_private_bo_seal(&operations, owner, handle, &result);
		break;
	case GPU_PRIVATE_BO_RELEASE:
		if ((a | b | c | d | e) == 0UL)
			gpu_private_bo_release(&operations, owner, handle, &result);
		break;
	case GPU_PRIVATE_BO_UNCACHED:
		if ((a | b | c | d | e) == 0UL)
			gpu_private_bo_uncached(&operations, owner, handle, &result);
		break;
	case GPU_PRIVATE_CONTEXT_DESTROY:
		if ((a | b | c | d | e) == 0UL) {
			gpu_firmware_context_yield(&firmware_operations, &operations, owner, handle, &result);
			if (result.status == GPU_PRIVATE_SUCCESS)
				gpu_private_context_destroy(&operations, owner, handle, &result);
		}
		break;
	case GPU_PRIVATE_MAP:
		gpu_firmware_context_yield(&firmware_operations, &operations, owner, handle, &result);
		if (result.status == GPU_PRIVATE_SUCCESS)
			gpu_private_map(&operations, owner, handle, a, b, c, d, e, &result);
		break;
	case GPU_PRIVATE_MAP_AUTHORIZE:
		/* Native VM_BIND first creates a Client grant and only later lets
		 * SERVICE_MAP consume it. Yield before adding pending: that grant
		 * must not make the old internal domain impossible to retire.
		 */
		gpu_firmware_context_yield(&firmware_operations, &operations, owner, handle, &result);
		if (result.status == GPU_PRIVATE_SUCCESS)
			gpu_private_map_authorize(owner, handle, a, b, c, d, e, &result);
		break;
	case GPU_PRIVATE_MAP_CANCEL:
		if ((a | b | c | d | e) == 0UL)
			gpu_private_map_cancel(owner, handle, &result);
		break;
	case GPU_PRIVATE_UNMAP:
		if ((c | d | e) == 0UL) {
			gpu_firmware_context_yield(&firmware_operations, &operations, owner, handle, &result);
			if (result.status == GPU_PRIVATE_SUCCESS)
				gpu_private_unmap(&operations, owner, handle, a, b, &result);
		}
		break;
	case GPU_PRIVATE_UNMAP_BO:
		if (e == 0UL) {
			gpu_firmware_context_yield(&firmware_operations, &operations, owner, handle, &result);
			if (result.status == GPU_PRIVATE_SUCCESS)
				gpu_private_unmap_bo(&operations, owner, handle, a, b, c, d, &result);
		}
		break;
	case GPU_PRIVATE_CONTEXT_ACTIVATE:
		/* Client root install must never be reached while raw MMIO remains
		 * available. Queue/launch and live Client-AS switching remain absent.
		 */
		if ((b | c | d | e) == 0UL && a != 0UL && a < GPU_PRIVATE_AS_SLOTS &&
		    opencca_gpu_service_isolated(owner))
			gpu_private_context_activate(&operations, owner, handle, a, &result);
		break;
	case GPU_PRIVATE_MAPPING_CHECK:
		gpu_private_mapping_check(&operations, owner, handle, a, b, c, d, e, &result);
		break;
	case GPU_PRIVATE_QUERY:
		if ((b | c | d | e) == 0UL)
			gpu_private_query(owner, handle, a, &result);
		break;
	case GPU_PRIVATE_BO_INSPECT:
	case GPU_PRIVATE_CONTEXT_INSPECT:
		if ((b | c | d | e) != 0UL || !opencca_gpu_service_isolated(owner))
			break;
		client = xshm_endpoint_peer(owner, handle, &peer_id);
		if (client == NULL)
			break;
		if (op == GPU_PRIVATE_BO_INSPECT)
			gpu_private_bo_inspect(owner, client, a, &result);
		else
			gpu_private_context_inspect(owner, client, a, &result);
		break;
	case GPU_PRIVATE_SERVICE_MAP:
	case GPU_PRIVATE_SERVICE_UNMAP:
	case GPU_PRIVATE_SERVICE_MAP_RELEASE:
		if (!opencca_gpu_service_isolated(owner))
			break;
		client = xshm_endpoint_peer(owner, a, &peer_id);
		if (client == NULL)
			break;
		if (op == GPU_PRIVATE_SERVICE_MAP ||
		    (op == GPU_PRIVATE_SERVICE_UNMAP && (d | e) == 0UL)) {
			gpu_firmware_context_yield(&firmware_operations, &operations, client, handle, &result);
			if (result.status != GPU_PRIVATE_SUCCESS)
				break;
		}
		if (op == GPU_PRIVATE_SERVICE_MAP)
			gpu_private_service_map(&operations, owner, client, handle,
				b, c, d, e >> 8U, e & 255UL, &result);
		else if (op == GPU_PRIVATE_SERVICE_UNMAP && (d | e) == 0UL)
			gpu_private_service_unmap(&operations, owner, client,
				handle, b, c, &result);
		else if (op == GPU_PRIVATE_SERVICE_MAP_RELEASE && (c | d | e) == 0UL)
			gpu_private_service_map_release(owner, client, handle, b, &result);
		break;
	case GPU_PRIVATE_SERVICE_ISOLATE:
		if ((handle | a | b | c | d | e) == 0UL &&
		    opencca_gpu_isolate_service(owner)) {
			result.status = GPU_PRIVATE_SUCCESS;
			result.value[0] = 1UL; /* Raw MMIO revoked; not an execution grant. */
		}
		break;
	case GPU_PRIVATE_FW_BEGIN:
		if ((handle | b | c | d | e) == 0UL &&
		    opencca_gpu_service_isolated(owner))
			gpu_firmware_begin(owner, a, &result);
		break;
	case GPU_PRIVATE_FW_WRITE:
		if ((handle | d | e) == 0UL && cpu < MAX_CPUS &&
		    opencca_gpu_service_isolated(owner) &&
		    copy_page_input(rec, a, b, input_pages[cpu], res))
			gpu_firmware_write(owner, c, input_pages[cpu], b, &result);
		break;
	case GPU_PRIVATE_FW_SEAL:
	case GPU_PRIVATE_FW_INSPECT:
	case GPU_PRIVATE_FW_PREPARE:
	case GPU_PRIVATE_FW_BOOT:
	case GPU_PRIVATE_FW_CONFIGURE:
		if ((handle | a | b | c | d | e) == 0UL &&
		    opencca_gpu_service_isolated(owner)) {
			if (op == GPU_PRIVATE_FW_SEAL)
				gpu_firmware_seal(&firmware_operations, owner, &result);
			else if (op == GPU_PRIVATE_FW_PREPARE)
				gpu_firmware_prepare(&firmware_operations, owner, &result);
			else if (op == GPU_PRIVATE_FW_BOOT)
				gpu_firmware_boot(&firmware_operations, owner, &result);
			else if (op == GPU_PRIVATE_FW_CONFIGURE)
				gpu_firmware_configure(&firmware_operations, owner, &result);
			else
				gpu_firmware_inspect(owner, &result);
		}
		break;
	case GPU_PRIVATE_FW_PROPERTIES:
		if ((handle | b | c | d | e) == 0UL &&
		    opencca_gpu_service_isolated(owner))
			gpu_firmware_properties(owner, a, &result);
		break;
	case GPU_PRIVATE_FW_CONTROL_BIND:
		if ((a | b | c | d | e) == 0UL && opencca_gpu_service_isolated(owner))
			gpu_firmware_control_bind(&firmware_operations, &operations, owner, handle, &result);
		break;
	case GPU_PRIVATE_GROUP_CREATE:
		if ((c | d | e) != 0UL)
			break;
		service = xshm_endpoint_peer(owner, a, &peer_id);
		if (service != NULL && opencca_gpu_service_isolated(service)) {
			gpu_firmware_context_yield(&firmware_operations, &operations, owner, handle, &result);
			if (result.status == GPU_PRIVATE_SUCCESS)
				gpu_firmware_group_create(&firmware_operations, &operations,
					service, owner, handle, b, &result);
		}
		break;
	case GPU_PRIVATE_GROUP_DESTROY:
		if ((a | b | c | d | e) == 0UL) {
			gpu_firmware_group_yield(&firmware_operations, &operations, owner, handle, &result);
			if (result.status == GPU_PRIVATE_SUCCESS)
				gpu_firmware_group_destroy(&operations, owner, handle, &result);
		}
		break;
	case GPU_PRIVATE_GROUP_VALIDATE:
		if ((d == 0UL && e != 0UL) || !opencca_gpu_service_isolated(owner))
			break;
		client = xshm_endpoint_peer(owner, a, &peer_id);
		if (client != NULL) {
			gpu_firmware_group_validate(owner, client, b, handle, c, &result);
			if (result.status == GPU_PRIVATE_SUCCESS && d != 0UL)
				gpu_firmware_group_queue_validate(owner, client, handle,
					d - 1UL, e & UINT32_MAX, e >> 32U, &result);
		}
		break;
	case GPU_PRIVATE_GROUP_CONFIGURE:
		if ((d | e) != 0UL || c == 0UL || c > GPU_FIRMWARE_STREAMS)
			break;
		service = xshm_endpoint_peer(owner, b, &peer_id);
		if (service != NULL && opencca_gpu_service_isolated(service) &&
		    copy_page_input(rec, a, c * sizeof(input_queues[0][0]), input_queues[cpu], res)) {
			gpu_firmware_group_yield(&firmware_operations, &operations, owner, handle, &result);
			if (result.status == GPU_PRIVATE_SUCCESS)
				gpu_firmware_group_configure(&operations, service, owner, handle,
					input_queues[cpu], c, &result);
		}
		break;
	case GPU_PRIVATE_TASK_STAGE:
		service = xshm_endpoint_peer(owner, a, &peer_id);
		if (service != NULL && opencca_gpu_service_isolated(service)) {
			gpu_firmware_group_yield(&firmware_operations, &operations, owner, handle, &result);
			if (result.status == GPU_PRIVATE_SUCCESS)
				gpu_firmware_task_stage(&operations, service, owner, handle, b, c, d, e, &result);
		}
		break;
	case GPU_PRIVATE_TASK_STAGE_HINT:
	case GPU_PRIVATE_TASK_STAGE_BATCH:
		if ((d & ~(GPU_PRIVATE_TASK_DEFERRED | GPU_PRIVATE_TASK_DELEGATE)) != 0UL ||
		    ((d & GPU_PRIVATE_TASK_DELEGATE) != 0UL && (d & GPU_PRIVATE_TASK_DEFERRED) == 0UL) ||
		    (op == GPU_PRIVATE_TASK_STAGE_BATCH ? e != 0UL : (e == 0UL || c != 1UL)) ||
		    c == 0UL || c > GPU_PRIVATE_TASK_BATCH)
			break;
		service = xshm_endpoint_peer(owner, b, &peer_id);
		if (service != NULL && opencca_gpu_service_isolated(service) &&
		    copy_page_input(rec, a, c * sizeof(input_commands[0][0]), input_commands[cpu], res)) {
			if (op == GPU_PRIVATE_TASK_STAGE_HINT)
				gpu_firmware_task_stage_hint(&firmware_operations, &operations, service, owner, handle,
					input_commands[cpu], (unsigned int)c, d, e, &result);
			else
				gpu_firmware_task_stage_domain(&firmware_operations, &operations, service, owner, handle,
					input_commands[cpu], (unsigned int)c, d, &result);
		}
		break;
	case GPU_PRIVATE_TASK_PUBLISH:
		if ((c | d | e) != 0UL)
			break;
		service = xshm_endpoint_peer(owner, a, &peer_id);
		if (service != NULL && opencca_gpu_service_isolated(service))
			gpu_firmware_task_publish(&firmware_operations, &operations,
				service, owner, handle, b, &result);
		break;
	case GPU_PRIVATE_TASK_CANCEL:
		if ((a | b | c | d | e) == 0UL)
			gpu_firmware_task_cancel_staged(&operations, owner, handle, &result);
		break;
	case GPU_PRIVATE_TASK_HEAP_EVENT:
	case GPU_PRIVATE_TASK_HEAP_GROW:
		task_heap_call(rec, &result);
		break;
	case GPU_PRIVATE_TASK_READY:
	case GPU_PRIVATE_TASK_READY_PUBLISH:
	case GPU_PRIVATE_TASK_READY_LAUNCH:
	case GPU_PRIVATE_TASK_RETURN:
	case GPU_PRIVATE_TASK_RETIRE:
	case GPU_PRIVATE_TASK_COMPLETE:
	case GPU_PRIVATE_TASK_PROGRESS:
	case GPU_PRIVATE_TASK_RECLAIM:
	case GPU_PRIVATE_TASK_FINISH:
		if ((b | c | d | e) != 0UL)
			break;
		service = xshm_endpoint_peer(owner, a, &peer_id);
		if (service != NULL && opencca_gpu_service_isolated(service)) {
			if (op == GPU_PRIVATE_TASK_FINISH)
				gpu_firmware_task_finish_domain(&firmware_operations, &operations,
					service, owner, handle, &result);
			else if (op == GPU_PRIVATE_TASK_READY_LAUNCH)
				gpu_firmware_task_ready_launch(&firmware_operations, &operations,
					service, owner, handle, &result);
			else if (op == GPU_PRIVATE_TASK_READY_PUBLISH)
				gpu_firmware_task_ready_publish(&firmware_operations, &operations,
					service, owner, handle, &result);
			else if (op == GPU_PRIVATE_TASK_RECLAIM)
				gpu_firmware_task_reclaim(&firmware_operations, &operations,
					service, owner, handle, &result);
			else if (op == GPU_PRIVATE_TASK_PROGRESS)
				gpu_firmware_task_progress(&firmware_operations, &operations,
					service, owner, handle, &result);
			else if (op == GPU_PRIVATE_TASK_COMPLETE)
				gpu_firmware_task_complete(&firmware_operations, &operations,
					service, owner, handle, &result);
			else if (op == GPU_PRIVATE_TASK_RETIRE)
				gpu_firmware_task_retire(&firmware_operations, &operations,
					service, owner, handle, &result);
			else if (op == GPU_PRIVATE_TASK_RETURN)
				gpu_firmware_task_return(&firmware_operations, &operations,
					service, owner, handle, &result);
			else
				gpu_firmware_task_ready(&firmware_operations, &operations,
					service, owner, handle, &result);
		}
		break;
	case GPU_PRIVATE_TASK_VALIDATE:
	case GPU_PRIVATE_TASK_PREPARE:
	case GPU_PRIVATE_TASK_PREPARE_LAUNCH:
	case GPU_PRIVATE_TASK_DISPATCH:
	case GPU_PRIVATE_TASK_START:
	case GPU_PRIVATE_TASK_QUIESCE:
		if ((d | e) != 0UL || !opencca_gpu_service_isolated(owner))
			break;
		client = xshm_endpoint_peer(owner, a, &peer_id);
		if (client != NULL) {
			if (op == GPU_PRIVATE_TASK_DISPATCH)
				gpu_firmware_task_dispatch(&firmware_operations, &operations,
					owner, client, b, c, handle, &result);
			else if (op == GPU_PRIVATE_TASK_PREPARE_LAUNCH)
				gpu_firmware_task_prepare_launch(&firmware_operations, &operations,
					owner, client, b, c, handle, &result);
			else if (op == GPU_PRIVATE_TASK_PREPARE)
				gpu_firmware_task_prepare(&firmware_operations, &operations,
					owner, client, b, c, handle, &result);
			else if (op == GPU_PRIVATE_TASK_START)
				gpu_firmware_task_start(&firmware_operations, &operations,
					owner, client, b, c, handle, &result);
			else if (op == GPU_PRIVATE_TASK_QUIESCE)
				gpu_firmware_task_quiesce(&firmware_operations, &operations,
					owner, client, b, c, handle, &result);
			else
				gpu_firmware_task_validate(owner, client, b, c, handle, &result);
		}
		break;
	case GPU_PRIVATE_GROUP_INSPECT:
		if ((b | c | d | e) != 0UL)
			break;
		client = xshm_endpoint_peer(owner, a, &peer_id);
		if (client == NULL)
			break;
		if (opencca_gpu_service_isolated(owner))
			gpu_firmware_group_inspect(owner, client, handle, &result);
		else if (opencca_gpu_service_isolated(client))
			gpu_firmware_group_inspect(client, owner, handle, &result);
		break;
	default:
		break;
	}
	xshm_policy_unlock();
	memset(&res->smc_res, 0, sizeof(res->smc_res));
	res->smc_res.x[0] = result.status;
	for (unsigned int i = 0U; i < 4U; i++)
		res->smc_res.x[i + 1U] = result.value[i];
}
