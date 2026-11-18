/* SPDX-License-Identifier: BSD-3-Clause */
#include <arch_helpers.h>
#include <buffer.h>
#include <cpuid.h>
#include <granule.h>
#include <opencca_gpu.h>
#include <opencca_gpu_firmware.h>
#include <opencca_gpu_private.h>
#include <opencca_gpu_lease.h>
#include <opencca_gpu_irq.h>
#include <opencca_iommu.h>
#include <mbedtls/sha256.h>
#include <realm.h>
#include <rec.h>
#include <rsi-handler.h>
#include <string.h>
#include <simd.h>
#include <spinlock.h>
#include <plat_common.h>
#include <xshm_endpoint.h>
#include <xshm_runtime.h>

/* Private snapshots, not a shared descriptor consumed after validation. */
static unsigned long input_pages[MAX_CPUS][GPU_PRIVATE_BATCH];
static struct gpu_firmware_queue_config input_queues[MAX_CPUS]
						    [GPU_FIRMWARE_STREAMS];
static struct gpu_firmware_task_command input_commands[MAX_CPUS]
						      [GPU_PRIVATE_TASK_BATCH];

_Static_assert(CACHE_WRITEBACK_GRANULE == GPU_FIRMWARE_CACHE_LINE,
	       "Firmware interfaces must not share CPU cache-maintenance lines");

/* Persistent CPU aliases only for donated internal control backing. The
 * core's registration/hidden/mapped references own their lifetime. Every
 * access still holds a fresh DATA granule lock and does full cache ordering.
 */
struct control_cpu_view {
	unsigned long pa, control;
	const void *owner;
	unsigned int index;
	bool usable;
};
static struct control_cpu_view control_views[PLAT_CMN_GPU_CONTROL_SLOTS];
static spinlock_t control_views_lock;
static unsigned int control_views_pinned;
static unsigned long control_view_hits, control_view_misses;
_Static_assert(PLAT_CMN_GPU_CONTROL_SLOTS == 8192U, "Control view hash width");
_Static_assert(PLAT_CMN_GPU_CONTROL_SLOTS >= 2U * GPU_PRIVATE_CONTROL_PAGES,
	       "Control view capacity must not expand the physical page budget");

static unsigned int control_view_find(unsigned long pa, bool *found)
{
	unsigned int first = PLAT_CMN_GPU_CONTROL_SLOTS;
	unsigned int hash =
		(unsigned int)(((pa >> 12U) * UINT64_C(0x9e3779b97f4a7c15)) >>
			       51U);

	*found = false;
	for (unsigned int n = 0U; n < PLAT_CMN_GPU_CONTROL_SLOTS; n++) {
		unsigned int i = (hash + n) & (PLAT_CMN_GPU_CONTROL_SLOTS - 1U);
		if (control_views[i].pa == pa) {
			*found = true;
			return i;
		}
		if (control_views[i].pa == 1UL &&
		    first == PLAT_CMN_GPU_CONTROL_SLOTS)
			first = i;
		if (control_views[i].pa == 0UL)
			return first == PLAT_CMN_GPU_CONTROL_SLOTS ? i : first;
	}
	return first;
}

static bool pin_control_page(const void *owner, unsigned long control,
			     unsigned int index, unsigned long pa)
{
	struct granule *data;
	bool found, pinned = false;
	void *memory = NULL;

	if (owner == NULL || control == 0UL ||
	    index >= GPU_PRIVATE_CONTROL_PAGES || pa == 0UL ||
	    !GRANULE_ALIGNED(pa) || pa >= (1UL << 40U))
		return false;
	data = find_lock_granule(pa, GRANULE_STATE_DATA);
	if (data == NULL)
		return false;
	spinlock_acquire(&control_views_lock);
	unsigned int i = control_view_find(pa, &found);
	if (found) {
		pinned = control_views[i].usable &&
			 control_views[i].owner == owner &&
			 control_views[i].control == control &&
			 control_views[i].index == index;
	} else if (i < PLAT_CMN_GPU_CONTROL_SLOTS &&
		   control_views_pinned < GPU_PRIVATE_CONTROL_PAGES) {
		/* Record possible exposure BEFORE the S1 operation. Failed/partial
		 * installation stays owned, unusable and charged until exact unpin.
		 */
		control_views[i] = (struct control_cpu_view){ pa, control,
							      owner, index,
							      false };
		control_views_pinned++;
		pinned = plat_cmn_gpu_control_map(i, pa, &memory) == 0;
		control_views[i].usable = pinned;
	}
	spinlock_release(&control_views_lock);
	granule_unlock(data);
	return pinned;
}

static bool unpin_control_page(const void *owner, unsigned long control,
			       unsigned int index, unsigned long pa)
{
	struct granule *data;
	bool found, released = false;

	if (owner == NULL || control == 0UL ||
	    index >= GPU_PRIVATE_CONTROL_PAGES || pa == 0UL ||
	    !GRANULE_ALIGNED(pa) || pa >= (1UL << 40U))
		return false;
	data = find_lock_granule(pa, GRANULE_STATE_DATA);
	if (data == NULL)
		return false;
	spinlock_acquire(&control_views_lock);
	unsigned int i = control_view_find(pa, &found);
	if (!found)
		released = true; /* Pin failed before installing a record. */
	else if (control_views[i].owner == owner &&
		 control_views[i].control == control &&
		 control_views[i].index == index) {
		control_views[i].usable = false;
		if (plat_cmn_gpu_control_unmap(i, pa) == 0) {
			/* All PEs have retired translations before metadata/RTT can release. */
			control_views[i] =
				(struct control_cpu_view){ .pa = 1UL };
			control_views_pinned--;
			released = true;
		}
	}
	spinlock_release(&control_views_lock);
	granule_unlock(data);
	return released;
}

/* Caller keeps this PA's DATA lock until copy/order completion; unpin takes
 * that same lock before changing the S1 entry, even outside the RSI path.
 */
static void *control_view_address(unsigned long pa)
{
	bool found;
	void *memory = NULL;

	spinlock_acquire(&control_views_lock);
	unsigned int i = control_view_find(pa, &found);
	if (found && control_views[i].usable) {
		memory = (void *)(PLAT_CMN_GPU_CONTROL_BASE +
				  (uintptr_t)i * GRANULE_SIZE);
		if (control_view_hits != ~0UL)
			control_view_hits++;
	} else if (control_view_misses != ~0UL)
		control_view_misses++;
	spinlock_release(&control_views_lock);
	return memory;
}

static void control_view_statistics(unsigned long values[4])
{
	spinlock_acquire(&control_views_lock);
	values[0] = control_view_hits;
	values[1] = control_view_misses;
	values[2] = control_views_pinned;
	values[3] = 7UL;
	spinlock_release(&control_views_lock);
}

static bool source_page(const void *owner, unsigned long ipa, unsigned long *pa)
{
	/* A private GPU BO cannot reuse a CPU-shared source/borrowed alias or
	 * register a page already held by another private BO.
	 */
	if (xshm_memory_range_busy(owner, ipa, GRANULE_SIZE) ||
	    gpu_private_range_busy(owner, ipa, GRANULE_SIZE) ||
	    opencca_iommu_range_busy(owner, ipa, GRANULE_SIZE))
		return false;
	return xshm_rtt_ops.source_page(owner, ipa, pa) &&
	       !opencca_gpu_page_busy(*pa);
}

static bool clear_page(unsigned long pa)
{
	struct granule *data = find_lock_granule(pa, GRANULE_STATE_DATA);
	void *memory;
	bool persistent;

	if (data == NULL)
		return false;
	memory = control_view_address(pa);
	persistent = memory != NULL;
	if (!persistent)
		memory = buffer_granule_map(data, SLOT_RSI_CALL);
	inv_dcache_range((uintptr_t)memory, GRANULE_SIZE);
	memset(memory, 0, GRANULE_SIZE);
	clean_dcache_range((uintptr_t)memory, GRANULE_SIZE);
	dsb(sy);
	if (persistent) {
		dsb(sy);
		isb();
	} else
		buffer_unmap(memory);
	granule_unlock(data);
	return true;
}

static bool write_page(unsigned long pa, size_t offset, const void *source,
		       size_t bytes)
{
	struct granule *data;
	void *memory;
	bool persistent;

	if (source == NULL || bytes == 0U || offset > GRANULE_SIZE ||
	    bytes > GRANULE_SIZE - offset)
		return false;
	data = find_lock_granule(pa, GRANULE_STATE_DATA);
	if (data == NULL)
		return false;
	memory = control_view_address(pa);
	persistent = memory != NULL;
	if (!persistent)
		memory = buffer_granule_map(data, SLOT_RSI_CALL);
	/* Fully donated pages have no untrusted CPU aliases. The firmware core
	 * owns this range: ring preparation requires STOP or a drained producer
	 * that cannot reach the new wrappers until a separate Client publication.
	 */
	inv_dcache_range((uintptr_t)memory + offset, bytes);
	memcpy((unsigned char *)memory + offset, source, bytes);
	clean_dcache_range((uintptr_t)memory + offset, bytes);
	dsb(sy);
	if (persistent) {
		dsb(sy);
		isb();
	} else
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

static bool read_page(unsigned long pa, size_t offset, void *destination,
		      size_t bytes)
{
	struct granule *data;
	void *memory;
	bool persistent;

	if (destination == NULL || bytes == 0U || offset > GRANULE_SIZE ||
	    bytes > GRANULE_SIZE - offset)
		return false;
	data = find_lock_granule(pa, GRANULE_STATE_DATA);
	if (data == NULL)
		return false;
	memory = control_view_address(pa);
	persistent = memory != NULL;
	if (!persistent)
		memory = buffer_granule_map(data, SLOT_RSI_CALL);
	/* All callers resolve CPU-hidden, donated control pages from trusted
	 * records. Discard speculative/stale CPU cache lines before the snapshot.
	 */
	inv_dcache_range((uintptr_t)memory, GRANULE_SIZE);
	dsb(sy);
	memcpy(destination, (const unsigned char *)memory + offset, bytes);
	if (persistent) {
		dsb(sy);
		isb();
	} else
		buffer_unmap(memory);
	granule_unlock(data);
	return true;
}

static bool map_command_page(unsigned long pa,
			     struct gpu_private_command_view *view)
{
	struct granule *data;

	if (view == NULL)
		return false;
	memset(view, 0, sizeof(*view));
	data = find_lock_granule(pa, GRANULE_STATE_DATA);
	if (data == NULL)
		return false;
	view->address = buffer_granule_map(data, SLOT_RSI_CALL);
	view->granule = data;
	/* The caller already checked the live private PTE/owner and exact
	 * command extent. Hold this DATA granule only until that page's final
	 * opcode or first error; do not retain an alias across pages or calls.
	 * As before, this is not a CPU-return cache invalidation operation.
	 */
	return true;
}

static void unmap_command_page(struct gpu_private_command_view *view)
{
	buffer_unmap((void *)view->address);
	granule_unlock(view->granule);
	memset(view, 0, sizeof(*view));
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

static bool activate(unsigned long context, unsigned long root,
		     unsigned int slot)
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
	.map_command_page = map_command_page,
	.unmap_command_page = unmap_command_page,
	.pin_control_page = pin_control_page,
	.unpin_control_page = unpin_control_page,
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

static bool firmware_digest(const void *image, size_t bytes,
			    unsigned char output[32])
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

static void irq_next(unsigned int csg, uint64_t epoch, uint64_t after,
		     struct gpu_private_result *result)
{
	unsigned int status =
		opencca_gpu_irq_next(csg, epoch, after, result->value);
	result->status = status == 0U ? GPU_PRIVATE_SUCCESS :
			 status == 4U ? GPU_PRIVATE_INCOMPLETE :
					GPU_PRIVATE_STATE;
}

static void irq_claim(unsigned int csg, uint64_t epoch, uint64_t after,
		      uint64_t sequence, uint64_t binding_epoch,
		      uint64_t device_epoch, unsigned int kind, bool completed,
		      struct gpu_private_result *result)
{
	unsigned int status = opencca_gpu_irq_claim(csg, epoch, after, sequence,
						    binding_epoch, device_epoch,
						    kind, completed);
	memset(result, 0, sizeof(*result));
	result->status = status == 0U ? GPU_PRIVATE_SUCCESS :
			 status == 5U ? GPU_PRIVATE_INPUT :
					GPU_PRIVATE_STATE;
	if (status == 0U) {
		result->value[0] = sequence;
		result->value[1] = binding_epoch;
		result->value[2] = kind;
		result->value[3] = device_epoch;
	}
}

static void irq_stats(unsigned int selector, struct gpu_private_result *result)
{
	memset(result, 0, sizeof(*result));
	result->status = opencca_gpu_irq_status(selector, result->value) ?
				 GPU_PRIVATE_SUCCESS :
				 GPU_PRIVATE_STATE;
}

static const struct gpu_firmware_irq_ops irq_operations = {
	.start = opencca_gpu_irq_start,
	.revoke = opencca_gpu_irq_revoke,
	.bind = opencca_gpu_irq_bind,
	.sync = opencca_gpu_irq_sync,
	.begin = opencca_gpu_irq_begin,
	.close = opencca_gpu_irq_close,
	.next = irq_next,
	.claim = irq_claim,
	.stats = irq_stats,
	.selftest = opencca_gpu_irq_selftest
};

static const struct gpu_firmware_ops firmware_operations = {
	.digest = firmware_digest,
	.address = table_pa,
	.clean = clean,
	.invalidate = invalidate,
	.install = opencca_gpu_firmware_install,
	.boot = opencca_gpu_firmware_boot,
	.configuration = opencca_gpu_firmware_configuration,
	.notify = opencca_gpu_firmware_notify,
	.notify_queue = opencca_gpu_firmware_queue_notify,
	.clock = read_cntpct_el0,
	.irq = &irq_operations
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
	    (op != GPU_PRIVATE_TASK_HEAP_EVENT &&
	     op != GPU_PRIVATE_TASK_HEAP_GROW) ||
	    (op == GPU_PRIVATE_TASK_HEAP_EVENT &&
	     (rec->regs[4] | rec->regs[5] | rec->regs[6]) != 0UL))
		return;
	service = xshm_endpoint_peer(owner, rec->regs[3], &peer_id);
	if (service == NULL ||
	    !opencca_gpu_service_isolated(service, xshm_endpoint_id(service)))
		return;
	if (op == GPU_PRIVATE_TASK_HEAP_EVENT)
		gpu_firmware_task_heap_event(&firmware_operations, &operations,
					     service, owner, rec->regs[2],
					     result);
	else
		gpu_firmware_task_heap_grow(&firmware_operations, &operations,
					    service, owner, rec->regs[2],
					    rec->regs[4], rec->regs[5],
					    rec->regs[6], result);
}

void handle_rsi_opencca_gpu_private(struct rec *rec, struct rsi_result *res)
{
	struct gpu_private_result result = { .status = GPU_PRIVATE_INPUT };
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
					  GPU_PRIVATE_CAP_PAGE_TABLES |
					  GPU_PRIVATE_CAP_SERVICE_MAPPING |
					  GPU_PRIVATE_CAP_MAPPING_AUTH |
					  GPU_PRIVATE_CAP_CONTROL_HANDOFF |
					  GPU_PRIVATE_CAP_PT_INSTALL |
					  GPU_PRIVATE_CAP_FW_SNAPSHOT |
					  GPU_PRIVATE_CAP_FW_PREPARE |
					  GPU_PRIVATE_CAP_FW_BOOT |
					  GPU_PRIVATE_CAP_FW_CONFIG |
					  GPU_PRIVATE_CAP_CONTROL_MEMORY |
					  GPU_PRIVATE_CAP_GROUP_MEMORY |
					  GPU_PRIVATE_CAP_GROUP_VALIDATION |
					  GPU_PRIVATE_CAP_GROUP_RINGS |
					  GPU_PRIVATE_CAP_TASK_STAGING |
					  GPU_PRIVATE_CAP_TASK_PREPARE |
					  GPU_PRIVATE_CAP_TASK_READY |
					  GPU_PRIVATE_CAP_TASK_START |
					  GPU_PRIVATE_CAP_TASK_QUIESCE |
					  GPU_PRIVATE_CAP_TASK_RETURN |
					  GPU_PRIVATE_CAP_TASK_RETIRE |
					  GPU_PRIVATE_CAP_TASK_COMPLETE |
					  GPU_PRIVATE_CAP_MAPPING_CHECK |
					  GPU_PRIVATE_CAP_TASK_BATCH |
					  GPU_PRIVATE_CAP_UNMAP_BO |
					  GPU_PRIVATE_CAP_TASK_PROGRESS |
					  GPU_PRIVATE_CAP_TASK_PUBLISH |
					  GPU_PRIVATE_CAP_TASK_HEAP |
					  GPU_PRIVATE_CAP_BO_RESIDENT |
					  GPU_PRIVATE_CAP_BO_UNCACHED |
					  GPU_PRIVATE_CAP_TASK_RECLAIM |
					  GPU_PRIVATE_CAP_TASK_READY_PUBLISH |
					  GPU_PRIVATE_CAP_TASK_READY_LAUNCH |
					  GPU_PRIVATE_CAP_TASK_FINISH |
					  GPU_PRIVATE_CAP_TASK_DISPATCH |
					  GPU_PRIVATE_CAP_TASK_STAGE_HINT |
					  GPU_PRIVATE_CAP_MAP_TRANSACTION |
					  GPU_PRIVATE_CAP_TASK_MAPPING_VERSION |
					  GPU_PRIVATE_CAP_TASK_DISPATCH_LIVE |
					  GPU_PRIVATE_CAP_BO_IDLE |
					  GPU_PRIVATE_CAP_TASK_OBSERVATION |
					  GPU_PRIVATE_CAP_TASK_OBSERVER;
			result.value[2] = GPU_PRIVATE_BATCH;
			if (firmware_operations.irq != NULL)
				result.value[1] |= GPU_PRIVATE_CAP_IRQ_SECURITY;
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
		if (service == NULL ||
		    !opencca_gpu_service_running(service,
						 xshm_endpoint_id(service)))
			break;
		/* Do not admit private data while the service can still program
		 * arbitrary GPU roots/firmware. Registration is not an opt-out from
		 * the trusted-control boundary, even before the first activation.
		 */
		if (!opencca_gpu_service_isolated(service,
						  xshm_endpoint_id(service))) {
			result.status = GPU_PRIVATE_STATE;
			break;
		}
		if (op == GPU_PRIVATE_BO_CREATE)
			gpu_private_bo_create(owner, service, a, b, &result);
		else
			gpu_private_context_create(&operations, owner, service,
						   &result);
		break;
	case GPU_PRIVATE_BO_APPEND:
	case GPU_PRIVATE_CONTROL_APPEND:
		if ((d | e) == 0UL && cpu < MAX_CPUS && b > 0UL &&
		    b <= GPU_PRIVATE_BATCH &&
		    (op != GPU_PRIVATE_CONTROL_APPEND ||
		     opencca_gpu_service_isolated(owner,
						  xshm_endpoint_id(owner))) &&
		    copy_page_input(rec, a, b * sizeof(unsigned long),
				    input_pages[cpu], res)) {
			if (op == GPU_PRIVATE_CONTROL_APPEND)
				gpu_private_control_append(&operations, owner,
							   handle, c,
							   input_pages[cpu], b,
							   &result);
			else
				gpu_private_bo_append(&operations, owner,
						      handle, c,
						      input_pages[cpu], b,
						      &result);
		}
		break;
	case GPU_PRIVATE_CONTROL_CREATE:
		if ((handle | b | c | d | e) == 0UL &&
		    opencca_gpu_service_isolated(owner,
						 xshm_endpoint_id(owner)))
			gpu_private_control_create(owner, a, &result);
		break;
	case GPU_PRIVATE_CONTROL_DESTROY:
		/* Scrub/restore is also needed after trusted RELEASE, when the
		 * service no longer owns an active isolated GPU session. Actual RD
		 * identity and the private control-object type remain mandatory.
		 */
		if ((a | b | c | d | e) == 0UL)
			gpu_private_control_destroy(&operations, owner, handle,
						    &result);
		break;
	case GPU_PRIVATE_BO_DESTROY:
		if ((a | b | c | d | e) == 0UL)
			gpu_private_bo_destroy(owner, handle, &result);
		break;
	case GPU_PRIVATE_BO_SEAL:
		if ((a | b | c | d | e) == 0UL)
			gpu_private_bo_seal(&operations, owner, handle,
					    &result);
		break;
	case GPU_PRIVATE_BO_RELEASE:
		if ((a | b | c | d | e) == 0UL)
			gpu_private_bo_release(&operations, owner, handle,
					       &result);
		break;
	case GPU_PRIVATE_BO_IDLE:
		if ((a | b | c | d | e) == 0UL)
			gpu_private_bo_idle(owner, handle, &result);
		break;
	case GPU_PRIVATE_BO_UNCACHED:
		if ((a | b | c | d | e) == 0UL)
			gpu_private_bo_uncached(&operations, owner, handle,
						&result);
		break;
	case GPU_PRIVATE_CONTEXT_DESTROY:
		if ((a | b | c | d | e) == 0UL) {
			gpu_firmware_context_yield(&firmware_operations,
						   &operations, owner, handle,
						   &result);
			if (result.status == GPU_PRIVATE_SUCCESS)
				gpu_private_context_destroy(&operations, owner,
							    handle, &result);
		}
		break;
	case GPU_PRIVATE_MAP:
		gpu_firmware_context_yield(&firmware_operations, &operations,
					   owner, handle, &result);
		if (result.status == GPU_PRIVATE_SUCCESS)
			gpu_private_map(&operations, owner, handle, a, b, c, d,
					e, &result);
		break;
	case GPU_PRIVATE_MAP_BEGIN: {
		struct gpu_private_map_request request;

		if ((b | c | d | e) != 0UL ||
		    !copy_page_input(rec, a, sizeof(request), &request, res))
			break;
		/* This request is an immutable trusted snapshot. Yield establishes
		 * stop/cache-return/detach before the core accepts an idle transaction.
		 * Continuations use only the saved request and the actual calling RD.
		 */
		gpu_firmware_context_yield(&firmware_operations, &operations,
					   owner, handle, &result);
		if (result.status == GPU_PRIVATE_SUCCESS)
			gpu_private_map_begin(&operations, owner, handle,
					      &request, &result);
		break;
	}
	case GPU_PRIVATE_MAP_STEP:
		if ((b | c | d | e) == 0UL)
			gpu_private_map_step(&operations, owner, handle, a,
					     &result);
		break;
	case GPU_PRIVATE_MAP_ABORT:
		if ((a | b | c | d | e) == 0UL)
			gpu_private_map_abort(&operations, owner, handle,
					      &result);
		break;
	case GPU_PRIVATE_MAPPING_VERSION:
		if ((a | b | c | d | e) == 0UL)
			gpu_private_mapping_version(owner, handle, &result);
		break;
	case GPU_PRIVATE_SERVICE_MAPPING_VERSION:
		if ((b | c | d | e) != 0UL ||
		    !opencca_gpu_service_isolated(owner,
						  xshm_endpoint_id(owner)))
			break;
		client = xshm_endpoint_peer(owner, a, &peer_id);
		if (client != NULL) {
			gpu_private_context_inspect(owner, client, handle,
						    &result);
			if (result.status == GPU_PRIVATE_SUCCESS)
				gpu_private_mapping_version(client, handle,
							    &result);
		}
		break;
	case GPU_PRIVATE_MAP_AUTHORIZE:
		/* Native VM_BIND first creates a Client grant and only later lets
		 * SERVICE_MAP consume it. Yield before adding pending: that grant
		 * must not make the old internal domain impossible to retire.
		 */
		gpu_firmware_context_yield(&firmware_operations, &operations,
					   owner, handle, &result);
		if (result.status == GPU_PRIVATE_SUCCESS)
			gpu_private_map_authorize(owner, handle, a, b, c, d, e,
						  &result);
		break;
	case GPU_PRIVATE_MAP_CANCEL:
		if ((a | b | c | d | e) == 0UL)
			gpu_private_map_cancel(owner, handle, &result);
		break;
	case GPU_PRIVATE_UNMAP:
		if ((c | d | e) == 0UL) {
			gpu_firmware_context_yield(&firmware_operations,
						   &operations, owner, handle,
						   &result);
			if (result.status == GPU_PRIVATE_SUCCESS)
				gpu_private_unmap(&operations, owner, handle, a,
						  b, &result);
		}
		break;
	case GPU_PRIVATE_UNMAP_BO:
		if (e == 0UL) {
			gpu_firmware_context_yield(&firmware_operations,
						   &operations, owner, handle,
						   &result);
			if (result.status == GPU_PRIVATE_SUCCESS)
				gpu_private_unmap_bo(&operations, owner, handle,
						     a, b, c, d, &result);
		}
		break;
	case GPU_PRIVATE_CONTEXT_ACTIVATE:
		/* Client root install must never be reached while raw MMIO remains
		 * available. Queue/launch and live Client-AS switching remain absent.
		 */
		if ((b | c | d | e) == 0UL && a != 0UL &&
		    a < GPU_PRIVATE_AS_SLOTS &&
		    opencca_gpu_service_isolated(owner,
						 xshm_endpoint_id(owner)))
			gpu_private_context_activate(&operations, owner, handle,
						     a, &result);
		break;
	case GPU_PRIVATE_MAPPING_CHECK:
		gpu_private_mapping_check(&operations, owner, handle, a, b, c,
					  d, e, &result);
		break;
	case GPU_PRIVATE_QUERY:
		if ((b | c | d | e) == 0UL)
			gpu_private_query(owner, handle, a, &result);
		break;
	case GPU_PRIVATE_BO_INSPECT:
	case GPU_PRIVATE_CONTEXT_INSPECT:
		if ((b | c | d | e) != 0UL ||
		    !opencca_gpu_service_isolated(owner,
						  xshm_endpoint_id(owner)))
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
		if (!opencca_gpu_service_isolated(owner,
						  xshm_endpoint_id(owner)))
			break;
		client = xshm_endpoint_peer(owner, a, &peer_id);
		if (client == NULL)
			break;
		if (op == GPU_PRIVATE_SERVICE_MAP ||
		    (op == GPU_PRIVATE_SERVICE_UNMAP && (d | e) == 0UL)) {
			gpu_firmware_context_yield(&firmware_operations,
						   &operations, client, handle,
						   &result);
			if (result.status != GPU_PRIVATE_SUCCESS)
				break;
		}
		if (op == GPU_PRIVATE_SERVICE_MAP)
			gpu_private_service_map(&operations, owner, client,
						handle, b, c, d, e >> 8U,
						e & 255UL, &result);
		else if (op == GPU_PRIVATE_SERVICE_UNMAP && (d | e) == 0UL)
			gpu_private_service_unmap(&operations, owner, client,
						  handle, b, c, &result);
		else if (op == GPU_PRIVATE_SERVICE_MAP_RELEASE &&
			 (c | d | e) == 0UL)
			gpu_private_service_map_release(owner, client, handle,
							b, &result);
		break;
	case GPU_PRIVATE_SERVICE_ISOLATE:
		if ((handle | a | b | c | d | e) == 0UL &&
		    opencca_gpu_isolate_service(owner)) {
			result.status = GPU_PRIVATE_SUCCESS;
			result.value[0] =
				1UL; /* Raw MMIO revoked; not an execution grant. */
		}
		break;
	case GPU_PRIVATE_FW_BEGIN:
		if ((handle | b | c | d | e) == 0UL &&
		    opencca_gpu_service_isolated(owner,
						 xshm_endpoint_id(owner)))
			gpu_firmware_begin(owner, a, &result);
		break;
	case GPU_PRIVATE_FW_WRITE:
		if ((handle | d | e) == 0UL && cpu < MAX_CPUS &&
		    opencca_gpu_service_isolated(owner,
						 xshm_endpoint_id(owner)) &&
		    copy_page_input(rec, a, b, input_pages[cpu], res))
			gpu_firmware_write(owner, c, input_pages[cpu], b,
					   &result);
		break;
	case GPU_PRIVATE_FW_SEAL:
	case GPU_PRIVATE_FW_INSPECT:
	case GPU_PRIVATE_FW_PREPARE:
	case GPU_PRIVATE_FW_BOOT:
	case GPU_PRIVATE_FW_CONFIGURE:
		if ((handle | a | b | c | d | e) == 0UL &&
		    opencca_gpu_service_isolated(owner,
						 xshm_endpoint_id(owner))) {
			if (op == GPU_PRIVATE_FW_SEAL)
				gpu_firmware_seal(&firmware_operations, owner,
						  &result);
			else if (op == GPU_PRIVATE_FW_PREPARE)
				gpu_firmware_prepare(&firmware_operations,
						     owner, &result);
			else if (op == GPU_PRIVATE_FW_BOOT)
				gpu_firmware_boot(&firmware_operations, owner,
						  &result);
			else if (op == GPU_PRIVATE_FW_CONFIGURE)
				gpu_firmware_configure(&firmware_operations,
						       owner, &result);
			else
				gpu_firmware_inspect(owner, &result);
		}
		break;
	case GPU_PRIVATE_FW_PROPERTIES:
		if ((handle | b | c | d | e) == 0UL &&
		    opencca_gpu_service_isolated(owner,
						 xshm_endpoint_id(owner)))
			gpu_firmware_properties(owner, a, &result);
		break;
	case GPU_PRIVATE_FW_CONTROL_BIND:
		if ((a | b | c | d | e) == 0UL &&
		    opencca_gpu_service_isolated(owner,
						 xshm_endpoint_id(owner)))
			gpu_firmware_control_bind(&firmware_operations,
						  &operations, owner, handle,
						  &result);
		break;
	case GPU_PRIVATE_GROUP_CREATE:
		if ((c | d | e) != 0UL)
			break;
		service = xshm_endpoint_peer(owner, a, &peer_id);
		if (service != NULL &&
		    opencca_gpu_service_isolated(service,
						 xshm_endpoint_id(service))) {
			gpu_firmware_context_yield(&firmware_operations,
						   &operations, owner, handle,
						   &result);
			if (result.status == GPU_PRIVATE_SUCCESS)
				gpu_firmware_group_create(&firmware_operations,
							  &operations, service,
							  owner, handle, b,
							  &result);
		}
		break;
	case GPU_PRIVATE_GROUP_DESTROY:
		if ((a | b | c | d | e) == 0UL) {
			gpu_firmware_group_yield(&firmware_operations,
						 &operations, owner, handle,
						 &result);
			if (result.status == GPU_PRIVATE_SUCCESS)
				gpu_firmware_group_destroy(&operations, owner,
							   handle, &result);
		}
		break;
	case GPU_PRIVATE_GROUP_VALIDATE:
		if ((d == 0UL && e != 0UL) ||
		    !opencca_gpu_service_isolated(owner,
						  xshm_endpoint_id(owner)))
			break;
		client = xshm_endpoint_peer(owner, a, &peer_id);
		if (client != NULL) {
			gpu_firmware_group_validate(owner, client, b, handle, c,
						    &result);
			if (result.status == GPU_PRIVATE_SUCCESS && d != 0UL)
				gpu_firmware_group_queue_validate(
					owner, client, handle, d - 1UL,
					e & UINT32_MAX, e >> 32U, &result);
		}
		break;
	case GPU_PRIVATE_GROUP_CONFIGURE:
		if ((d | e) != 0UL || c == 0UL || c > GPU_FIRMWARE_STREAMS)
			break;
		service = xshm_endpoint_peer(owner, b, &peer_id);
		if (service != NULL &&
		    opencca_gpu_service_isolated(service,
						 xshm_endpoint_id(service)) &&
		    copy_page_input(rec, a, c * sizeof(input_queues[0][0]),
				    input_queues[cpu], res)) {
			gpu_firmware_group_yield(&firmware_operations,
						 &operations, owner, handle,
						 &result);
			if (result.status == GPU_PRIVATE_SUCCESS)
				gpu_firmware_group_configure(
					&operations, service, owner, handle,
					input_queues[cpu], c, &result);
		}
		break;
	case GPU_PRIVATE_TASK_STAGE_HINT:
	case GPU_PRIVATE_TASK_STAGE_BATCH:
		if ((d &
		     ~(GPU_PRIVATE_TASK_DEFERRED | GPU_PRIVATE_TASK_DELEGATE |
		       GPU_PRIVATE_TASK_MAPPING_VERSION)) != 0UL ||
		    ((d & GPU_PRIVATE_TASK_DELEGATE) != 0UL &&
		     (d & GPU_PRIVATE_TASK_DEFERRED) == 0UL) ||
		    (op == GPU_PRIVATE_TASK_STAGE_BATCH ?
			     e != 0UL :
			     (e == 0UL || c != 1UL)) ||
		    c == 0UL || c > GPU_PRIVATE_TASK_BATCH)
			break;
		service = xshm_endpoint_peer(owner, b, &peer_id);
		if (service != NULL &&
		    opencca_gpu_service_isolated(service,
						 xshm_endpoint_id(service)) &&
		    copy_page_input(rec, a, c * sizeof(input_commands[0][0]),
				    input_commands[cpu], res)) {
			if (op == GPU_PRIVATE_TASK_STAGE_HINT)
				gpu_firmware_task_stage_hint(
					&firmware_operations, &operations,
					service, owner, handle,
					input_commands[cpu], (unsigned int)c, d,
					e, &result);
			else
				gpu_firmware_task_stage_domain(
					&firmware_operations, &operations,
					service, owner, handle,
					input_commands[cpu], (unsigned int)c, d,
					&result);
		}
		break;
	case GPU_PRIVATE_TASK_PUBLISH:
		if ((c | d | e) != 0UL)
			break;
		service = xshm_endpoint_peer(owner, a, &peer_id);
		if (service != NULL &&
		    opencca_gpu_service_isolated(service,
						 xshm_endpoint_id(service)))
			gpu_firmware_task_publish(&firmware_operations,
						  &operations, service, owner,
						  handle, b, &result);
		break;
	case GPU_PRIVATE_TASK_CANCEL:
		if ((a | b | c | d | e) == 0UL)
			gpu_firmware_task_cancel_staged(&operations, owner,
							handle, &result);
		break;
	case GPU_PRIVATE_TASK_HEAP_EVENT:
	case GPU_PRIVATE_TASK_HEAP_GROW:
		task_heap_call(rec, &result);
		break;
	case GPU_PRIVATE_TASK_DISPATCH_LIVE:
		if ((c | d | e) != 0UL)
			break;
		service = xshm_endpoint_peer(owner, a, &peer_id);
		if (service != NULL &&
		    opencca_gpu_service_isolated(service,
						 xshm_endpoint_id(service)))
			gpu_firmware_task_dispatch_live(&firmware_operations,
							&operations, service,
							owner, handle, b,
							&result);
		break;
	case GPU_PRIVATE_TASK_OBSERVER_ARM:
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
		if (service != NULL &&
		    opencca_gpu_service_isolated(service,
						 xshm_endpoint_id(service))) {
			if (op == GPU_PRIVATE_TASK_OBSERVER_ARM)
				gpu_firmware_task_observer_arm(service, owner,
							       handle, &result);
			else if (op == GPU_PRIVATE_TASK_FINISH)
				gpu_firmware_task_finish_domain(
					&firmware_operations, &operations,
					service, owner, handle, &result);
			else if (op == GPU_PRIVATE_TASK_READY_LAUNCH)
				gpu_firmware_task_ready_launch(
					&firmware_operations, &operations,
					service, owner, handle, &result);
			else if (op == GPU_PRIVATE_TASK_READY_PUBLISH)
				gpu_firmware_task_ready_publish(
					&firmware_operations, &operations,
					service, owner, handle, &result);
			else if (op == GPU_PRIVATE_TASK_RECLAIM)
				gpu_firmware_task_reclaim(&firmware_operations,
							  &operations, service,
							  owner, handle,
							  &result);
			else if (op == GPU_PRIVATE_TASK_PROGRESS)
				gpu_firmware_task_progress(&firmware_operations,
							   &operations, service,
							   owner, handle,
							   &result);
			else if (op == GPU_PRIVATE_TASK_COMPLETE)
				gpu_firmware_task_complete(&firmware_operations,
							   &operations, service,
							   owner, handle,
							   &result);
			else if (op == GPU_PRIVATE_TASK_RETIRE)
				gpu_firmware_task_retire(&firmware_operations,
							 &operations, service,
							 owner, handle,
							 &result);
			else if (op == GPU_PRIVATE_TASK_RETURN)
				gpu_firmware_task_return(&firmware_operations,
							 &operations, service,
							 owner, handle,
							 &result);
			else
				gpu_firmware_task_ready(&firmware_operations,
							&operations, service,
							owner, handle, &result);
		}
		break;
	case GPU_PRIVATE_TASK_OBSERVER_POLL:
		if ((b | c | d | e) != 0UL ||
		    !opencca_gpu_service_isolated(owner,
						  xshm_endpoint_id(owner)))
			break;
		client = xshm_endpoint_peer(owner, a, &peer_id);
		if (client != NULL)
			gpu_firmware_task_observer_poll(
				&operations, owner, client, handle, &result);
		break;
	case GPU_PRIVATE_TASK_VALIDATE:
	case GPU_PRIVATE_TASK_PREPARE:
	case GPU_PRIVATE_TASK_PREPARE_LAUNCH:
	case GPU_PRIVATE_TASK_DISPATCH:
	case GPU_PRIVATE_TASK_DISPATCH_LEASE:
	case GPU_PRIVATE_TASK_START:
	case GPU_PRIVATE_TASK_QUIESCE:
		if (e != 0UL ||
		    !opencca_gpu_service_isolated(owner,
						  xshm_endpoint_id(owner)) ||
		    (op == GPU_PRIVATE_TASK_QUIESCE && d != 0UL))
			break;
		client = xshm_endpoint_peer(owner, a, &peer_id);
		if (client != NULL) {
			/* A service reply or local metadata cannot authorize an old map.
			 * Stop remains available after heap growth/version changes.
			 */
			if (op != GPU_PRIVATE_TASK_QUIESCE &&
			    !gpu_private_mapping_accept(owner, client, b, d)) {
				result.status = GPU_PRIVATE_INPUT;
				break;
			}
			if (op == GPU_PRIVATE_TASK_DISPATCH_LEASE)
				gpu_firmware_task_dispatch_lease(
					&firmware_operations, &operations,
					owner, client, b, c, handle, &result);
			else if (op == GPU_PRIVATE_TASK_DISPATCH)
				gpu_firmware_task_dispatch(&firmware_operations,
							   &operations, owner,
							   client, b, c, handle,
							   &result);
			else if (op == GPU_PRIVATE_TASK_PREPARE_LAUNCH)
				gpu_firmware_task_prepare_launch(
					&firmware_operations, &operations,
					owner, client, b, c, handle, &result);
			else if (op == GPU_PRIVATE_TASK_PREPARE)
				gpu_firmware_task_prepare(&firmware_operations,
							  &operations, owner,
							  client, b, c, handle,
							  &result);
			else if (op == GPU_PRIVATE_TASK_START)
				gpu_firmware_task_start(&firmware_operations,
							&operations, owner,
							client, b, c, handle,
							&result);
			else if (op == GPU_PRIVATE_TASK_QUIESCE)
				gpu_firmware_task_quiesce(&firmware_operations,
							  &operations, owner,
							  client, b, c, handle,
							  &result);
			else
				gpu_firmware_task_validate(owner, client, b, c,
							   handle, &result);
		}
		break;
	case GPU_PRIVATE_TASK_IRQ_PEEK:
	case GPU_PRIVATE_TASK_IRQ_CLAIM:
	case GPU_PRIVATE_GROUP_IRQ_PEEK:
	case GPU_PRIVATE_GROUP_IRQ_CLAIM:
		if ((op == GPU_PRIVATE_TASK_IRQ_PEEK ||
		     op == GPU_PRIVATE_GROUP_IRQ_PEEK) &&
		    (b | c | d | e) != 0UL)
			break;
		client = xshm_endpoint_peer(owner, a, &peer_id);
		/* Event statements belong to the actual isolated Proxy. A Client
		 * cannot acquire service authority by knowing a channel/task token.
		 */
		if (client == NULL || !opencca_gpu_service_isolated(
					      owner, xshm_endpoint_id(owner)))
			break;
		if (op == GPU_PRIVATE_TASK_IRQ_PEEK)
			gpu_firmware_task_irq_peek(&firmware_operations, owner,
						   client, handle, &result);
		else if (op == GPU_PRIVATE_TASK_IRQ_CLAIM)
			gpu_firmware_task_irq_claim(&firmware_operations,
						    &operations, owner, client,
						    handle, b, c, d, e,
						    &result);
		else if (op == GPU_PRIVATE_GROUP_IRQ_PEEK)
			gpu_firmware_group_irq_peek(&firmware_operations, owner,
						    client, handle, &result);
		else
			gpu_firmware_group_irq_claim(&firmware_operations,
						     owner, client, handle, b,
						     c, d, e, &result);
		break;
	case GPU_PRIVATE_IRQ_STATUS:
		if (handle > 6UL || (b | c | d | e) != 0UL ||
		    firmware_operations.irq == NULL)
			break;
		client = xshm_endpoint_peer(owner, a, &peer_id);
		if (client != NULL &&
		    (opencca_gpu_service_isolated(owner,
						  xshm_endpoint_id(owner)) ||
		     opencca_gpu_service_isolated(client,
						  xshm_endpoint_id(client)))) {
			if (handle >= 2UL) {
				result.status =
					(gpu_firmware_queue_statistics(
						 owner, result.value) ||
					 gpu_firmware_queue_statistics(
						 client, result.value)) ?
						GPU_PRIVATE_SUCCESS :
						GPU_PRIVATE_INPUT;
				if (result.status == GPU_PRIVATE_SUCCESS) {
					if (handle == 3UL || handle == 4UL) {
						if (!opencca_gpu_root_statistics(
							    (unsigned int)handle,
							    result.value))
							result.status =
								GPU_PRIVATE_STATE;
					} else if (handle == 5UL) {
						firmware_operations.irq->stats(
							2U, &result);
					} else if (handle == 6UL)
						control_view_statistics(
							result.value);
				}
			} else
				firmware_operations.irq->stats(
					(unsigned int)handle, &result);
		}
		break;
	case GPU_PRIVATE_IRQ_SELFTEST:
		if ((b | c | d | e) != 0UL)
			break;
		service = xshm_endpoint_peer(owner, a, &peer_id);
		if (service != NULL &&
		    opencca_gpu_service_isolated(service,
						 xshm_endpoint_id(service)))
			gpu_firmware_irq_selftest(&firmware_operations, service,
						  owner, handle, &result);
		break;
	case GPU_PRIVATE_TASK_OBSERVATION:
	case GPU_PRIVATE_GROUP_INSPECT:
		if ((b | c | d | e) != 0UL)
			break;
		client = xshm_endpoint_peer(owner, a, &peer_id);
		if (client == NULL)
			break;
		if (opencca_gpu_service_isolated(owner,
						 xshm_endpoint_id(owner))) {
			if (op == GPU_PRIVATE_TASK_OBSERVATION)
				gpu_firmware_task_observation(owner, client,
							      handle, &result);
			else
				gpu_firmware_group_inspect(owner, client,
							   handle, &result);
		} else if (opencca_gpu_service_isolated(
				   client, xshm_endpoint_id(client))) {
			if (op == GPU_PRIVATE_TASK_OBSERVATION)
				gpu_firmware_task_observation(client, owner,
							      handle, &result);
			else
				gpu_firmware_group_inspect(client, owner,
							   handle, &result);
		}
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
