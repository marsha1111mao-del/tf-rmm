/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef OPENCCA_GPU_FIRMWARE_H
#define OPENCCA_GPU_FIRMWARE_H

#include <opencca_gpu_private.h>

/* Explicit build-time allowlist for the existing arch10.8 CSF image. Changing
 * this trust anchor requires review and a new trusted RMM build, not an RSI
 * request from the service. This is image pinning, not vendor attestation.
 */
#define GPU_FIRMWARE_IMAGE_SIZE 274432UL
#define GPU_FIRMWARE_SECTIONS 8U
/* The allowlisted image needs 176 runtime pages and nine four-level tables;
 * eight extra tables cover the trusted 16 MiB donated-control arena.
 * Donated pages have their CPU mappings removed before becoming MCU backing.
 */
#define GPU_FIRMWARE_RUNTIME_PAGES 176U
#define GPU_FIRMWARE_TABLES 17U
/* Runtime MCU buffers must stay in Panthor's 0x04000000..0x08000000
 * shared window. Leave the pinned image's 0x04000000..0x0400c000
 * interfaces untouched; the complete 16 MiB arena fits at 0x05000000.
 */
#define GPU_FIRMWARE_CONTROL_VA UINT32_C(0x05000000)
#define GPU_FIRMWARE_GROUPS 31U
#define GPU_FIRMWARE_STREAMS 32U
#define GPU_FIRMWARE_CACHE_LINE 64U
#define GPU_FIRMWARE_LOGICAL_GROUPS 32U
#define GPU_FIRMWARE_CLIENT_GROUPS 8U
#define GPU_FIRMWARE_TASKS 128U
#define GPU_FIRMWARE_CLIENT_TASKS 32U
#define GPU_FIRMWARE_TASK_INSTRUCTIONS 16U

enum gpu_firmware_group_state {
	GPU_FIRMWARE_GROUP_RESERVED = 1,
	GPU_FIRMWARE_GROUP_CLOSING,
	GPU_FIRMWARE_GROUP_QUARANTINED,
	GPU_FIRMWARE_GROUP_PREPARED,
	GPU_FIRMWARE_GROUP_STARTED,
	GPU_FIRMWARE_GROUP_QUIESCED
};

/* Trusted internal consumer/test view; never returned through RSI. These
 * suspend/I/O are MCU addresses; ring/sync are protected Client GPU VAs.
 * None is a service CPU mapping. TASK_PREPARE copies private wrappers into
 * protected rings; TASK_START alone publishes trusted launch requests.
 */
struct gpu_firmware_group_resources {
	unsigned long context;
	uint32_t suspend_va, suspend_bytes, streams;
	uint32_t input_va[GPU_FIRMWARE_STREAMS];
	uint32_t output_va[GPU_FIRMWARE_STREAMS];
	uint64_t ring_va[GPU_FIRMWARE_STREAMS], sync_va;
	uint32_t ring_bytes[GPU_FIRMWARE_STREAMS], priority[GPU_FIRMWARE_STREAMS];
};

struct gpu_firmware_queue_config {
	uint32_t ring_bytes, priority;
};

/* Actual Client snapshot, at most six normal queue submissions. No CPU/HPA
 * pointers. Members on each queue retain array order; queues start together.
 */
struct gpu_firmware_task_command {
	uint64_t start;
	uint32_t bytes, queue, latest_flush, pad;
};

/* RMM-private immutable submission wrapper; never returned by RSI. This
 * template is copied by TASK_PREPARE; it is not itself a completion proof.
 * The Client retains its own command stream and resources in private BOs.
 */
struct gpu_firmware_task_resources {
	unsigned long group, context;
	uint32_t queue, bytes, latest_flush;
	uint64_t instructions[GPU_FIRMWARE_TASK_INSTRUCTIONS];
};

/* Fixed platform policy, never supplied by Proxy. */
struct gpu_firmware_config {
	uint64_t shader_mask;
	uint32_t poweroff_timer, idle_timer;
	unsigned long ack_timeout_ticks;
};

enum gpu_firmware_state {
	GPU_FIRMWARE_EMPTY,
	GPU_FIRMWARE_RECEIVING,
	GPU_FIRMWARE_VERIFIED,
	GPU_FIRMWARE_PREPARED,
	GPU_FIRMWARE_INSTALLED,
	GPU_FIRMWARE_BOOTED,
	GPU_FIRMWARE_QUARANTINED,
	GPU_FIRMWARE_CONFIGURED
};

struct gpu_firmware_ops {
	bool (*digest)(const void *image, size_t size, unsigned char output[32]);
	unsigned long (*address)(const void *memory);
	void (*clean)(const void *memory, size_t size);
	void (*invalidate)(const void *memory, size_t size);
	bool (*install)(unsigned long root);
	bool (*boot)(unsigned long root);
	bool (*configuration)(unsigned long root, struct gpu_firmware_config *config);
	bool (*notify)(unsigned long root);
	unsigned long (*clock)(void);
};

struct gpu_firmware_section {
	uint32_t flags, va, size, data_offset, data_size;
};

/* All entry points use the common ownership policy lock. The RSI adapter must
 * authenticate the actual isolated GPU service before invoking these APIs.
 * The image is never imported from Proxy-owned GPU mappings.
 */
void gpu_firmware_begin(const void *service, unsigned long size,
		struct gpu_private_result *result);
void gpu_firmware_write(const void *service, unsigned long offset,
		const void *snapshot, size_t bytes, struct gpu_private_result *result);
void gpu_firmware_seal(const struct gpu_firmware_ops *ops, const void *service,
		struct gpu_private_result *result);
void gpu_firmware_inspect(const void *service, struct gpu_private_result *result);
void gpu_firmware_prepare(const struct gpu_firmware_ops *ops, const void *service,
		struct gpu_private_result *result);
/* Installs only the protected MCU root and boots the pinned firmware. Does
 * not publish group/stream requests or authorize any Client GPU task.
 * Any ambiguous hardware outcome retains pages/tables until trusted reset.
 */
void gpu_firmware_boot(const struct gpu_firmware_ops *ops, const void *service,
		struct gpu_private_result *result);
/* Configure the validated private global interface and observe its actual
 * ACK within a trusted deadline. No Client group or stream is started.
 */
void gpu_firmware_configure(const struct gpu_firmware_ops *ops, const void *service,
		struct gpu_private_result *result);
/* Bind one sealed arena before MCU boot; no caller-supplied VA, PA or root.
 * Success retains the object until verified device reset. This supplies
 * protected backing, not Client queues or task execution permission.
 */
void gpu_firmware_control_bind(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		unsigned long object, struct gpu_private_result *result);
/* Client-authorized memory reservation; does not bind a hardware CSG slot,
 * publish a ring or start any task. owner is actual Client RD, not payload.
 * CREATE returns [opaque group, streams, suspend bytes, reserved pages]. A
 * scrub failure returns STATE and the quarantined group handle in value[0],
 * so owner may retry typed destruction; no resources can be consumed then.
 */
void gpu_firmware_group_create(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long context, unsigned long streams,
		struct gpu_private_result *result);
void gpu_firmware_group_destroy(const struct gpu_private_ops *memory_ops,
		const void *owner, unsigned long group, struct gpu_private_result *result);
/* Actual Client snapshot; immutable queue parameters, CPU-hidden rings and
 * RO/XN/NC Client GPU leaves plus one RW/XN/NC completion page. Prelaunch only.
 * Does not publish a ring to firmware or grant task execution permission.
 */
void gpu_firmware_group_configure(const struct gpu_private_ops *memory_ops,
		const void *service, const void *owner, unsigned long group,
		const struct gpu_firmware_queue_config *queues, unsigned long count,
		struct gpu_private_result *result);
void gpu_firmware_group_queue_validate(const void *service, const void *owner,
		unsigned long group, unsigned long index, unsigned long ring_bytes,
		unsigned long priority, struct gpu_private_result *result);
/* Returns [state, streams, suspend bytes, remaining reserved pages]. */
void gpu_firmware_group_inspect(const void *service, const void *owner,
		unsigned long group, struct gpu_private_result *result);
/* Import validation only: no address disclosure or execution permission. */
void gpu_firmware_group_validate(const void *service, const void *owner,
		unsigned long context, unsigned long group, unsigned long streams,
		struct gpu_private_result *result);
bool gpu_firmware_group_resources(const void *service, const void *owner,
		unsigned long group, struct gpu_firmware_group_resources *resources);
void gpu_firmware_task_stage(const struct gpu_private_ops *memory_ops,
		const void *service, const void *owner, unsigned long group,
		unsigned long queue, unsigned long start, unsigned long bytes,
		unsigned long latest_flush, struct gpu_private_result *result);
/* Existing Guest operations use these trusted domain consumers. Only
 * frozen NC/resident mappings and already-active queues can stay live.
 * A finished public token becomes an inaccessible internal lifetime anchor.
 * Map/destruction/admission consumers must yield before changing its leases.
 */
void gpu_firmware_task_stage_domain(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long group,
		const struct gpu_firmware_task_command *commands, unsigned int count,
		unsigned long flags, struct gpu_private_result *result);
/* Single-member optional scheduling hint; original admission remains intact. */
void gpu_firmware_task_stage_hint(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long group,
		const struct gpu_firmware_task_command *commands, unsigned int count,
		unsigned long flags, unsigned long hint, struct gpu_private_result *result);
void gpu_firmware_task_cancel_staged(const struct gpu_private_ops *memory_ops,
		const void *owner, unsigned long token, struct gpu_private_result *result);
void gpu_firmware_task_finish_domain(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long token, struct gpu_private_result *result);
void gpu_firmware_context_yield(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *owner,
		unsigned long context, struct gpu_private_result *result);
void gpu_firmware_group_yield(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *owner,
		unsigned long group, struct gpu_private_result *result);
void gpu_firmware_task_stage_batch(const struct gpu_private_ops *memory_ops,
		const void *service, const void *owner, unsigned long group,
		const struct gpu_firmware_task_command *commands, unsigned int count,
		unsigned long flags, struct gpu_private_result *result);
/* Actual Client only. Cumulative per-queue prefixes after READY; can extend
 * protected INSERT while STARTED. No arbitrary pointer/register from service.
 * A partial write/notification/ACK failure quarantines and retains backing.
 */
void gpu_firmware_task_publish(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long token, unsigned long members,
		struct gpu_private_result *result);
void gpu_firmware_task_cancel(const void *owner, unsigned long task,
		struct gpu_private_result *result);
void gpu_firmware_task_validate(const void *service, const void *owner,
		unsigned long context, unsigned long group, unsigned long task,
		struct gpu_private_result *result);
bool gpu_firmware_task_resources(const void *service, const void *owner,
		unsigned long task, struct gpu_firmware_task_resources *resources);
/* Prepare protected rings on a stopped slot, or append to a drained internal
 * domain without changing INSERT/EXTRACT_INIT. Cold preparation chooses unused
 * AS/CSG slots and snapshots firmware interface offsets. Neither path publishes
 * the new batch, issues START, or grants execution permission.
 * Partial hardware/memory work remains quarantined until trusted reset.
 */
void gpu_firmware_task_prepare(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long context, unsigned long group,
		unsigned long task, struct gpu_private_result *result);
/* Actual Client assertion that all CPU data preparation is complete.
 * Legacy all-at-once tasks also require all dependencies here. Deferred tasks
 * establish each member's device dependencies before its TASK_PUBLISH instead.
 * Synchronize all private mapped data pages in bounded batches; Proxy cannot
 * make this assertion. This step changes no queue producer or doorbell;
 * a retained domain still has only the previous drained producer published.
 * Returns [ready (0/1), queue, cumulative synchronized pages, 0]. Status
 * INCOMPLETE requires the same Client/token to continue the private cursor.
 */
void gpu_firmware_task_ready(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long task, struct gpu_private_result *result);
/* Client-only initial full deferred publication. One bounded READY slice;
 * INCOMPLETE never publishes. On SUCCESS, preserve all PUBLISH checks and
 * return READY's fields only after publication succeeds. Cold tasks remain
 * stopped; live domains use PUBLISH's checked doorbell/ACK path. Already
 * published tokens cannot replay this operation.
 */
void gpu_firmware_task_ready_publish(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long task, struct gpu_private_result *result);
/* Explicit service selection/permission, before any preparation or publish.
 * No launch until the original Client finishes READY_LAUNCH. Permission is
 * private, exact-token and consumed before the ordinary full START path.
 */
void gpu_firmware_task_prepare_launch(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long context, unsigned long group,
		unsigned long task, struct gpu_private_result *result);
void gpu_firmware_task_ready_launch(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long task, struct gpu_private_result *result);
void gpu_firmware_task_dispatch(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long context, unsigned long group,
		unsigned long task, struct gpu_private_result *result);
/* Service may start only the exact prepared token made ready by its actual
 * Client. Publish child CS inputs before CSG and global doorbells, observe
 * real ACKs for all participating queues within a trusted deadline, and never
 * reissue on retry. A continuing group RESUMEs its protected native CS state;
 * same-queue members keep order and queue cursors remain monotonic. Returns
 * [group state STARTED (5), queue, 0, 0], which is acceptance, not completion.
 * Any ambiguous publication retains resources quarantined until reset.
 */
void gpu_firmware_task_start(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long context, unsigned long group,
		unsigned long task, struct gpu_private_result *result);
/* Explicit abort/quiescence, NOT successful task completion. Stop the exact
 * started CSs/CSG, check every actual ACK, then flush and disable its Client AS.
 * No other published group may reference the same context. Returns
 * [QUIESCED (6), queue, 0, 0]; all backing/cache/task references remain held.
 */
void gpu_firmware_task_quiesce(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long context, unsigned long group,
		unsigned long task, struct gpu_private_result *result);
/* Client requests CPU cache return for its exact quiesced token. Every batch
 * first rechecks exact TERMINATE/SUSPEND ACK and disabled AS; bounded invalidation never
 * exposes Client pages to service. Returns [returned (0/1), queue, pages, 0].
 * This does not prove task success, retire resources or permit a new launch.
 */
void gpu_firmware_task_return(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long task, struct gpu_private_result *result);
/* Client-only retirement after full RETURN. Aborts scrub group control pages;
 * successful batches retain this group's protected suspend/IO/ring state and
 * commit the checked monotonic history for the next RESUME. Group destruction
 * scrubs all retained pages before reuse by another owner. Both paths remove
 * old firmware addresses (retaining acknowledged state/toggles) and exact
 * task/AS/CSG/cache leases, invalidate the old
 * token, and keep BO mappings. Neither retirement asserts task success.
 * Returns [retired (0/1), queue, scrubbed pages, 0], no task success assertion.
 */
void gpu_firmware_task_retire(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long task, struct gpu_private_result *result);
/* Original Client only, after successful COMPLETE. One bounded CPU RETURN
 * followed by RETIRE when fully returned, under the same policy lock. Reuses
 * RETURN's final full hardware check only across a callback-free boundary.
 * Aborts are rejected. Returns [retired (0/1), queue, 0, 0]; INCOMPLETE retains
 * every reference and must continue with this same token. No success replay
 * after retirement; the old token is invalidated exactly as with RETIRE.
 */
void gpu_firmware_task_reclaim(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long task, struct gpu_private_result *result);
/* Client-only compound completion/return/retirement. SUCCESS=[1,queue,0,0]
 * invalidates the token; INCOMPLETE=[0,queue,0,kind], kind=0 GPU wait, 1 bounded
 * CPU return. Reuse only the adjacent COMPLETE final check, with no intervening
 * callback/publication/unlock. All continuations and post-cache boundaries keep
 * full stopped-state checks. Explicit aborts never become successful tasks.
 */
void gpu_firmware_task_finish(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long task, struct gpu_private_result *result);
/* Original Client completion observation. RMM requests fresh STATUS_UPDATE,
 * verifies the matching ACK and every participating queue's idle/error and
 * exact final sequence evidence, saves native CS state with acknowledged
 * SUSPEND, resets CS inputs without a notification or stale-CS ACK wait, then
 * flushes/disables the AS before recording completion. Counter
 * alone never authorizes completion. Returns [complete (0/1), queue, 0, 0];
 * INCOMPLETE means a fresh snapshot was valid but work was not done. All
 * references remain until separate CPU RETURN and RETIRE. No data addresses.
 */
void gpu_firmware_task_complete(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long task, struct gpu_private_result *result);
/* Fresh, Client-only per-member progress from the same observer as COMPLETE.
 * A wrapper's protected sequence AND consumed prefix must reach its per-queue
 * ordinal; counters cannot regress and every queue/error is checked before
 * publishing any mask. SUCCESS=[mask,count,queue_mask,0]; INCOMPLETE has mask0
 * and means no fresh observation. Does not STOP, detach, sync CPU data, signal
 * a job fence or release references, even for an all-members mask.
 */
void gpu_firmware_task_progress(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long task, struct gpu_private_result *result);
/* Internal trusted live-domain prerequisite, deliberately not an RSI/Guest
 * operation. Fresh all-queue completion, memory flush and postchecks may mark
 * an NC/resident context drained while retaining its AS and every lease.
 * SUCCESS is not a public fence, CPU cache return or permission to reclaim.
 * Ordinary COMPLETE and the explicit non-domain FINISH still stop, disable,
 * return and retire; the RSI domain consumer separately invalidates public
 * tokens after successful drain while retaining an internal lifetime anchor.
 */
void gpu_firmware_task_drain(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long task, struct gpu_private_result *result);
/* Trusted original-Client adapter only. Snapshot an actual pending tiler OOM
 * from cached MCU interfaces after checking live task/context/AS ownership.
 * SUCCESS=[event,heap GPUVA,in_flight|(pending_frag<<32),queue], or all zero if
 * none. Event IDs never wrap/reuse across reset. No MMIO/firmware writes.
 */
void gpu_firmware_task_heap_event(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long task, struct gpu_private_result *result);
/* Consume that event with a fresh owner BO at empty VA, or object=VA=0 for
 * native ENOMEM fallback. Bounded cache-before-PTE extension, then ordered
 * trusted heap-pointer/ACK/doorbell publication. Partial publication is never
 * replayed. SUCCESS=[1,event,pages,queue], INCOMPLETE=[0,event,pages,queue].
 * This is event acceptance, never completion/CPU return or safe BO release.
 * Original-Client RSI adapter derives owner/service from RD and channel.
 */
void gpu_firmware_task_heap_grow(const struct gpu_firmware_ops *ops,
		const struct gpu_private_ops *memory_ops, const void *service,
		const void *owner, unsigned long task, unsigned long event,
		unsigned long object, unsigned long iova, struct gpu_private_result *result);
/* Two sanitized property records; never returns interface or backing pointers.
 * 0: version, global features, groups, instrumentation features.
 * 1: streams/group, stream features, suspend bytes, protected suspend bytes.
 */
void gpu_firmware_properties(const void *service, unsigned long record,
		struct gpu_private_result *result);
/* Trusted backend only; no RSI returns these pointers or section addresses.
 * Returned data remains valid until trusted reset/revocation. A verified image
 * cannot be overwritten by BEGIN/WRITE, even by its original service.
 */
bool gpu_firmware_section(const void *service, unsigned int index,
		struct gpu_firmware_section *section, const void **data);
/* Only after raw-MMIO revocation and verified device reset. */
void gpu_firmware_device_revoked(void);

#endif
