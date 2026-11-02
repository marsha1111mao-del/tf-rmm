/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef OPENCCA_GPU_PRIVATE_H
#define OPENCCA_GPU_PRIVATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct gpu_firmware_config;

#define GPU_PRIVATE_ABI 2UL
#define GPU_PRIVATE_PAGE_SIZE 4096UL
#define GPU_PRIVATE_BATCH 512U
#define GPU_PRIVATE_READ 1UL
#define GPU_PRIVATE_WRITE 2UL
#define GPU_PRIVATE_EXEC 4UL
#define GPU_PRIVATE_CACHE 8UL
#define GPU_PRIVATE_ACCESS 7UL
#define GPU_PRIVATE_CAP_REGISTRATION 1UL
#define GPU_PRIVATE_CAP_PAGE_TABLES 2UL
#define GPU_PRIVATE_CAP_EXECUTION 4UL
#define GPU_PRIVATE_CAP_SERVICE_MAPPING 8UL
#define GPU_PRIVATE_CAP_MAPPING_AUTH 16UL
#define GPU_PRIVATE_CAP_CONTROL_HANDOFF 32UL
#define GPU_PRIVATE_CAP_PT_INSTALL 64UL
#define GPU_PRIVATE_CAP_FW_SNAPSHOT 128UL
#define GPU_PRIVATE_CAP_FW_PREPARE 256UL
#define GPU_PRIVATE_CAP_FW_BOOT 512UL
#define GPU_PRIVATE_CAP_FW_CONFIG 1024UL
#define GPU_PRIVATE_CAP_CONTROL_MEMORY 2048UL
#define GPU_PRIVATE_CAP_GROUP_MEMORY 4096UL
#define GPU_PRIVATE_CAP_GROUP_VALIDATION 8192UL
#define GPU_PRIVATE_CAP_GROUP_RINGS 16384UL
#define GPU_PRIVATE_CAP_TASK_STAGING 32768UL
#define GPU_PRIVATE_CAP_TASK_PREPARE 65536UL
#define GPU_PRIVATE_CAP_TASK_READY 131072UL
#define GPU_PRIVATE_CAP_TASK_START 262144UL
#define GPU_PRIVATE_CAP_TASK_QUIESCE 524288UL
#define GPU_PRIVATE_CAP_TASK_RETURN 1048576UL
#define GPU_PRIVATE_CAP_TASK_RETIRE 2097152UL
#define GPU_PRIVATE_CAP_TASK_COMPLETE 4194304UL
#define GPU_PRIVATE_CAP_MAPPING_CHECK 8388608UL
#define GPU_PRIVATE_CAP_TASK_BATCH 16777216UL
#define GPU_PRIVATE_CAP_UNMAP_BO 33554432UL
#define GPU_PRIVATE_CAP_TASK_PROGRESS 67108864UL
#define GPU_PRIVATE_CAP_TASK_PUBLISH 134217728UL
#define GPU_PRIVATE_CAP_TASK_HEAP 268435456UL
#define GPU_PRIVATE_CAP_BO_RESIDENT 536870912UL
#define GPU_PRIVATE_CAP_BO_UNCACHED 1073741824UL
#define GPU_PRIVATE_CAP_TASK_RECLAIM 2147483648UL
#define GPU_PRIVATE_CAP_TASK_READY_PUBLISH 4294967296UL
#define GPU_PRIVATE_CAP_TASK_READY_LAUNCH 8589934592UL
#define GPU_PRIVATE_CAP_TASK_FINISH 17179869184UL
#define GPU_PRIVATE_CAP_TASK_DISPATCH 34359738368UL
#define GPU_PRIVATE_CAP_TASK_STAGE_HINT 68719476736ULL
#define GPU_PRIVATE_TASK_DEFERRED 1UL
#define GPU_PRIVATE_TASK_DELEGATE 2UL
#define GPU_PRIVATE_TASK_BATCH 6U
/* Last 16 MiB of the 48-bit VA space is exclusively trusted internal data. */
#define GPU_PRIVATE_CONTROL_GPU_VA UINT64_C(0x0000ffffff000000)
#define GPU_PRIVATE_CONTROL_OBJECTS 32U
#define GPU_PRIVATE_CONTROL_PAGES 4096U
#ifndef GPU_PRIVATE_OBJECTS
#define GPU_PRIVATE_OBJECTS 1024U
#endif
#ifndef GPU_PRIVATE_BLOCKS
#define GPU_PRIVATE_BLOCKS 1024U
#endif
#ifndef GPU_PRIVATE_TABLES
/* Keep the existing 38 MiB RK RMM reservation. Exhaustion rejects mappings;
 * it must never fall back to Guest-owned tables. */
#define GPU_PRIVATE_TABLES 448U
#endif
#define GPU_PRIVATE_CONTEXTS 32U
#define GPU_PRIVATE_AS_SLOTS 16U
#define GPU_PRIVATE_BO_BLOCKS 256U
#define GPU_PRIVATE_MAP_GRANTS 128U
#define GPU_PRIVATE_CONTEXT_GRANTS 32U

enum gpu_private_status {
	GPU_PRIVATE_SUCCESS,
	GPU_PRIVATE_INPUT,
	GPU_PRIVATE_STATE,
	GPU_PRIVATE_FULL,
	GPU_PRIVATE_INCOMPLETE
};

/* Caller/peer are authenticated RD instances supplied by the RSI adapter.
 * The core never maps a data page into the service's CPU address space.
 * All calls, source RTT updates and CPU sharing use xshm_policy_lock.
 */
struct gpu_private_ops {
	bool (*source_page)(const void *owner, unsigned long ipa, unsigned long *pa);
	unsigned long (*table_pa)(const void *table);
	void (*clean)(const void *table, size_t bytes);
	/* Both callbacks belong to the trusted device backend, never Proxy.
	 * Activate installs the root into the specified hardware slot after
	 * taking exclusive control of roots, firmware and launch paths. Root
	 * addresses are never returned to the RSI caller. A false result means
	 * potentially partial hardware work: retain the slot and all backing.
	 */
	bool (*activate)(unsigned long context, unsigned long root, unsigned int slot);
	/* Edits to an activated context require trusted translation invalidation. */
	bool (*synchronize)(unsigned long context, unsigned long root);
	/* Internal control-page donation. A false hide/restore MUST leave the
	 * CPU PTE unchanged; true completes the corresponding global TLBI.
	 * Clearing happens through a trusted temporary mapping, not a Proxy VA.
	 */
	bool (*hide_page)(const void *owner, unsigned long ipa, unsigned long pa);
	bool (*restore_page)(const void *owner, unsigned long ipa, unsigned long pa);
	/* Restore only an assigned-empty DATA page, forcing Normal NC across
	 * all Client S1 aliases. Same no-mutation-on-failure and TLBI contract.
	 */
	bool (*restore_page_uncached)(const void *owner, unsigned long ipa, unsigned long pa);
	/* Order NC CPU writes/device return before publication, once per batch. */
	bool (*cache_barrier)(void);
	bool (*clear_page)(unsigned long pa);
	/* Trusted-only preparation: an unused nonzero AS with the verified MCU
	 * running; never selected by a hardware CSG until the firmware core binds
	 * it. No service-selected root, firmware root or AS index is accepted.
	 */
	bool (*prepare_as)(unsigned long root, unsigned int slot, unsigned long firmware_root, bool existing);
	/* Check an already prepared AS and the fixed MCU configuration together.
	 * No programming, publication, or cached proof: validate actual registers
	 * under the backend mapping lock. Other trusted adapters use prepare_as
	 * and the firmware configuration callback separately when this is NULL.
	 */
	bool (*check_running_as)(unsigned long root, unsigned int slot,
		unsigned long firmware_root, struct gpu_firmware_config *config);
	/* Trusted additive mapping only. Validate the live Client/firmware roots,
	 * flush this exact AS's PT caches, then revalidate; never install a root,
	 * change attributes, start a queue or ring a doorbell.
	 */
	bool (*extend_as)(unsigned long root, unsigned int slot, unsigned long firmware_root);
	bool (*write_page)(unsigned long pa, size_t offset, const void *data, size_t bytes);
	/* Clean and invalidate an entire owned data granule to PoC before the
	 * GPU can use it; no Proxy mapping or caller-selected PA is involved.
	 */
	bool (*sync_page_for_device)(unsigned long pa);
	/* Firmware consumer calls only after its Client's CS/CSG STOP/TERMINATE
	 * ACK. Flush memory and disable that exact AS; detached replay checks only.
	 * A detached replay must check the full live firmware configuration (root,
	 * attributes, MCU/fault state, shaders, tiler and trusted timer frequency)
	 * before and after AS validation; callers do not duplicate those checks.
	 * Never sufficient on its own to establish firmware quiescence.
	 */
	bool (*detach_as)(unsigned long root, unsigned int slot, unsigned long firmware_root, bool detached);
	/* Invalidate owned data at PoC only after trusted STOP and AS disable.
	 * Never clean stale CPU lines back over device-produced data.
	 */
	bool (*sync_page_for_cpu)(unsigned long pa);
	/* Snapshot protected donated control data through a trusted mapping;
	 * never a service VA or ordinary Client data page supplied by an RPC.
	 */
	bool (*read_page)(unsigned long pa, size_t offset, void *data, size_t bytes);
	/* Trusted backend guarantee: PTs/tags are writable only by this core,
	 * under the policy lock. Allows epoch-bound reuse of validated NC/resident
	 * mapping sets; fresh BO lifecycle/lease checks remain mandatory. False
	 * keeps the reference per-leaf walk. Never supplied through RSI/RPC.
	 */
	bool protected_mapping_summary;
	/* Internal live memory barrier. Leaves roots and execution intact; false
	 * may follow partial MMIO. Not a completion or CPU-ownership assertion.
	 */
	bool (*flush_as)(unsigned long root, unsigned int slot, unsigned long firmware_root);
};

struct gpu_private_result {
	unsigned long status;
	unsigned long value[4];
};

/* Internal dead-owner cleanup. Adapter proves zero RECs and trusted whole-
 * device revocation under xshm_policy_lock before calling. One BO batch per
 * call; INCOMPLETE requires another call. Never retires another owner's BO.
 */
void gpu_private_owner_reclaim(const struct gpu_private_ops *ops,
		const void *owner, struct gpu_private_result *result);
void opencca_gpu_private_reclaim(unsigned long rd_addr,
		struct gpu_private_result *result);
bool gpu_private_raw_access_blocked(void);

enum gpu_private_operation {
	GPU_PRIVATE_VERSION,
	GPU_PRIVATE_BO_CREATE,
	GPU_PRIVATE_BO_APPEND,
	GPU_PRIVATE_BO_DESTROY,
	GPU_PRIVATE_CONTEXT_CREATE,
	GPU_PRIVATE_CONTEXT_DESTROY,
	GPU_PRIVATE_MAP,
	GPU_PRIVATE_UNMAP,
	GPU_PRIVATE_CONTEXT_ACTIVATE,
	GPU_PRIVATE_QUERY,
	GPU_PRIVATE_BO_INSPECT,
	GPU_PRIVATE_CONTEXT_INSPECT,
	GPU_PRIVATE_SERVICE_MAP,
	GPU_PRIVATE_SERVICE_UNMAP,
	GPU_PRIVATE_MAP_AUTHORIZE,
	GPU_PRIVATE_MAP_CANCEL,
	GPU_PRIVATE_SERVICE_MAP_RELEASE,
	GPU_PRIVATE_SERVICE_ISOLATE,
	GPU_PRIVATE_FW_BEGIN,
	GPU_PRIVATE_FW_WRITE,
	GPU_PRIVATE_FW_SEAL,
	GPU_PRIVATE_FW_INSPECT,
	GPU_PRIVATE_FW_PREPARE,
	GPU_PRIVATE_FW_BOOT,
	GPU_PRIVATE_FW_CONFIGURE,
	GPU_PRIVATE_FW_PROPERTIES,
	GPU_PRIVATE_CONTROL_CREATE,
	GPU_PRIVATE_CONTROL_APPEND,
	GPU_PRIVATE_CONTROL_DESTROY,
	GPU_PRIVATE_FW_CONTROL_BIND,
	GPU_PRIVATE_GROUP_CREATE,
	GPU_PRIVATE_GROUP_DESTROY,
	GPU_PRIVATE_GROUP_INSPECT,
	GPU_PRIVATE_GROUP_VALIDATE,
	GPU_PRIVATE_GROUP_CONFIGURE,
	GPU_PRIVATE_TASK_STAGE,
	GPU_PRIVATE_TASK_CANCEL,
	GPU_PRIVATE_TASK_VALIDATE,
	GPU_PRIVATE_TASK_PREPARE,
	GPU_PRIVATE_TASK_READY,
	GPU_PRIVATE_TASK_START,
	GPU_PRIVATE_TASK_QUIESCE,
	GPU_PRIVATE_TASK_RETURN,
	GPU_PRIVATE_TASK_RETIRE,
	GPU_PRIVATE_TASK_COMPLETE,
	GPU_PRIVATE_MAPPING_CHECK,
	GPU_PRIVATE_TASK_STAGE_BATCH,
	GPU_PRIVATE_UNMAP_BO,
	GPU_PRIVATE_TASK_PROGRESS,
	GPU_PRIVATE_TASK_PUBLISH,
	GPU_PRIVATE_TASK_HEAP_EVENT,
	GPU_PRIVATE_TASK_HEAP_GROW,
	GPU_PRIVATE_BO_SEAL,
	GPU_PRIVATE_BO_RELEASE,
	GPU_PRIVATE_BO_UNCACHED,
	GPU_PRIVATE_TASK_RECLAIM,
	GPU_PRIVATE_TASK_READY_PUBLISH,
	GPU_PRIVATE_TASK_PREPARE_LAUNCH,
	GPU_PRIVATE_TASK_READY_LAUNCH,
	GPU_PRIVATE_TASK_FINISH,
	GPU_PRIVATE_TASK_DISPATCH,
	GPU_PRIVATE_TASK_STAGE_HINT
};

void gpu_private_bo_create(const void *owner, const void *service,
		unsigned long size, unsigned long access,
		struct gpu_private_result *result);
void gpu_private_bo_append(const struct gpu_private_ops *ops, const void *owner,
		unsigned long handle, unsigned long offset,
		const unsigned long *ipas, size_t count,
		struct gpu_private_result *result);
void gpu_private_bo_destroy(const void *owner, unsigned long handle,
		struct gpu_private_result *result);
/* Original Client only, before any mapping/grant. Hide each CPU RTT leaf,
 * complete its global TLBI, then flush initialized contents to the GPU.
 * Bounded and irreversible: errors close the BO and retain the hidden prefix.
 * Completed replays only inspect metadata. No service/ordinary CPU aliases.
 * RELEASE requires no GPU/mapping/grant holds, scrubs before CPU restoration,
 * and is also the cleanup path for partial/failed seals. Ordinary DESTROY
 * cannot release a sealed BO without these trusted operations.
 */
void gpu_private_bo_seal(const struct gpu_private_ops *ops, const void *owner,
		unsigned long handle, struct gpu_private_result *result);
void gpu_private_bo_uncached(const struct gpu_private_ops *ops, const void *owner,
		unsigned long handle, struct gpu_private_result *result);
void gpu_private_bo_release(const struct gpu_private_ops *ops, const void *owner,
		unsigned long handle, struct gpu_private_result *result);
/* Only the actual isolated service may donate its own previously private,
 * unshared pages. Distinct type: never imported as a Client data BO.
 */
void gpu_private_control_create(const void *service, unsigned long size,
		struct gpu_private_result *result);
void gpu_private_control_append(const struct gpu_private_ops *ops, const void *service,
		unsigned long handle, unsigned long offset, const unsigned long *ipas,
		size_t count, struct gpu_private_result *result);
void gpu_private_control_destroy(const struct gpu_private_ops *ops, const void *service,
		unsigned long handle, struct gpu_private_result *result);
/* Trusted firmware consumer only; no RSI exposes these PAs. Acquire clears
 * and pins all sealed pages; release is allowed only before hardware exposure
 * or after verified reset. Device retirement also drops the firmware hold.
 */
bool gpu_private_control_acquire(const struct gpu_private_ops *ops, const void *service,
		unsigned long handle, unsigned int *pages);
bool gpu_private_control_page(const void *service, unsigned long handle,
		unsigned int index, unsigned long *pa);
void gpu_private_control_release(const void *service, unsigned long handle);
void gpu_private_context_create(const struct gpu_private_ops *ops,
		const void *owner, const void *service,
		struct gpu_private_result *result);
void gpu_private_context_destroy(const struct gpu_private_ops *ops,
		const void *owner, unsigned long context,
		struct gpu_private_result *result);
/* Trusted group-memory consumer only. Authenticated owner/service must match
 * the actual context. Holds prevent context reuse until group retirement;
 * verified whole-device revocation retires all holds with the groups.
 */
bool gpu_private_context_hold(const void *service, const void *owner,
		unsigned long context);
void gpu_private_context_put(const void *owner, unsigned long context);
/* Trusted task consumer: validate every command-stream page using real PTEs
 * and private object tags, then freeze this context's mappings. CPU contents
 * remain Client-owned; no service CPU alias is introduced. Work is bounded
 * to GPU_PRIVATE_BATCH pages. Prepared/started references survive trusted
 * quiescence until CPU cache return/retirement; service assertions never
 * authorize release. Unprepared records may be cancelled without hardware.
 */
bool gpu_private_task_hold(const struct gpu_private_ops *ops, const void *service,
		const void *owner, unsigned long context, unsigned long start,
		unsigned long bytes);
struct gpu_private_command_range {
	unsigned long start, bytes;
};
/* Validate all ranges atomically under the policy lock and acquire ONE
 * context reference. Empty ranges represent fence-only members (start=0).
 * The entire batch, including repeated pages, walks at most 512 pages.
 */
bool gpu_private_task_hold_batch(const struct gpu_private_ops *ops, const void *service,
		const void *owner, unsigned long context,
		const struct gpu_private_command_range *ranges, unsigned int count);
bool gpu_private_task_put(const void *owner, unsigned long context);
/* Trusted live-domain consumers/test view only; none is an RSI operation.
 * Eligibility requires an epoch-valid, protected NC/resident-only mapping
 * summary and every current cache lease. WB keeps the stop/return path.
 * FLUSH clears any earlier drained proof and retains backing on ambiguity.
 * MARK follows the firmware consumer's fresh all-queue checks after FLUSH;
 * it freezes ownership, never authorizes RETURN/RETIRE or CPU-page release.
 */
bool gpu_private_task_live_eligible(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context, unsigned long task);
bool gpu_private_task_flush_live(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long task, unsigned long firmware_root);
bool gpu_private_task_mark_drained(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context, unsigned long task);
/* Internal certificate query only; firmware must also revalidate the hidden
 * idle anchor and real roots/configuration/queues before using this proof.
 */
bool gpu_private_task_is_drained(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context, unsigned long task);
/* Discard a previous idle observation before starting any fresh observation. */
void gpu_private_task_clear_drained(const void *service, const void *owner,
		unsigned long context, unsigned long task);
/* Reserve a separately staged successor while a trusted drained task keeps
 * the AS/mapping/cache leases. Ordinary HOLD/PUT still reject active contexts.
 * Handoff atomically replaces the predecessor's cache token with the staged
 * successor, consuming one of at least two task holds. No hardware or page
 * callback occurs; firmware must commit its ring/history/token state too.
 */
bool gpu_private_task_hold_live(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long task, const struct gpu_private_command_range *ranges, unsigned int count);
bool gpu_private_task_put_live(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context, unsigned long task);
bool gpu_private_task_handoff_live(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long previous, unsigned long next);
void gpu_private_context_prepare(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long firmware_root, struct gpu_private_result *result);
void gpu_private_context_check_running(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long firmware_root, struct gpu_firmware_config *config,
		struct gpu_private_result *result);
/* Trusted firmware consumer after verified STOP/TERMINATE, with no sibling
 * published CSG using this context. Disables the AS but retains all references
 * and cache ownership until subsequent trusted CPU cache return/retirement.
 */
void gpu_private_context_quiesce(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long task, unsigned long firmware_root, struct gpu_private_result *result);
/* Trusted consumer only: mappings are frozen by task holds. Walk at most
 * GPU_PRIVATE_BATCH leaf entries/call, keep cursor/token in RMM, skip internal
 * control pages, and retain any partial/ambiguous synchronization until reset.
 * value[0] is the cumulative data-page count, never a backing or table address.
 */
void gpu_private_task_cache(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long task, struct gpu_private_result *result);
/* Internal firmware consumer only, after authenticating a pending tiler OOM.
 * Add a fresh Client-owned RW/XN/WB chunk (32..2048 pages) to empty VA without
 * thawing existing mappings. One <=512-page batch per call, fixed object/VA
 * and exact ready task; data is synchronized BEFORE publishing each leaf.
 * value[0] is cumulative pages, never an address. Partial/uncertain work holds
 * the object and blocks RETURN/RETIRE until full extension or trusted reset.
 * This primitive is not an RSI mapping authorization or an OOM acknowledgement.
 */
void gpu_private_task_extend(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long task, unsigned long object, unsigned long iova,
		unsigned long firmware_root, struct gpu_private_result *result);
/* Trusted firmware consumer after rechecking quiescence and disabled AS on
 * EVERY batch. Invalidates private data only, with an independent private
 * cursor; does not release cache/task/backing/AS leases or authorize reuse.
 */
void gpu_private_task_return(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long task, struct gpu_private_result *result);
/* Trusted firmware consumer only, after complete CPU return, protected group
 * scrub and stopped/disabled hardware revalidation. Drops this task's hold,
 * AS reservation and cache leases; leaves BO mappings and other staged holds.
 */
/* Pure metadata check: requires a complete, quiesced CPU return. No cache,
 * hardware or backing-page callback; caller separately checks real STOP/AS.
 */
void gpu_private_task_returned(const void *service, const void *owner,
		unsigned long context, unsigned long task, struct gpu_private_result *result);

bool gpu_private_task_retire(const void *service, const void *owner,
		unsigned long context, unsigned long task);
/* Trusted consumer only. Maps donated, CPU-hidden arena pages at fixed VAs;
 * Client MAP/UNMAP cannot touch these leaves. No hardware-active edits yet.
 */
void gpu_private_control_mapping(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long object, unsigned int first, unsigned int count,
		bool writable, bool install, struct gpu_private_result *result);
void gpu_private_map(const struct gpu_private_ops *ops, const void *owner,
		unsigned long context, unsigned long object, unsigned long offset,
		unsigned long iova, size_t count, unsigned long prot,
		struct gpu_private_result *result);
void gpu_private_unmap(const struct gpu_private_ops *ops, const void *owner,
		unsigned long context, unsigned long iova, size_t count,
		struct gpu_private_result *result);
/* Atomic cleanup of an uncertain MAP attempt. Empty/other-object leaves stay
 * unchanged. Matching leaves must point at the specified BO page offset;
 * malformed tables or mismatched offsets reject the entire batch. The caller
 * holds xshm_policy_lock across preflight and mutation. Does not cancel grants
 * or reserve VA: outstanding grants retain their own BO/context references.
 */
void gpu_private_unmap_bo(const struct gpu_private_ops *ops, const void *owner,
		unsigned long context, unsigned long object, unsigned long offset,
		unsigned long iova, size_t count, struct gpu_private_result *result);
void gpu_private_context_activate(const struct gpu_private_ops *ops,
		const void *service, unsigned long context, unsigned long slot,
		struct gpu_private_result *result);
void gpu_private_query(const void *owner, unsigned long context,
		unsigned long iova, struct gpu_private_result *result);
/* owner is the actual peer RD resolved from the service's authenticated
 * channel by RSI, never a numeric owner supplied in an RPC payload.
 */
void gpu_private_bo_inspect(const void *service, const void *owner,
		unsigned long object, struct gpu_private_result *result);
void gpu_private_context_inspect(const void *service, const void *owner,
		unsigned long context, struct gpu_private_result *result);
void gpu_private_service_map(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long authorization, unsigned long offset, unsigned long iova,
		size_t count, unsigned long prot, struct gpu_private_result *result);
/* A Client issues an exact, one-use mapping authorization. It holds BO and
 * context references until consumed, cancelled, or trusted device release.
 * Service batches must advance sequentially; the service cannot substitute
 * BO, address, offset, access attributes or context.
 */
void gpu_private_map_authorize(const void *owner, unsigned long context,
		unsigned long object, unsigned long offset, unsigned long iova,
		size_t count, unsigned long prot, struct gpu_private_result *result);
void gpu_private_map_cancel(const void *owner, unsigned long authorization,
		struct gpu_private_result *result);
void gpu_private_service_map_release(const void *service, const void *owner,
		unsigned long context, unsigned long authorization,
		struct gpu_private_result *result);
void gpu_private_service_unmap(const struct gpu_private_ops *ops,
		const void *service, const void *owner, unsigned long context,
		unsigned long iova, size_t count, struct gpu_private_result *result);
/* Trusted-device entry, not an RSI operation. Caller holds the policy gate
 * and has completed BOTH MMIO revocation and verified whole-device reset.
 * Invalidates all old contexts permanently; does not release CPU backing.
 */
/* Client-only exact mapping snapshot. object=0 checks an unmapped range.
 * Returns [verified bytes, non-wrapping mapping epoch, 0, 0], never addresses.
 */
void gpu_private_mapping_check(const struct gpu_private_ops *ops, const void *owner,
        unsigned long context, unsigned long object, unsigned long offset,
        unsigned long iova, size_t count, unsigned long prot,
        struct gpu_private_result *result);
void gpu_private_device_revoked(const struct gpu_private_ops *ops);
bool gpu_private_owner_busy(const void *owner);
bool gpu_private_range_busy(const void *owner, unsigned long ipa,
		unsigned long size);


/* Validated CPU-readable NC data hint, never a completion certificate. */
bool gpu_private_task_hint_check(const struct gpu_private_ops *ops, const void *service,
		const void *owner, unsigned long context, unsigned long iova);

#endif
