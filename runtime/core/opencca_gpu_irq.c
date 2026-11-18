/* SPDX-License-Identifier: BSD-3-Clause */
#include <arch_helpers.h>
#include <debug.h>
#include <opencca_gpu_irq.h>
#include <opencca_gpu_irq_consumer.h>
#include <rmm_el3_ifc.h>
#include <smc.h>
#include <stddef.h>
#include <string.h>

/* All calls are serialized by xshm_policy_lock. EL3 owns a separate lock and
 * never re-enters RMM. Its shared-page lock is released before any callback.
 */
static struct ogi_consumer consumer;
static struct ogi_mailbox mailbox;
static struct ogi_statistics statistics;
static bool active;
/* Dedicated RMM-private BSS, never a Client control pool or GPU mapping.
 * The platform's fixed RMM reserved region is already mapped by Root.
 */
static struct ogi_fast_view fast_view __attribute__((aligned(4096)));
static bool view_registered;
static uint64_t last_view_sequence, fast_hits, fast_misses;

/* Pure protocol models and other platforms safely use the old SMC path. */
__attribute__((weak)) bool plat_opencca_gpu_irq_idle(uint32_t gpu_mask,
						     uint32_t job_mask,
						     uint32_t mmu_mask)
{
	(void)gpu_mask;
	(void)job_mask;
	(void)mmu_mask;
	return false;
}

_Static_assert(OGI_CLAIM_PROGRESS == 1U && OGI_CLAIM_FAULT == 2U &&
		       OGI_CLAIM_COMPLETE == 3U,
	       "Claim kind ABI");

static unsigned int invoke(unsigned int command)
{
	uintptr_t shared = rmm_el3_ifc_get_shared_buf_locked();
	mailbox.abi = OGI_ABI;
	mailbox.command = command;
	mailbox.count = 0U;
	mailbox.status = OGI_STATE;
	memset(mailbox.records, 0, sizeof(mailbox.records));
	const size_t prefix = offsetof(struct ogi_mailbox, records);
	/* Requests never contain records. Keep the fixed maximum wire extent,
	 * but synchronize only the actual request/response bytes, especially for
	 * the common no-event observation. Root validates and zeroes output count.
	 */
	memcpy((void *)shared, &mailbox, prefix);
	flush_dcache_range(shared, prefix);
	unsigned long status = monitor_call(SMC_RMM_OPENCCA_GPU_IRQ, command,
					    rmm_el3_ifc_get_shared_buf_pa(),
					    sizeof(mailbox), 0UL, 0UL, 0UL);
	inv_dcache_range(shared, prefix);
	memcpy(&mailbox, (const void *)shared, prefix);
	if (status > OGI_STALE || status != mailbox.status ||
	    mailbox.abi != OGI_ABI || mailbox.command != command ||
	    mailbox.count > OGI_BATCH) {
		consumer.lost = true;
		rmm_el3_ifc_release_shared_buf();
		return OGI_LOST;
	}
	if (mailbox.count != 0U) {
		size_t bytes = mailbox.count * sizeof(mailbox.records[0]);
		inv_dcache_range(shared + prefix, bytes);
		memcpy(mailbox.records, (const void *)(shared + prefix), bytes);
	}
	rmm_el3_ifc_release_shared_buf();
	statistics = mailbox.stats;
	if (command == OGI_START && status == OGI_OK &&
	    !statistics.simulation) {
		/* Optional optimization: unsupported registration keeps old drains.
		 * Only a successful, fresh START can install a new protected view.
		 */
		view_registered = false;
		last_view_sequence = 0U;
		memset(&fast_view, 0, sizeof(fast_view));
		flush_dcache_range((uintptr_t)&fast_view, sizeof(fast_view));
		dsb(sy);
		mailbox.view_pa = (uintptr_t)&fast_view;
		view_registered = invoke(OGI_VIEW_REGISTER) == OGI_OK;
	}
	return (unsigned int)status;
}

static bool fast_empty(void)
{
	struct ogi_fast_view snapshot;
	uint64_t before, after;

	if (!view_registered)
		return false;
	inv_dcache_range((uintptr_t)&fast_view, sizeof(fast_view));
	dsb(sy);
	before = __atomic_load_n(&fast_view.sequence, __ATOMIC_ACQUIRE);
	/* The acquire orders all payload reads after the first version load.
	 * Bytewise volatile capture forbids speculative compiler reuse of
	 * fields modified by the independent Root producer. Sequence itself
	 * is accessed atomically, never through this payload copy.
	 */
	snapshot.sequence = before;
	for (size_t i = sizeof(before); i < sizeof(snapshot); i++)
		((unsigned char *)&snapshot)[i] =
			((const volatile unsigned char *)&fast_view)[i];
	if (before == 0U || (before & 1U) != 0U ||
	    before < last_view_sequence || snapshot.abi != OGI_ABI ||
	    snapshot.reserved != 0U || snapshot.magic != OGI_FAST_MAGIC ||
	    !snapshot.stats.active || snapshot.stats.simulation ||
	    snapshot.stats.lost || snapshot.stats.queued != 0U ||
	    snapshot.stats.produced != consumer.received ||
	    snapshot.stats.consumed != consumer.received ||
	    snapshot.stats.device_epoch != consumer.device_epoch ||
	    snapshot.stats.binding_generation !=
		    statistics.binding_generation ||
	    snapshot.masks_valid != 1U || snapshot.masks[0] != 3U)
		return false;
	uint32_t required_job = UINT32_C(1) << 31U, required_mmu = 1U;
	for (unsigned int i = 0U; i < OGI_CSGS; i++) {
		const struct ogi_binding *binding = &consumer.bindings[i];
		if (binding->epoch != 0U) {
			if (binding->csg != i || binding->as >= OGI_AS_COUNT)
				return false;
			required_job |= UINT32_C(1) << i;
			required_mmu |= UINT32_C(1) << binding->as;
		}
	}
	if ((snapshot.masks[1] & required_job) != required_job ||
	    (snapshot.masks[2] & required_mmu) != required_mmu ||
	    !plat_opencca_gpu_irq_idle(snapshot.masks[0], snapshot.masks[1],
				       snapshot.masks[2]))
		return false;
	/* Root publishes odd BEFORE masking/capturing/W1C. Re-read after all
	 * fresh hardware accesses; a cleared fault cannot hide behind old stats.
	 */
	inv_dcache_range((uintptr_t)&fast_view, sizeof(fast_view));
	dsb(sy);
	after = __atomic_load_n(&fast_view.sequence, __ATOMIC_ACQUIRE);
	if (after != before || (after & 1U) != 0U)
		return false;
	last_view_sequence = after;
	statistics = snapshot.stats;
	return true; /* Empty drain only; caller still checks binding/fault latch. */
}

static bool drain(bool quiet)
{
	if (!active || consumer.lost)
		return false;
	if (!quiet && view_registered) {
		if (fast_empty()) {
			if (fast_hits != UINT64_MAX)
				fast_hits++;
			return true;
		}
		if (fast_misses != UINT64_MAX)
			fast_misses++;
	}
	for (unsigned int attempt = 0U; attempt <= OGI_CAPACITY / OGI_BATCH;
	     attempt++) {
		mailbox.acknowledge = consumer.received;
		unsigned int status =
			invoke(quiet ? OGI_DRAIN_QUIET : OGI_DRAIN);
		if (status != OGI_OK && status != OGI_EMPTY) {
			consumer.lost = true;
			return false;
		}
		if (!statistics.active || statistics.lost ||
		    statistics.device_epoch != consumer.device_epoch) {
			consumer.lost = true;
			return false;
		}
		for (unsigned int i = 0U; i < mailbox.count; i++) {
			status = ogi_consumer_ingest(&consumer,
						     &mailbox.records[i]);
			if (status != OGI_OK && status != OGI_STALE)
				return false;
		}
		/* Newly copied records remain protected in RMM before their Root
		 * positions are acknowledged. No callback can erase their fault latch.
		 * The next call acknowledges this last batch, avoiding a redundant SMC
		 * on every ordinary task observation.
		 */
		if (mailbox.count < OGI_BATCH)
			return true;
	}
	consumer.lost = true;
	return false;
}

bool opencca_gpu_irq_start(void)
{
	if (active)
		return !consumer.lost && !consumer.global_fault;
	memset(&mailbox, 0, sizeof(mailbox));
	if (invoke(OGI_START) != OGI_OK)
		return false;
	ogi_consumer_start(&consumer, statistics.device_epoch,
			   statistics.consumed, false);
	active = true;
	if (!drain(false) || consumer.global_fault) {
		/* A recorded startup fault is not a healthy configured service.
		 * Preserve failure state, and stop the newly acquired interrupt lease.
		 */
		(void)invoke(OGI_STOP);
		active = false;
		consumer.lost = true;
		return false;
	}
	return true;
}

void opencca_gpu_irq_revoke(void)
{
	view_registered = false;
	if (active)
		(void)invoke(OGI_STOP);
	active = false;
	consumer.lost = true;
}

/* Drain and acknowledge the current cutover boundary. The caller separately
 * proves hardware nonexecution before UNBIND; clearing a pending GIC bit alone
 * is not that proof. Old RMM records are invalidated on close, never retagged.
 */
static bool boundary(void)
{
	for (unsigned int i = 0U; i < 4U; i++) {
		if (!drain(true))
			return false;
		if (statistics.produced == statistics.consumed &&
		    statistics.queued == 0U)
			return true;
	}
	return false;
}

bool opencca_gpu_irq_bind(const void *owner, unsigned long context,
			  unsigned long group, unsigned int csg,
			  unsigned int as, uint64_t *epoch)
{
	if (epoch == NULL)
		return false;
	for (unsigned int i = 0U; i < 16U; i++) {
		if (!boundary())
			return false;
		mailbox.binding =
			(struct ogi_binding){ .owner = (uintptr_t)owner,
					      .context = context,
					      .group = group,
					      .csg = csg,
					      .as = as };
		unsigned int status = invoke(OGI_BIND);
		if (status == OGI_STATE && !statistics.lost)
			continue;
		if (status != OGI_OK ||
		    ogi_consumer_bind(&consumer, &mailbox.binding) != OGI_OK)
			return false;
		*epoch = mailbox.binding.epoch;
		return true;
	}
	return false;
}

bool opencca_gpu_irq_sync(unsigned int csg, uint64_t epoch, uint64_t *sequence)
{
	if (csg >= OGI_CSGS || !drain(false) ||
	    consumer.bindings[csg].epoch != epoch ||
	    !ogi_consumer_healthy(&consumer, &consumer.bindings[csg]))
		return false;
	if (sequence != NULL)
		*sequence = consumer.received;
	return true;
}

bool opencca_gpu_irq_begin(unsigned int csg, uint64_t epoch, uint64_t *sequence)
{
	if (!opencca_gpu_irq_sync(csg, epoch, sequence))
		return false;
	ogi_consumer_begin(&consumer, &consumer.bindings[csg]);
	return true;
}

bool opencca_gpu_irq_close(unsigned int csg, uint64_t epoch)
{
	if (csg >= OGI_CSGS || consumer.bindings[csg].epoch != epoch)
		return false;
	for (unsigned int i = 0U; i < 16U; i++) {
		if (!boundary())
			return false;
		mailbox.binding = consumer.bindings[csg];
		unsigned int status = invoke(OGI_UNBIND);
		if (status == OGI_STATE && !statistics.lost)
			continue;
		if (status != OGI_OK)
			return false;
		return ogi_consumer_close(&consumer, &consumer.bindings[csg]) ==
		       OGI_OK;
	}
	return false;
}

unsigned int opencca_gpu_irq_next(unsigned int csg, uint64_t epoch,
				  uint64_t after, unsigned long values[4])
{
	struct ogi_record record;
	if (csg >= OGI_CSGS || !drain(false) ||
	    consumer.bindings[csg].epoch != epoch)
		return OGI_STATE;
	unsigned int status = ogi_consumer_next(
		&consumer, &consumer.bindings[csg], after, &record);
	if (status == OGI_OK) {
		values[0] = record.sequence;
		values[1] = record.binding_epoch;
		values[2] = record.flags;
		values[3] = record.device_epoch;
	}
	return status;
}

unsigned int opencca_gpu_irq_claim(unsigned int csg, uint64_t epoch,
				   uint64_t after, uint64_t sequence,
				   uint64_t binding_epoch,
				   uint64_t device_epoch, unsigned int kind,
				   bool completed)
{
	if (csg >= OGI_CSGS || !drain(false) ||
	    consumer.bindings[csg].epoch != epoch)
		return OGI_STATE;
	return ogi_consumer_claim(&consumer, &consumer.bindings[csg], after,
				  sequence, binding_epoch, device_epoch, kind,
				  completed);
}

bool opencca_gpu_irq_status(unsigned int selector, unsigned long values[4])
{
	if (selector == 2U) {
		values[0] = fast_hits;
		values[1] = fast_misses;
		values[2] = view_registered;
		values[3] = OGI_ABI;
		return true; /* Diagnostic counts, never completion/health evidence. */
	}
	if (selector > 2U)
		return false;
	if (invoke(OGI_STATS) != OGI_OK)
		return false;
	if (selector == 0U) {
		values[0] = statistics.physical_deliveries;
		values[1] = statistics.root_samples;
		values[2] = statistics.simulated;
		values[3] = statistics.overflows;
	} else {
		values[0] = consumer.claimed;
		values[1] = consumer.rejected;
		values[2] = statistics.device_epoch;
		values[3] = consumer.lost || consumer.global_fault;
	}
	return true;
}

static bool simulation_start(void)
{
	(void)invoke(OGI_STOP);
	active = false;
	memset(&mailbox, 0, sizeof(mailbox));
	mailbox.snapshot.flags = OGI_SOURCE_SIMULATION;
	if (invoke(OGI_START) != OGI_OK)
		return false;
	ogi_consumer_start(&consumer, statistics.device_epoch,
			   statistics.consumed, true);
	active = true;
	return true;
}

static bool simulation_capture(uint32_t job, uint32_t mmu)
{
	mailbox.snapshot =
		(struct ogi_snapshot){ .flags = OGI_SOURCE_SIMULATION,
				       .intid = OGI_JOB_INTID,
				       .cpu = 0U,
				       .job_raw = job,
				       .mmu_raw = mmu,
				       .timestamp = read_cntpct_el0() };
	mailbox.snapshot.fault_status[1] = 0x42U;
	mailbox.snapshot.fault_address[1] = 0x80001234U;
	return invoke(OGI_SIM_CAPTURE) == OGI_OK;
}

bool opencca_gpu_irq_selftest(const void *owner, unsigned long context,
			      unsigned long group, unsigned long values[4])
{
	/* Firmware admits this fixed experiment only with zero prepared/running
	 * hardware groups. No Guest can supply snapshots, simulated source flags,
	 * arbitrary bindings, or a positive completion predicate.
	 */
	unsigned long event[4] = { 0 };
	uint64_t epoch, new_epoch, before = statistics.simulated;
	unsigned int checks = 0U;
	bool passed = false;
	if (!active || !boundary() || consumer.lost || consumer.global_fault)
		return false;
	for (unsigned int i = 0U; i < OGI_CSGS; i++)
		if (consumer.bindings[i].epoch != 0U)
			return false;
#define CHECK(x)                  \
	do {                      \
		if (!(x))         \
			goto out; \
		checks++;         \
	} while (0)
	CHECK(simulation_start());
	CHECK(opencca_gpu_irq_bind(owner, context, group, 0U, 1U, &epoch));
	CHECK(simulation_capture(1U, 0U));
	CHECK(opencca_gpu_irq_next(0U, epoch, 0U, event) == OGI_OK);
	CHECK(event[2] == OGI_SOURCE_SIMULATION);
	CHECK(opencca_gpu_irq_claim(0U, epoch, 0U, event[0] + 1U, epoch,
				    event[3], OGI_CLAIM_PROGRESS,
				    false) == OGI_STALE);
	CHECK(opencca_gpu_irq_claim(0U, epoch, 0U, event[0], epoch + 1U,
				    event[3], OGI_CLAIM_PROGRESS,
				    false) == OGI_STALE);
	CHECK(opencca_gpu_irq_claim(0U, epoch, 0U, event[0], epoch,
				    event[3] + 1U, OGI_CLAIM_PROGRESS,
				    false) == OGI_STALE);
	CHECK(opencca_gpu_irq_claim(0U, epoch, 0U, event[0], epoch, event[3],
				    OGI_CLAIM_COMPLETE, false) == OGI_STATE);
	CHECK(opencca_gpu_irq_claim(0U, epoch, 0U, event[0], epoch, event[3],
				    OGI_CLAIM_PROGRESS, false) == OGI_OK);
	CHECK(opencca_gpu_irq_claim(0U, epoch, 0U, event[0], epoch, event[3],
				    OGI_CLAIM_PROGRESS, false) == OGI_STALE);
	CHECK(simulation_capture(1U, 0U));
	CHECK(opencca_gpu_irq_next(0U, epoch, 0U, event) == OGI_OK);
	CHECK(opencca_gpu_irq_close(0U, epoch));
	CHECK(opencca_gpu_irq_bind(owner, context, group, 0U, 1U, &new_epoch));
	CHECK(new_epoch > epoch);
	CHECK(opencca_gpu_irq_claim(0U, new_epoch, 0U, event[0], epoch,
				    event[3], OGI_CLAIM_PROGRESS,
				    false) == OGI_STALE);
	CHECK(simulation_capture(1U, 1U << 1U));
	CHECK(opencca_gpu_irq_next(0U, new_epoch, 0U, event) == OGI_OK);
	CHECK((event[2] & OGI_EVENT_FAULT) != 0U);
	CHECK(!opencca_gpu_irq_sync(0U, new_epoch, NULL));
	CHECK(opencca_gpu_irq_claim(0U, new_epoch, 0U, event[0], new_epoch,
				    event[3], OGI_CLAIM_COMPLETE,
				    true) == OGI_STALE);
	CHECK(opencca_gpu_irq_claim(0U, new_epoch, 0U, event[0], new_epoch,
				    event[3], OGI_CLAIM_FAULT,
				    false) == OGI_OK);
	CHECK(!opencca_gpu_irq_sync(0U, new_epoch, NULL));
	CHECK(simulation_start());
	CHECK(opencca_gpu_irq_bind(owner, context, group, 0U, 1U, &epoch));
	for (unsigned int i = 0U; i < OGI_CAPACITY; i++)
		CHECK(simulation_capture(1U, 0U));
	mailbox.snapshot =
		(struct ogi_snapshot){ .flags = OGI_SOURCE_SIMULATION,
				       .intid = OGI_JOB_INTID,
				       .cpu = 0U,
				       .job_raw = 1U };
	CHECK(invoke(OGI_SIM_CAPTURE) == OGI_LOST && statistics.lost);
	CHECK(!opencca_gpu_irq_sync(0U, epoch, NULL));
	passed = true;
out:
	(void)invoke(OGI_STOP);
	active = false;
	bool restored = opencca_gpu_irq_start();
	values[0] = checks;
	values[1] = statistics.simulated - before;
	values[2] = statistics.device_epoch;
	values[3] = passed && restored ? 0UL : 1UL;
#undef CHECK
	return passed && restored;
}
