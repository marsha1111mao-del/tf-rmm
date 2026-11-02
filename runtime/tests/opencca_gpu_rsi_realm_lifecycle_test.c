/* SPDX-License-Identifier: BSD-3-Clause */
/* Real RMI destruction/policy bodies on the two-Client task/memory chain.
 * RD allocation, REC references, RTT primitives, locks and MMIO remain models.
 * In particular, recycling below is NOT smc_realm_create() coverage. */
#define GPU_RSI_REALM_LIFECYCLE_TEST
static void task_realm_lifecycle(void);
#include "opencca_gpu_rsi_task_chain_test.c"
#include <errno.h>
#include <smc-rmi.h>

#define RMI_ERROR_REALM 2UL
#define INFO(...) ((void)fprintf(stderr, __VA_ARGS__))
static unsigned int lifecycle_dead, lifecycle_vmid_frees, lifecycle_transitions;
static bool lifecycle_memory_busy, lifecycle_iommu_busy;

bool xshm_memory_owner_busy(const void *owner)
{ return lifecycle_memory_busy && owner == &chain_owners[lifecycle_dead]; }
bool opencca_iommu_owner_busy(const void *owner)
{ return lifecycle_iommu_busy && owner == &chain_owners[lifecycle_dead]; }
static unsigned long granule_addr(const struct granule *owner)
{
	for (unsigned int c = 0; c < OWNERS; c++)
		if (owner == &chain_owners[c]) return CHAIN_RD_PA + c * 4096UL;
	chain_expect(false, "known RD address"); return 0;
}
static int find_lock_unused_granule(unsigned long address, enum granule_state state,
		struct granule **result)
{
	*result = find_lock_granule(address, state);
	if (*result == NULL) return -EINVAL;
	if ((*result)->refs != 0U) { granule_unlock(*result); return -EBUSY; }
	return 0;
}
static void vmid_free(unsigned int vmid)
{
	chain_expect(vmid == 100U + lifecycle_dead, "destroy frees the selected Realm VMID");
	for (unsigned int t = 0; t < 3; t++)
		chain_expect(chain_rtt[lifecycle_dead][t].refs == 0U,
			"nonempty RTT must reject destroy before VMID release");
	lifecycle_vmid_frees++;
}
static void buffer_granule_memzero(struct granule *granule, unsigned int slot)
{
	void *memory = buffer_granule_map(granule, slot);
	memset(memory, 0, slot == SLOT_RD ? sizeof(struct rd) : 4096U);
	buffer_unmap(memory);
}
static void granule_unlock_transition(struct granule *granule, enum granule_state state)
{
	chain_expect(state == GRANULE_STATE_DELEGATED && granule->locked,
		"destroy transitions only locked granules to delegated");
	if (granule->state == GRANULE_STATE_RD) {
		const unsigned char *bytes = (const unsigned char *)&chain_rd[lifecycle_dead];
		for (size_t i = 0; i < sizeof(struct rd); i++)
			chain_expect(bytes[i] == 0U, "RD transition follows complete metadata scrub");
	} else {
		chain_expect(granule->state == GRANULE_STATE_RTT && !granule->refs,
			"destroy releases an unreferenced root RTT");
		unsigned int t = (unsigned int)(granule - &chain_rtt[lifecycle_dead][0]);
		chain_expect(t < 3U, "root RTT belongs to destroyed Realm");
		for (unsigned int i = 0; i < 512; i++)
			chain_expect(chain_entries[lifecycle_dead][t][i] == 0UL,
				"RTT transition follows complete table scrub");
	}
	lifecycle_transitions++;
	granule->state = state;
	granule_unlock(granule);
}

/* Unmodified production functions, including the RMI policy and destroy body. */
#include "chain-realm-actual.inc"

static unsigned long lifecycle_destroy(unsigned long address, bool *allowed)
{
	unsigned long result;
	xshm_policy_lock();
	*allowed = xshm_rmi_allowed(SMC_RMI_REALM_DESTROY, address, 0, 0, 0);
	result = *allowed ? smc_realm_destroy(address) : RMI_ERROR_INPUT;
	xshm_policy_unlock();
	chain_balanced();
	return result;
}

static void lifecycle_policy_denied(void)
{
	bool allowed;
	unsigned int locked = chain_locks, freed = lifecycle_vmid_frees;
	unsigned int changed = lifecycle_transitions, written = writes;
	unsigned long endpoint = xshm_endpoint_id(&chain_owners[lifecycle_dead]);
	chain_expect(lifecycle_destroy(granule_addr(&chain_owners[lifecycle_dead]), &allowed) == RMI_ERROR_INPUT &&
		!allowed, "RMI policy blocks destroy while private registrations remain");
	chain_expect(chain_locks == locked && lifecycle_vmid_frees == freed &&
		lifecycle_transitions == changed && writes == written &&
		xshm_endpoint_id(&chain_owners[lifecycle_dead]) == endpoint,
		"policy rejection has no granule VMID device or endpoint effects");
}

static void lifecycle_drop_rtt_entries(void)
{
	/* Model Host RTT teardown AFTER trusted reclaim. The production
	 * DATA_DESTROY/RTT_DESTROY bodies and real TLBI are not executed here. */
	chain_expect(!gpu_private_owner_busy(&chain_owners[lifecycle_dead]),
		"modeled Host RTT teardown follows complete private reclaim");
	for (unsigned int p = 0; p < CHAIN_PAGES; p++)
		chain_expect(!chain_data[lifecycle_dead][p].refs, "no pinned data before modeled Host RTT teardown");
	for (unsigned int t = 0; t < 3; t++) {
		memset(chain_entries[lifecycle_dead][t], 0, 4096U);
		/* A reference-free root can still contain unassigned descriptors.
		 * Leave one to independently require actual free_sl_rtts scrubbing. */
		chain_entries[lifecycle_dead][t][511] = 32UL;
		chain_rtt[lifecycle_dead][t].refs = 0U;
	}
}

static void task_realm_lifecycle(void)
{
	lifecycle_dead = task_fault_case == 7U ? 0U : 2U;
	unsigned long address = granule_addr(&chain_owners[lifecycle_dead]);
	unsigned long old_id[OWNERS], old_channels[2], output[4], peer;
	for (unsigned int c = 0; c < OWNERS; c++) {
		old_id[c] = xshm_endpoint_id(&chain_owners[c]);
		chain_rd[c].s2_ctx.num_root_rtts = 3U;
		chain_rd[c].s2_ctx.vmid = 100U + c;
	}
	memcpy(old_channels, chain_channels, sizeof(old_channels));
	bool allowed;
	/* Private registration is the sole policy blocker in these probes. */
	lifecycle_policy_denied();
	chain_owners[lifecycle_dead].refs = 0U;
	lifecycle_policy_denied();
	chain_expect(task_pm(OPENCCA_GPU_RELEASE, 0, 0).x[0] == RMI_SUCCESS,
		"trusted release precedes RD reclamation");
	lifecycle_policy_denied();
	chain_realm_state[lifecycle_dead] = REALM_SYSTEM_OFF;
	struct smc_result reclaimed = task_reclaim(address, 0);
	if (lifecycle_dead == 2U) {
		chain_expect(reclaimed.x[0] == RMI_SUCCESS && reclaimed.x[2] == GPU_PRIVATE_INCOMPLETE,
			"service reclaim first restores only a bounded control suffix");
		lifecycle_policy_denied();
		reclaimed = task_reclaim(address, 0);
	}
	chain_expect(reclaimed.x[0] == RMI_SUCCESS && reclaimed.x[2] == GPU_PRIVATE_SUCCESS &&
		!gpu_private_owner_busy(&chain_owners[lifecycle_dead]), "complete reclaim removes destroyed RD GPU identity");
	/* Exercise independent actual policy blockers after GPU registrations
	 * are gone, so GPU rejection cannot mask missing shared/IOMMU guards. */
	for (unsigned int kind = 0; kind < 2; kind++) {
		lifecycle_memory_busy = kind == 0U; lifecycle_iommu_busy = kind == 1U;
		chain_expect(lifecycle_destroy(address, &allowed) == RMI_ERROR_INPUT && !allowed,
			"other memory owners still block actual Realm-destroy policy");
	}
	lifecycle_memory_busy = lifecycle_iommu_busy = false;
	/* After GPU/policy blockers are gone, independently exercise the actual
	 * unused-RD and root-ref checks. Reference counts remain model inputs. */
	chain_owners[lifecycle_dead].refs = 1U;
	unsigned int locked = chain_locks;
	chain_expect(lifecycle_destroy(address, &allowed) == RMI_ERROR_REALM && allowed &&
		chain_locks == locked + 1U, "existing REC blocks destroy before RTT traversal");
	chain_owners[lifecycle_dead].refs = 0U;
	chain_expect(lifecycle_destroy(address, &allowed) == RMI_ERROR_REALM && allowed &&
		!lifecycle_vmid_frees && !lifecycle_transitions,
		"nonempty RTT must reject destroy before VMID release");
	chain_expect(lifecycle_destroy(address + 1UL, &allowed) == RMI_ERROR_INPUT && allowed,
		"actual destroy rejects malformed RD address");
	lifecycle_drop_rtt_entries();
	/* Seed an old pending event/IRQ binding. A new Realm at the same RD
	 * address must receive neither event state nor channel authority. */
	chain_expect(xshm_endpoint_call(&chain_owners[lifecycle_dead], XSHM_IRQ_BIND, 0, 0, output) == XSHM_SUCCESS &&
		xshm_endpoint_call(&chain_owners[lifecycle_dead], XSHM_ACK_ARM, old_channels[0], 0, output) == XSHM_SUCCESS,
		"old endpoint has armed IRQ binding");
	unsigned int sender = lifecycle_dead == 0U ? 2U : 0U;
	chain_expect(xshm_endpoint_call(&chain_owners[sender], XSHM_NOTIFY, old_channels[0], 0, output) == XSHM_SUCCESS && output[2] == 1UL,
		"old endpoint has real pending notification");
	chain_expect(lifecycle_destroy(address, &allowed) == RMI_SUCCESS && allowed &&
		lifecycle_vmid_frees == 1U && lifecycle_transitions == 4U &&
		chain_owners[lifecycle_dead].state == GRANULE_STATE_DELEGATED,
		"actual destroy scrubs and delegates RD and all roots");
	chain_expect(!xshm_endpoint_id(&chain_owners[lifecycle_dead]) &&
		!xshm_endpoint_irq_enabled(&chain_owners[lifecycle_dead]) &&
		!xshm_endpoint_irq_take(&chain_owners[lifecycle_dead]),
		"actual Realm destroy releases endpoint and pending IRQ identity");
	if (lifecycle_dead == 2U)
		chain_expect(opencca_gpu_state() == OPENCCA_GPU_UNOWNED,
			"destroyed GPU owner is detached before RD reuse");
	for (unsigned int c = 0; c < OWNERS; c++) if (c != lifecycle_dead)
		chain_expect(xshm_endpoint_id(&chain_owners[c]) == old_id[c], "living Realm endpoint identity preserved");
	if (lifecycle_dead == 0U)
		chain_expect(xshm_endpoint_peer(&chain_owners[1], old_channels[1], &peer) == &chain_owners[2] &&
			peer == old_id[2] && xshm_endpoint_call(&chain_owners[1], XSHM_QUERY, old_channels[1], 0, output) == XSHM_SUCCESS,
			"unrelated living Client channel remains usable");
	for (unsigned int c = 0; c < 2; c++) {
		if (lifecycle_dead == 0U && c == 1U) continue;
		unsigned int alive = lifecycle_dead == 2U ? c : 2U;
		chain_expect(xshm_endpoint_call(&chain_owners[alive], XSHM_QUERY, old_channels[c], 0, output) != XSHM_SUCCESS,
			"destroyed Realm removes old channel event authority");
	}
	/* Model a new RD/REC allocation at the SAME granule address. This is
	 * not execution of smc_realm_create; endpoint IDs are real core IDs. */
	chain_owners[lifecycle_dead].state = GRANULE_STATE_RD;
	chain_owners[lifecycle_dead].refs = 1U;
	chain_realm_state[lifecycle_dead] = REALM_ACTIVE;
	chain_expect(xshm_endpoint_call(&chain_owners[lifecycle_dead], XSHM_REGISTER, 0, 0, output) == XSHM_SUCCESS &&
		output[0] == XSHM_ABI_VERSION && output[1] > old_id[lifecycle_dead] &&
		output[1] == xshm_endpoint_id(&chain_owners[lifecycle_dead]), "recycled RD receives fresh endpoint generation");
	chain_expect(!xshm_endpoint_irq_enabled(&chain_owners[lifecycle_dead]) &&
		!xshm_endpoint_irq_take(&chain_owners[lifecycle_dead]), "recycled RD does not inherit IRQ state");
	for (unsigned int c = 0; c < 2; c++) {
		if (lifecycle_dead == 0U && c == 1U) continue;
		chain_expect(xshm_endpoint_peer(&chain_owners[lifecycle_dead], old_channels[c], &peer) == NULL && !peer &&
			xshm_endpoint_call(&chain_owners[lifecycle_dead], XSHM_NOTIFY, old_channels[c], 0, output) != XSHM_SUCCESS,
			"recycled RD cannot reuse old channel");
		chain_channels[c] = chain_open(c, true);
		chain_expect(chain_channels[c] != old_channels[c], "new explicit channel has fresh generation");
	}
	for (unsigned int c = 0; c < 2; c++) {
		if (c == lifecycle_dead) continue;
		chain_expect(gpu_private_range_busy(&chain_owners[c], DATA_IPA, 8192),
			"RD reuse preserves living Client data registration");
	}
	/* New legitimate channels still must not recover old GPU authority. */
	for (unsigned int c = 0; c < 2; c++) {
		struct gpu_private_result r;
		xshm_policy_lock();
		gpu_private_bo_inspect(&chain_owners[2], &chain_owners[c], task_bos[c], &r);
		xshm_policy_unlock();
		if (lifecycle_dead == 2U || c == 0U)
			chain_expect(r.status != GPU_PRIVATE_SUCCESS, "new RD cannot inspect old Client BO through new channel");
		chain_denied(chain_call(2, GPU_PRIVATE_TASK_DISPATCH, task_tokens[c], chain_channels[c],
			task_contexts[c], task_groups[c], 0, 0));
	}
	for (unsigned int c = 0; c < 2; c++) {
		if (c == lifecycle_dead) continue;
		chain_success(chain_call(c, GPU_PRIVATE_CONTEXT_DESTROY, task_contexts[c], 0, 0, 0, 0, 0));
		chain_success(chain_call(c, GPU_PRIVATE_BO_DESTROY, task_bos[c], 0, 0, 0, 0, 0));
	}
	if (lifecycle_dead != 2U) task_destroy_arena();
	chain_expect(!task_cpu_returns[0] && !task_cpu_returns[1], "Realm destroy never forges GPU completion");
	printf("GPU_RSI_REALM_LIFECYCLE=PASS destroyed=%u vmid_frees=%u delegated=%u actual_policy/REALM_DESTROY/endpoint_release modeled_RD_reallocation no_REALM_CREATE/GPC/concurrency\n",
		lifecycle_dead, lifecycle_vmid_frees, lifecycle_transitions);
}
