/* SPDX-License-Identifier: BSD-3-Clause */
/* One RSI -> endpoint -> snapshot -> RTT -> private PT/memory call chain.
 * Low-level REC/RTT descriptors, locks, slots, cache effects and MMIO remain
 * host models. Reuse the existing backend only for platform/link fixtures. */
#define main gpu_backend_fixture_main
#include "opencca_gpu_backend_test.c"
#undef main
#include "rtt-stubs/control_rtt_model.h"
#include <xshm_endpoint.h>
#include <xshm_runtime.h>
#include <arch_helpers.h>

#define OWNERS 4U
#define CHAIN_PAGES 522U
#define INPUT_IPA 0x200000UL
#define DATA_IPA (INPUT_IPA + 4096UL)
#define ARENA_IPA 0x400000UL
#define CHAIN_RD_PA 0x50000000UL
#ifdef GPU_RSI_TASK_CHAIN_TEST
/* Device double dereferences hardware-format PTEs into device-visible bytes.
 * These host addresses model physical pages; no physical GPC is simulated. */
#define CHAIN_PA ((uintptr_t)chain_device)
#else
#define CHAIN_PA 0x60000000UL
#endif
#define SLOT_RSI_CALL 3U
#define MAX_CPUS 1U
#define UPDATE_REC_RETURN_TO_REALM 1U
#define STAGE_2_TRANSLATION_FAULT 6U
enum ripas { RIPAS_EMPTY, RIPAS_RAM, RIPAS_DESTROYED };
enum s2_walk_status { WALK_SUCCESS, WALK_INVALID_PARAMS, WALK_FAIL };
struct rec {
	struct { const void *g_rd; struct s2tt_context s2_ctx; } realm_info;
	unsigned long regs[8];
};
struct rsi_result {
	unsigned int action;
	unsigned long rtt_level;
	struct { unsigned long x[8]; } smc_res;
};
struct s2_walk_result {
	unsigned long pa, rtt_level;
	enum ripas ripas_val;
	struct granule *llt;
};
static struct granule chain_owners[OWNERS], chain_rtt[OWNERS][3];
static struct granule chain_data[OWNERS][CHAIN_PAGES];
static struct rd chain_rd[OWNERS];
static unsigned long chain_entries[OWNERS][3][512];
static unsigned char chain_cpu[OWNERS][CHAIN_PAGES][4096] __attribute__((aligned(4096)));
static unsigned char chain_device[OWNERS][CHAIN_PAGES][4096] __attribute__((aligned(4096)));
static bool chain_mapped[OWNERS][CHAIN_PAGES], chain_rd_map[OWNERS], chain_rtt_map[OWNERS][3];
static bool chain_policy, chain_mutate;
static bool chain_shared_busy, chain_iommu_busy;
static unsigned int chain_locks, chain_unlocks, chain_calls, chain_checks;
static unsigned int chain_invalidates, chain_cleans, chain_flushes, chain_tlbis;
static unsigned long chain_channels[2];
static unsigned long chain_last_op, chain_last_owner;
#ifdef GPU_RSI_TASK_CHAIN_TEST
static void task_after_unmap(unsigned int owner, unsigned int page);
static void task_before_cache(unsigned int owner, unsigned int page, bool to_device);
#endif
static unsigned long input_pages[MAX_CPUS][GPU_PRIVATE_BATCH];
static struct gpu_firmware_queue_config input_queues[MAX_CPUS][GPU_FIRMWARE_STREAMS];
static struct gpu_firmware_task_command input_commands[MAX_CPUS][GPU_PRIVATE_TASK_BATCH];

static void chain_expect(bool value, const char *reason)
{
	if (!value) {
		fprintf(stderr, "GPU_RSI_MEMORY_CHAIN_REJECT %s\n", reason);
		assert(false);
	}
}
static unsigned long chain_ipa(unsigned int page)
{ return page < 9U ? INPUT_IPA + page * 4096UL : ARENA_IPA + (page - 9U) * 4096UL; }
static unsigned long *chain_entry(unsigned int owner, unsigned int page)
{
	unsigned long ipa = chain_ipa(page);
	return &chain_entries[owner][(ipa >> 21U) - 1UL][(ipa >> 12U) & 511UL];
}
void granule_lock(struct granule *g, enum granule_state state)
{
	chain_expect(chain_policy && g && !g->locked && g->state == state, "valid serialized granule lock");
	g->locked = true; chain_locks++;
}
void granule_unlock(struct granule *g)
{
	chain_expect(g && g->locked, "unlock held granule");
	g->locked = false; chain_unlocks++;
}
struct granule *find_granule(unsigned long pa)
{
	for (unsigned int c = 0; c < OWNERS; c++)
		if (pa == CHAIN_RD_PA + c * 4096UL)
			return &chain_owners[c];
	if (pa < CHAIN_PA || pa >= CHAIN_PA + OWNERS * CHAIN_PAGES * 4096UL || !GRANULE_ALIGNED(pa))
		return NULL;
	unsigned long index = (pa - CHAIN_PA) / 4096UL;
	return &chain_data[index / CHAIN_PAGES][index % CHAIN_PAGES];
}
struct granule *find_lock_granule(unsigned long pa, enum granule_state state)
{
	struct granule *g = find_granule(pa);
	if (!g || g->state != state) return NULL;
	granule_lock(g, state); return g;
}
void atomic_granule_get(struct granule *g) { g->refs++; }
void atomic_granule_put(struct granule *g) { assert(g->refs); g->refs--; }
void *buffer_granule_map(struct granule *g, unsigned int slot)
{
	for (unsigned int c = 0; c < OWNERS; c++) {
		if (g == &chain_owners[c]) {
			assert(g->locked && slot == SLOT_RD && !chain_rd_map[c]);
			chain_rd_map[c] = true; return &chain_rd[c];
		}
		for (unsigned int t = 0; t < 3; t++) if (g == &chain_rtt[c][t]) {
			assert(g->locked && slot == SLOT_RTT && !chain_rtt_map[c][t]);
			chain_rtt_map[c][t] = true; return chain_entries[c][t];
		}
		for (unsigned int p = 0; p < CHAIN_PAGES; p++) if (g == &chain_data[c][p]) {
			unsigned int t = (unsigned int)((chain_ipa(p) >> 21U) - 1UL);
			assert((g->locked || chain_rtt[c][t].locked) && slot == SLOT_RSI_CALL && !chain_mapped[c][p]);
			chain_mapped[c][p] = true; return chain_cpu[c][p];
		}
	}
	assert(false); return NULL;
}
void buffer_unmap(void *memory)
{
	for (unsigned int c = 0; c < OWNERS; c++) {
		if (memory == &chain_rd[c]) { assert(chain_rd_map[c]); chain_rd_map[c] = false; return; }
		for (unsigned int t = 0; t < 3; t++) if (memory == chain_entries[c][t]) {
			assert(chain_rtt_map[c][t]); chain_rtt_map[c][t] = false; return;
		}
		for (unsigned int p = 0; p < CHAIN_PAGES; p++) if (memory == chain_cpu[c][p]) {
			assert(chain_mapped[c][p]); chain_mapped[c][p] = false;
			if (p == 0U && chain_mutate) {
				/* Mutation occurs after the actual private memcpy, before the
				 * dispatcher calls the BO core. No memcpy interposition. */
				memset(chain_cpu[c][p], 0xee, 4096);
				memset(chain_device[c][p], 0xee, 4096);
				chain_mutate = false;
			}
#ifdef GPU_RSI_TASK_CHAIN_TEST
			task_after_unmap(c, p);
#endif
			return;
		}
	}
	assert(false);
}
bool addr_in_par(const struct rd *rd, unsigned long ipa)
{ (void)rd; return ipa >= INPUT_IPA && ipa < ARENA_IPA + 513UL * 4096UL; }
static bool addr_in_rec_par(struct rec *rec, unsigned long ipa)
{ (void)rec; return addr_in_par(NULL, ipa); }
void s2tt_walk_lock_unlock(const struct s2tt_context *ctx, unsigned long ipa, int level, struct s2tt_walk *walk)
{
	assert(ctx->g_rtt->locked && level == 3);
	unsigned int t = (unsigned int)((ipa >> 21U) - 1UL);
	assert(t < 3U);
	struct granule *leaf = ctx->g_rtt + t;
	if (t != 0U) { granule_unlock(ctx->g_rtt); granule_lock(leaf, GRANULE_STATE_RTT); }
	*walk = (struct s2tt_walk){leaf, (ipa >> 12U) & 511UL, 3};
}
unsigned long s2tte_read(const unsigned long *e) { return *e; }
void s2tte_write(unsigned long *e, unsigned long v)
{
	/* A return to WB must never expose unsanitized donated data. NC
	 * handoff legitimately preserves input, so check WB and NC separately. */
	if ((*e & 4095UL) == 16UL && (v & 4095UL) == 0x3fUL) {
		struct granule *g = find_granule(v & ~4095UL);
		chain_expect(g != NULL, "restored WB backing exists");
		unsigned long index = (g->pa - CHAIN_PA) / 4096UL;
		for (unsigned int b = 0; b < 4096; b++)
			chain_expect(chain_device[index / CHAIN_PAGES][index % CHAIN_PAGES][b] == 0, "scrub published before restoring WB");
	}
	*e = v;
}
bool s2tte_is_assigned_ram(const struct s2tt_context *c, unsigned long e, long l)
{ (void)c; (void)l; return (e & 3UL) == 3UL; }
bool s2tte_is_assigned_empty(const struct s2tt_context *c, unsigned long e, long l)
{ (void)c; (void)l; return (e & 4095UL) == 16UL; }
bool s2tte_is_unassigned_ram(const struct s2tt_context *c, unsigned long e)
{ (void)c; return e == 32UL; }
static bool s2tte_is_assigned_destroyed(const struct s2tt_context *c, unsigned long e, long l)
{ (void)c; (void)l; return (e & 4095UL) == 64UL; }
static bool s2tte_is_unassigned_destroyed(const struct s2tt_context *c, unsigned long e)
{ (void)c; return e == 128UL; }
unsigned long s2tte_pa(const struct s2tt_context *c, unsigned long e, long l)
{ (void)c; (void)l; return e & ~4095UL; }
unsigned long s2tte_create_assigned_ram(const struct s2tt_context *c, unsigned long pa, long l)
{ (void)c; (void)l; return pa | 0x3fUL; }
unsigned long s2tte_create_assigned_empty(const struct s2tt_context *c, unsigned long pa, long l)
{ (void)c; (void)l; return pa | 16UL; }
unsigned long s2tte_create_unassigned_ram(const struct s2tt_context *c)
{ (void)c; return 32UL; }
void s2tt_invalidate_page(const struct s2tt_context *ctx, unsigned long ipa)
{ (void)ctx; assert(GRANULE_ALIGNED(ipa)); chain_tlbis++; }
bool xshm_memory_range_busy(const void *owner, unsigned long ipa, unsigned long size)
{ return chain_shared_busy && owner == &chain_owners[0] && ipa == DATA_IPA && size == 4096; }
bool opencca_iommu_range_busy(const void *owner, unsigned long ipa, unsigned long size)
{ return chain_iommu_busy && owner == &chain_owners[0] && ipa == DATA_IPA && size == 4096; }
static void chain_cache(uintptr_t address, size_t bytes, bool to_device)
{
	for (unsigned int c = 0; c < OWNERS; c++) for (unsigned int p = 0; p < CHAIN_PAGES; p++) {
		uintptr_t base = (uintptr_t)chain_cpu[c][p];
		if (address < base || address >= base + 4096UL) continue;
		size_t offset = address - base;
		assert(chain_mapped[c][p] && bytes <= 4096UL - offset);
#ifdef GPU_RSI_TASK_CHAIN_TEST
		task_before_cache(c, p, to_device);
#endif
		if (to_device) memcpy(chain_device[c][p] + offset, (void *)address, bytes);
		else memcpy((void *)address, chain_device[c][p] + offset, bytes);
		return;
	}
	assert(false);
}
static void inv_dcache_range(uintptr_t address, size_t bytes)
{ chain_invalidates++; chain_cache(address, bytes, false); }
static void clean_dcache_range(uintptr_t address, size_t bytes)
{ chain_cleans++; chain_cache(address, bytes, true); }
static void flush_dcache_range(uintptr_t address, size_t bytes)
{ chain_flushes++; chain_cache(address, bytes, true); }
static int opencca_gpu_mappings_lock;
static void spinlock_acquire(int *lock)
{ assert(chain_policy && !*lock); *lock = 1; }
static void spinlock_release(int *lock)
{ assert(*lock); *lock = 0; }
#include "chain-busy.inc"
#include "chain-translate.inc"
#include "chain-copy.inc"
#include "chain-memory.inc"
/* Actual memory/RTT callbacks; PT physical addressing/cleaning are host models.
 * The task-chain fixture additionally exercises modeled launch/completion. */
static const struct gpu_private_ops operations = {
	.source_page = source_page, .clear_page = clear_page,
	.write_page = write_page, .read_page = read_page,
	.sync_page_for_device = sync_page_for_device, .sync_page_for_cpu = sync_page_for_cpu,
	.cache_barrier = cache_barrier, .hide_page = gpu_control_rtt_hide,
	.restore_page = gpu_control_rtt_restore, .restore_page_uncached = gpu_private_rtt_restore_uncached,
	.table_pa = table_address, .clean = table_clean, .protected_mapping_summary = true
#ifdef GPU_RSI_TASK_CHAIN_TEST
	, .prepare_as = plat_opencca_gpu_pt_prepare, .extend_as = plat_opencca_gpu_pt_extend,
	.check_running_as = plat_opencca_gpu_pt_check_running,
	.detach_as = plat_opencca_gpu_pt_detach, .flush_as = plat_opencca_gpu_pt_flush_live
#endif
};
static const struct opencca_gpu_ops chain_device_ops;
bool opencca_gpu_isolate_service(const void *owner)
{ return opencca_gpu_service_isolate(&chain_device_ops, owner); }
static bool chain_revoke_mmio(const void *owner)
{ assert(owner == &chain_owners[2] && !opencca_gpu_mmio_allowed(owner)); return true; }
static const struct opencca_gpu_ops chain_device_ops = {
	.reset = plat_opencca_gpu_reset, .revoke_mmio = chain_revoke_mmio,
	.opp_valid = plat_opencca_gpu_opp_valid
};
#ifdef GPU_RSI_TASK_CHAIN_TEST
/* The production RMI dispatcher holds the policy gate. This model calls the
 * actual PM adapter inside that gate; it does not replace the dispatcher or
 * claim to cover its locking. RD state/REC reference counts remain models. */
#define RMI_SUCCESS 0UL
#define RMI_ERROR_INPUT 1UL
#define RSI_SUCCESS 0UL
#define RSI_ERROR_INPUT 1UL
struct smc_result { unsigned long x[8]; };
#define REALM_NEW 0U
#define REALM_ACTIVE 1U
#define REALM_SYSTEM_OFF 2U
static unsigned int chain_realm_state[OWNERS];
static unsigned int granule_refcount_read(struct granule *owner)
{
	chain_expect(owner->locked, "reclaim reads REC references under RD lock");
	return owner->refs;
}
static unsigned int get_rd_state_locked(struct rd *rd)
{
	for (unsigned int c = 0; c < OWNERS; c++)
		if (rd == &chain_rd[c]) {
			chain_expect(chain_owners[c].locked && chain_rd_map[c], "reclaim reads mapped and locked RD state");
			return chain_realm_state[c];
		}
	chain_expect(false, "reclaim RD belongs to known Realm");
	return REALM_NEW;
}
#define gpu_ops chain_device_ops
#include "chain-lifecycle.inc"
#undef gpu_ops
#endif
static unsigned int my_cpuid(void) { return 0U; }
void xshm_policy_lock(void) { assert(!chain_policy); chain_policy = true; chain_calls++; }
void xshm_policy_unlock(void) { assert(chain_policy); chain_policy = false; }
#ifdef GPU_RSI_TASK_CHAIN_TEST
static const struct gpu_firmware_ops chain_firmware_ops = {
	.digest = fw_digest, .address = fw_address, .clean = fw_clean, .invalidate = fw_cache,
	.install = plat_opencca_gpu_firmware_install, .boot = plat_opencca_gpu_firmware_boot,
	.configuration = plat_opencca_gpu_firmware_configuration,
	.notify = fw_notify, .clock = read_cntpct_el0
};
#define firmware_operations chain_firmware_ops
#else
#define firmware_operations fw_ops
#endif
#include "chain-dispatch.inc"
#undef firmware_operations

static void chain_balanced(void)
{
	chain_expect(!chain_policy && chain_locks == chain_unlocks, "balanced policy/granule locks");
	for (unsigned int c = 0; c < OWNERS; c++) {
		chain_expect(!chain_owners[c].locked && !chain_rd_map[c], "RD released");
		for (unsigned int t = 0; t < 3U; t++) chain_expect(!chain_rtt[c][t].locked && !chain_rtt_map[c][t], "RTT released");
		for (unsigned int p = 0; p < CHAIN_PAGES; p++) chain_expect(!chain_data[c][p].locked && !chain_mapped[c][p], "DATA released");
	}
}
static struct gpu_private_result chain_call(unsigned int owner, unsigned long op,
		unsigned long handle, unsigned long a, unsigned long b, unsigned long c,
		unsigned long d, unsigned long e)
{
	struct rec rec = {.realm_info = {&chain_owners[owner], chain_rd[owner].s2_ctx},
		.regs = {0, op, handle, a, b, c, d, e}};
	struct rsi_result res = {0};
	unsigned int before = chain_calls;
	handle_rsi_opencca_gpu_private(&rec, &res);
	chain_last_op = op; chain_last_owner = owner;
	chain_expect(chain_calls == before + 1U && res.action == UPDATE_REC_RETURN_TO_REALM, "RSI action and policy gate");
	chain_balanced(); chain_checks++;
	struct gpu_private_result r = {.status = res.smc_res.x[0]};
	for (unsigned int i = 0; i < 4U; i++) r.value[i] = res.smc_res.x[i + 1U];
	for (unsigned int i = 5; i < 8U; i++) chain_expect(!res.smc_res.x[i], "unused return registers zero");
	return r;
}
static void chain_success(struct gpu_private_result r)
{
	if (r.status != GPU_PRIVATE_SUCCESS)
		fprintf(stderr, "RSI request=%lu owner=%lu op=%lu status=%lu values=%lu,%lu,%lu,%lu\n",
			(unsigned long)chain_checks, chain_last_owner, chain_last_op, r.status,
			r.value[0], r.value[1], r.value[2], r.value[3]);
	chain_expect(r.status == GPU_PRIVATE_SUCCESS, "expected successful RSI request");
}
static void chain_denied(struct gpu_private_result r)
{ chain_expect(r.status != GPU_PRIVATE_SUCCESS, "hostile RSI request denied"); }
static unsigned long chain_open(unsigned int client, bool accept)
{
	unsigned long out[4];
	assert(xshm_endpoint_call(&chain_owners[2], XSHM_OFFER, xshm_endpoint_id(&chain_owners[client]), 0, out) == XSHM_SUCCESS);
	unsigned long channel = out[0];
	if (accept) assert(xshm_endpoint_call(&chain_owners[client], XSHM_ACCEPT, channel, 0, out) == XSHM_SUCCESS);
	return channel;
}
static void chain_setup(void)
{
	initialize();
	assert(opencca_gpu_control(&chain_device_ops, NULL, OPENCCA_GPU_POWER_ON, 0, 0));
	assert(opencca_gpu_mmio_grant(&chain_owners[2]) && opencca_gpu_claim(&chain_owners[2]));
	unsigned long out[4];
	for (unsigned int c = 0; c < OWNERS; c++) {
		chain_owners[c] = (struct granule){.state = GRANULE_STATE_RD};
#ifdef GPU_RSI_TASK_CHAIN_TEST
		chain_owners[c].refs = 1U; /* One existing REC, even if stopped. */
		chain_realm_state[c] = REALM_ACTIVE;
#endif
		chain_rd[c].s2_ctx.g_rtt = &chain_rtt[c][0];
		for (unsigned int t = 0; t < 3; t++) chain_rtt[c][t] = (struct granule){.state = GRANULE_STATE_RTT, .refs = CHAIN_PAGES};
		for (unsigned int p = 0; p < CHAIN_PAGES; p++) {
			chain_data[c][p] = (struct granule){.state = GRANULE_STATE_DATA,
				.pa = CHAIN_PA + (c * CHAIN_PAGES + p) * 4096UL};
			*chain_entry(c, p) = chain_data[c][p].pa | 0x3fUL;
		}
		memset(chain_cpu[c], 0xa0 + c, sizeof(chain_cpu[c]));
		memset(chain_device[c], 0x30 + c, sizeof(chain_device[c]));
		assert(xshm_endpoint_call(&chain_owners[c], XSHM_REGISTER, 0, 0, out) == XSHM_SUCCESS);
	}
	/* Legacy leases cannot be acquired after service isolation. Exercise the
	 * actual physical lease guard before isolation as a supplementary direct
	 * callback probe, not a private RSI request. */
	unsigned long pa = chain_data[0][1].pa, translated;
	assert(opencca_gpu_lease_acquire(&chain_owners[2], &pa, 1));
	xshm_policy_lock();
	chain_expect(!source_page(&chain_owners[0], DATA_IPA, &translated), "real legacy GPU lease denies source page");
	xshm_policy_unlock();
	opencca_gpu_lease_release(&chain_owners[2], &pa, 1);
	chain_balanced();
	chain_success(chain_call(2, GPU_PRIVATE_SERVICE_ISOLATE, 0, 0, 0, 0, 0, 0));
	chain_channels[0] = chain_open(0, true); chain_channels[1] = chain_open(1, true);
}
static unsigned long chain_bo(unsigned int c, unsigned int pages)
{
	struct gpu_private_result r = chain_call(c, GPU_PRIVATE_BO_CREATE, chain_channels[c], pages * 4096UL, GPU_PRIVATE_READ | GPU_PRIVATE_WRITE, 0, 0, 0);
	chain_success(r); return r.value[0];
}
static void chain_input(unsigned int c, unsigned long ipa, unsigned int count)
{
	unsigned long values[GPU_PRIVATE_BATCH];
	assert(count <= GPU_PRIVATE_BATCH);
	for (unsigned int p = 0; p < count; p++) values[p] = ipa + p * 4096UL;
	memcpy(chain_device[c][0], values, count * sizeof(values[0]));
	memset(chain_cpu[c][0], 0xe1, 4096); /* stale CPU snapshot */
}
static unsigned long chain_leaf(unsigned long root, unsigned long va)
{
	unsigned long address = root;
	for (unsigned int level = 0; level < 4U; level++) {
		chain_expect(address >= TABLE_BASE && address < TABLE_BASE + GPU_PRIVATE_TABLES * 4096UL, "PT walk remains in trusted table pool");
		const uint64_t *table = (const void *)(table_base + address - TABLE_BASE);
		uint64_t entry = table[(va >> (39U - level * 9U)) & 511UL];
		chain_expect((entry & 3UL) == 3UL, "hardware-format PT entry valid");
		address = entry & UINT64_C(0x000000fffffff000);
	}
	return address;
}
static void chain_registration(void)
{
	unsigned long bos[2] = {chain_bo(0, 2), chain_bo(1, 2)};
	for (unsigned int c = 0; c < 2; c++) {
		chain_input(c, DATA_IPA, 2); chain_mutate = true;
		chain_success(chain_call(c, GPU_PRIVATE_BO_APPEND, bos[c], INPUT_IPA, 2, 0, 0, 0));
		chain_expect(!chain_mutate && gpu_private_range_busy(&chain_owners[c], DATA_IPA, 8192), "snapshot survives guest mutation");
	}
	unsigned long duplicate = chain_bo(0, 1);
	chain_input(0, DATA_IPA, 1);
	chain_denied(chain_call(0, GPU_PRIVATE_BO_APPEND, duplicate, INPUT_IPA, 1, 0, 0, 0));
	chain_success(chain_call(0, GPU_PRIVATE_BO_DESTROY, duplicate, 0, 0, 0, 0, 0));
	unsigned long contexts[2];
	for (unsigned int c = 0; c < 2; c++) {
		struct gpu_private_result r = chain_call(c, GPU_PRIVATE_CONTEXT_CREATE, chain_channels[c], 0, 0, 0, 0, 0);
		chain_success(r); contexts[c] = r.value[0];
		/* Creation cleans the newly allocated root. Capture it in the
		 * trusted table callback; no guest API exports its address. */
		unsigned long root = latest_table_pa;
		r = chain_call(c, GPU_PRIVATE_MAP_AUTHORIZE, contexts[c], bos[c], 0, 0x800000UL, 2, GPU_PRIVATE_READ);
		chain_success(r); unsigned long grant = r.value[0];
		unsigned int before = chain_cleans;
		chain_denied(chain_call(2, GPU_PRIVATE_SERVICE_MAP, contexts[c], chain_channels[1U-c], grant, 0, 0x800000UL, (2UL << 8U) | GPU_PRIVATE_READ));
		chain_denied(chain_call(3, GPU_PRIVATE_SERVICE_MAP, contexts[c], chain_channels[c], grant, 0, 0x800000UL, (2UL << 8U) | GPU_PRIVATE_READ));
		chain_denied(chain_call(2, GPU_PRIVATE_SERVICE_MAP, contexts[c], chain_channels[c], grant, 0, 0x801000UL, (2UL << 8U) | GPU_PRIVATE_READ));
		chain_expect(chain_cleans == before, "denials never write data");
		chain_success(chain_call(2, GPU_PRIVATE_SERVICE_MAP, contexts[c], chain_channels[c], grant, 0, 0x800000UL, (2UL << 8U) | GPU_PRIVATE_READ));
		/* Independently walk actual hardware-format PTs, not QUERY counts. */
		for (unsigned int p = 0; p < 2; p++) {
			chain_expect(chain_leaf(root, 0x800000UL + p * 4096UL) == chain_data[c][p+1U].pa, "PT contains correct Client HPA");
		}
		chain_denied(chain_call(2, GPU_PRIVATE_SERVICE_MAP, contexts[c], chain_channels[c], grant, 0, 0x800000UL, (2UL << 8U) | GPU_PRIVATE_READ));
		chain_success(chain_call(c, GPU_PRIVATE_MAPPING_CHECK, contexts[c], bos[c], 0, 0x800000UL, 2, GPU_PRIVATE_READ));
		chain_denied(chain_call(1U-c, GPU_PRIVATE_QUERY, contexts[c], 0x800000UL, 0, 0, 0, 0));
		chain_denied(chain_call(2, GPU_PRIVATE_BO_RELEASE, bos[c], 0, 0, 0, 0, 0));
	}
	for (unsigned int c = 0; c < 2; c++) {
		chain_success(chain_call(2, GPU_PRIVATE_SERVICE_UNMAP, contexts[c], chain_channels[c], 0x800000UL, 2, 0, 0));
		chain_success(chain_call(c, GPU_PRIVATE_CONTEXT_DESTROY, contexts[c], 0, 0, 0, 0, 0));
		chain_success(chain_call(c, GPU_PRIVATE_BO_DESTROY, bos[c], 0, 0, 0, 0, 0));
	}
}
static void chain_busy_and_channels(void)
{
	unsigned long bo = chain_bo(0, 1), pa = chain_data[0][1].pa;
	chain_input(0, DATA_IPA, 1);
	for (unsigned int which = 0; which < 3; which++) {
		chain_shared_busy = which == 0; chain_iommu_busy = which == 1;
		if (which == 2) assert(opencca_dma_map_acquire(77, 0x900000, pa, 4096));
		chain_denied(chain_call(0, GPU_PRIVATE_BO_APPEND, bo, INPUT_IPA, 1, 0, 0, 0));
		chain_expect(!gpu_private_range_busy(&chain_owners[0], DATA_IPA, 4096), "busy denial does not register page");
		if (which == 2) assert(opencca_dma_map_release(77, 0x900000, 4096));
	}
	chain_shared_busy = chain_iommu_busy = false;
	chain_denied(chain_call(1, GPU_PRIVATE_BO_APPEND, bo, INPUT_IPA, 1, 0, 0, 0));
	chain_denied(chain_call(0, GPU_PRIVATE_BO_APPEND, bo, INPUT_IPA + 1, 1, 0, 0, 0));
	chain_success(chain_call(0, GPU_PRIVATE_BO_APPEND, bo, INPUT_IPA, 1, 0, 0, 0));
	chain_success(chain_call(0, GPU_PRIVATE_BO_DESTROY, bo, 0, 0, 0, 0, 0));
	unsigned long channel = chain_open(0, false), out[4];
	chain_denied(chain_call(0, GPU_PRIVATE_BO_CREATE, channel, 4096, GPU_PRIVATE_READ, 0, 0, 0));
	assert(xshm_endpoint_call(&chain_owners[0], XSHM_ACCEPT, channel, 0, out) == XSHM_SUCCESS);
	struct gpu_private_result r = chain_call(0, GPU_PRIVATE_BO_CREATE, channel, 4096, GPU_PRIVATE_READ, 0, 0, 0);
	chain_success(r); chain_success(chain_call(0, GPU_PRIVATE_BO_DESTROY, r.value[0], 0, 0, 0, 0, 0));
	assert(xshm_endpoint_call(&chain_owners[0], XSHM_CLOSE, channel, 0, out) == XSHM_SUCCESS);
	chain_denied(chain_call(0, GPU_PRIVATE_BO_CREATE, channel, 4096, GPU_PRIVATE_READ, 0, 0, 0));
}
static void chain_handoff(void)
{
	for (unsigned int nc = 0; nc < 2; nc++) {
		unsigned long bo = chain_bo(0, 2);
		chain_input(0, DATA_IPA, 2);
		chain_success(chain_call(0, GPU_PRIVATE_BO_APPEND, bo, INPUT_IPA, 2, 0, 0, 0));
		for (unsigned int p = 1; p < 3; p++) memset(chain_cpu[0][p], 0x72, 4096);
		unsigned int before = chain_flushes;
		chain_success(chain_call(0, nc ? GPU_PRIVATE_BO_UNCACHED : GPU_PRIVATE_BO_SEAL, bo, 0, 0, 0, 0, 0));
		chain_expect(chain_flushes == before + 2U, "handoff flushes each real backing page");
		for (unsigned int p = 1; p < 3; p++) {
			unsigned long entry = *chain_entry(0,p);
			chain_expect(nc ? (entry & 0x3fUL) == 0x17UL : (entry & 4095UL) == 16UL, "hidden or forced NC CPU leaf");
			chain_expect(chain_device[0][p][0] == 0x72 && chain_device[1][p][0] == 0x31, "handoff reaches only owner device memory");
		}
		chain_success(chain_call(0, GPU_PRIVATE_BO_RELEASE, bo, 0, 0, 0, 0, 0));
		for (unsigned int p = 1; p < 3; p++) {
			chain_expect((*chain_entry(0,p) & 4095UL) == 0x3fUL, "WB CPU access restored");
			for (unsigned int b = 0; b < 4096; b++) chain_expect(chain_device[0][p][b] == 0, "all bytes scrubbed before restore");
		}
	}
}
static void chain_control(void)
{
	struct gpu_private_result r = chain_call(2, GPU_PRIVATE_CONTROL_CREATE, 0, 513UL * 4096UL, 0, 0, 0, 0);
	chain_success(r); unsigned long control = r.value[0];
	for (unsigned int p = 0; p < 513; p += GPU_PRIVATE_BATCH) {
		unsigned int count = p == 0 ? GPU_PRIVATE_BATCH : 1U;
		chain_input(2, ARENA_IPA + p * 4096UL, count);
		chain_success(chain_call(2, GPU_PRIVATE_CONTROL_APPEND, control, INPUT_IPA, count, p * 4096UL, 0, 0));
	}
	for (unsigned int p = 9; p < CHAIN_PAGES; p++) {
		chain_expect((*chain_entry(2,p) & 4095UL) == 16UL, "donated control CPU leaf hidden");
		for (unsigned int b = 0; b < 4096; b++) chain_expect(chain_device[2][p][b] == 0, "donated control scrubbed");
	}
	/* Trusted firmware consumers resolve PA only from this donated object.
	 * These helper calls are supplemental, never an arbitrary-PA guest RSI. */
	unsigned int pages;
	xshm_policy_lock();
	chain_expect(gpu_private_control_acquire(&operations, &chain_owners[2], control, &pages) && pages == 513U,
		"trusted consumer acquires exact donated object");
	for (unsigned int index = 0; index < 513; index += 512) {
		unsigned long pa;
		chain_expect(!gpu_private_control_page(&chain_owners[0], control, index, &pa), "other Client cannot resolve control backing");
		chain_expect(gpu_private_control_page(&chain_owners[2], control, index, &pa) && pa == chain_data[2][index+9U].pa,
			"trusted control lookup selects service backing");
		unsigned char input[64], output[66];
		memset(input, 0x7c, sizeof(input)); memset(output, 0xd7, sizeof(output));
		chain_expect(write_page(pa, 4032, input, sizeof(input)) && chain_device[2][index+9U][4032] == 0x7c,
			"trusted control write reaches device bytes");
		memset(chain_device[2][index+9U] + 4032, 0x5a, 64);
		chain_expect(read_page(pa, 4032, output+1, 64), "trusted control read succeeds");
		for (unsigned int b = 0; b < 66; b++) chain_expect(output[b] == (b == 0 || b == 65 ? 0xd7 : 0x5a), "fresh read and output redzones");
		memset(chain_cpu[2][index+9U], 0xe3, 4096);
		chain_expect(sync_page_for_cpu(pa) && chain_device[2][index+9U][4032] == 0x5a && chain_cpu[2][index+9U][4032] == 0x5a,
			"CPU return never overwrites device result");
	}
	gpu_private_control_release(&chain_owners[2], control);
	xshm_policy_unlock(); chain_balanced();
	chain_denied(chain_call(0, GPU_PRIVATE_CONTROL_DESTROY, control, 0, 0, 0, 0, 0));
	r = chain_call(2, GPU_PRIVATE_CONTROL_DESTROY, control, 0, 0, 0, 0, 0);
	chain_expect(r.status == GPU_PRIVATE_INCOMPLETE && r.value[0] == 1, "bounded destroy retains one page at 512 boundary");
	chain_expect((*chain_entry(2,9) & 4095UL) == 16UL && (*chain_entry(2,10) & 4095UL) == 0x3fUL, "only remaining prefix stays hidden");
	chain_success(chain_call(2, GPU_PRIVATE_CONTROL_DESTROY, control, 0, 0, 0, 0, 0));
	for (unsigned int p = 9; p < CHAIN_PAGES; p++) chain_expect((*chain_entry(2,p) & 4095UL) == 0x3fUL, "all control CPU leaves restored");
	chain_denied(chain_call(2, GPU_PRIVATE_CONTROL_DESTROY, control, 0, 0, 0, 0, 0));
}
#ifndef GPU_RSI_TASK_CHAIN_TEST
int main(void)
{
	chain_setup(); chain_registration(); chain_busy_and_channels(); chain_handoff(); chain_control(); chain_balanced();
	chain_expect(!opencca_gpu_lease_active() && !opencca_dma_map_active(), "all physical reservations retired");
	printf("GPU_RSI_MEMORY_CHAIN=PASS rsi_requests=%u invalidates=%u cleans=%u flushes=%u tlbis=%u MODEL_ONLY no launch/GPC/concurrency\n",
		chain_checks, chain_invalidates, chain_cleans, chain_flushes, chain_tlbis);
}
#endif
