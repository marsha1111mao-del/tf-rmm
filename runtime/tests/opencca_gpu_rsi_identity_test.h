/* SPDX-License-Identifier: BSD-3-Clause */
/* Low-level host model for a dispatcher using the actual copy, IPA translation
 * and complete endpoint core. REC/S2 layout, locks, slots and caches are models.
 * The GPU cores, dispatcher and helper bodies are not replaced. */
#include <limits.h>
#include <xshm_endpoint.h>

#define GRANULE_SIZE 4096UL
#define GRANULE_ALIGNED(v) (((v) & (GRANULE_SIZE - 1UL)) == 0UL)
#define GRANULE_STATE_RTT 1U
#define SLOT_RTT 2U
#define SLOT_RSI_CALL 3U
#define S2TT_PAGE_LEVEL 3
#define STAGE_2_TRANSLATION_FAULT 6U
#define IDENTITY_IPA 0x201000UL
#define IDENTITY_ENTRY_MASK 7UL
enum ripas { RIPAS_EMPTY, RIPAS_RAM, RIPAS_DESTROYED };
enum s2_walk_status { WALK_SUCCESS, WALK_INVALID_PARAMS, WALK_FAIL };
enum identity_entry_kind { IDENTITY_RAM = 1, IDENTITY_UNASSIGNED_RAM,
	IDENTITY_EMPTY, IDENTITY_DESTROYED, IDENTITY_UNASSIGNED_DESTROYED };
struct granule { unsigned int client; bool table, locked, mapped; };
struct s2tt_context { struct granule *g_rtt; unsigned int ipa_bits; };
struct rec {
	struct { const void *g_rd; struct s2tt_context s2_ctx; } realm_info;
	unsigned long regs[8];
};
struct rsi_result {
	unsigned int action;
	unsigned long rtt_level;
	struct { unsigned long x[8]; } smc_res;
};
struct s2tt_walk { struct granule *g_llt; unsigned long index; int last_level; };
struct s2_walk_result {
	unsigned long pa, rtt_level;
	enum ripas ripas_val;
	struct granule *llt;
};
static struct granule identity_tables[4], identity_pages[4];
static struct s2tt_context identity_contexts[4];
static unsigned long identity_entries[4], domain_channels[2];
static unsigned char identity_device[4][GRANULE_SIZE], identity_cpu[4][GRANULE_SIZE];
static unsigned int identity_locks, identity_unlocks, identity_walks, identity_maps;
static unsigned int identity_invalidations, identity_copies, identity_mapped;
static unsigned int identity_last_action;
static unsigned long identity_last_level;
static bool identity_ready, identity_mutate_source;
static unsigned int identity_index(const void *owner)
{
	if (owner == &client_a) return 0U;
	if (owner == &client_b) return 1U;
	if (owner == &service) return 2U;
	assert(owner == &stranger);
	return 3U;
}
static unsigned long identity_open(const void *owner, bool accept)
{
	unsigned long output[4];
	assert(xshm_endpoint_call(&service, XSHM_OFFER, xshm_endpoint_id(owner), 0, output) == XSHM_SUCCESS);
	unsigned long channel = output[0];
	if (accept) assert(xshm_endpoint_call(owner, XSHM_ACCEPT, channel, 0, output) == XSHM_SUCCESS);
	return channel;
}
static void domain_identity_setup(void)
{
	if (identity_ready) return;
	const void *owners[] = { &client_a, &client_b, &service, &stranger };
	unsigned long output[4];
	for (unsigned int i = 0; i < 4U; i++) {
		assert(xshm_endpoint_call(owners[i], XSHM_REGISTER, 0, 0, output) == XSHM_SUCCESS);
		identity_tables[i] = (struct granule){ .client = i, .table = true };
		identity_pages[i] = (struct granule){ .client = i };
		identity_contexts[i] = (struct s2tt_context){ &identity_tables[i], 24U };
	}
	domain_channels[0] = identity_open(&client_a, true);
	domain_channels[1] = identity_open(&client_b, true);
	identity_ready = true;
}
static void domain_identity_disconnect(const void *owner)
{
	unsigned long output[4];
	assert(xshm_endpoint_call(owner, XSHM_CLOSE, domain_channels[identity_index(owner)], 0, output) == XSHM_SUCCESS);
}
static void domain_identity_reconnect(const void *owner)
{
	domain_channels[identity_index(owner)] = identity_open(owner, true);
}
static void identity_reset(void)
{
	identity_locks = identity_unlocks = identity_walks = identity_maps = 0U;
	identity_invalidations = identity_copies = 0U;
	identity_mutate_source = false;
	for (unsigned int i = 0; i < 4U; i++) {
		assert(!identity_tables[i].locked && !identity_tables[i].mapped && !identity_pages[i].mapped);
		identity_entries[i] = ((i + 1UL) << 32U) | IDENTITY_RAM;
		memset(identity_device[i], 0x21 + i, GRANULE_SIZE);
		memset(identity_cpu[i], 0xb0 + i, GRANULE_SIZE);
	}
}
static bool addr_in_rec_par(struct rec *rec, unsigned long ipa)
{ return ipa < ((1UL << rec->realm_info.s2_ctx.ipa_bits) >> 1U); }
static unsigned long s2tte_map_size(int level)
{ assert(level == S2TT_PAGE_LEVEL); return GRANULE_SIZE; }
static void granule_lock(struct granule *g, unsigned int state)
{
	assert(domain_policy_locked && g->table && state == GRANULE_STATE_RTT && !g->locked);
	g->locked = true;
	identity_locks++;
}
static void granule_unlock(struct granule *g)
{
	assert(g->table && g->locked && !identity_pages[g->client].mapped);
	g->locked = false;
	identity_unlocks++;
}
static void s2tt_walk_lock_unlock(struct s2tt_context *ctx, unsigned long ipa,
		int level, struct s2tt_walk *walk)
{
	assert(ctx->g_rtt->locked && level == S2TT_PAGE_LEVEL);
	*walk = (struct s2tt_walk){ ctx->g_rtt, 0, S2TT_PAGE_LEVEL };
	/* A missing guest mapping is represented by an assigned-empty entry. */
	if (ipa != IDENTITY_IPA) identity_entries[ctx->g_rtt->client] = IDENTITY_EMPTY;
	identity_walks++;
}
static void *buffer_granule_map(struct granule *g, unsigned int slot)
{
	assert(!g->mapped && identity_tables[g->client].locked);
	g->mapped = true;
	identity_maps++;
	if (g->table) {
		assert(slot == SLOT_RTT);
		return &identity_entries[g->client];
	}
	assert(slot == SLOT_RSI_CALL && !identity_tables[g->client].mapped);
	identity_mapped = g->client;
	return identity_cpu[g->client];
}
static void buffer_unmap(void *memory)
{
	for (unsigned int i = 0; i < 4U; i++) {
		struct granule *g = memory == &identity_entries[i] ? &identity_tables[i] :
			memory == identity_cpu[i] ? &identity_pages[i] : NULL;
		if (g == NULL) continue;
		/* realm_ipa_to_pa unlocks an unsuccessful RTT walk before unmapping
		 * its table slot. A successful data-page copy retains the RTT lock. */
		assert(g->mapped && (g->table || identity_tables[i].locked));
		if (!g->table) assert(identity_copies == 1U);
		g->mapped = false;
		return;
	}
	assert(false);
}
static unsigned long s2tte_read(const unsigned long *e) { return *e; }
static bool s2tte_is_assigned_ram(struct s2tt_context *c, unsigned long e, int l)
{ (void)c; (void)l; return (e & IDENTITY_ENTRY_MASK) == IDENTITY_RAM; }
static bool s2tte_is_assigned_destroyed(struct s2tt_context *c, unsigned long e, int l)
{ (void)c; (void)l; return (e & IDENTITY_ENTRY_MASK) == IDENTITY_DESTROYED; }
static bool s2tte_is_unassigned_destroyed(struct s2tt_context *c, unsigned long e)
{ (void)c; return (e & IDENTITY_ENTRY_MASK) == IDENTITY_UNASSIGNED_DESTROYED; }
static bool s2tte_is_unassigned_ram(struct s2tt_context *c, unsigned long e)
{ (void)c; return (e & IDENTITY_ENTRY_MASK) == IDENTITY_UNASSIGNED_RAM; }
static unsigned long s2tte_pa(struct s2tt_context *c, unsigned long e, int l)
{ (void)c; (void)l; return e & ~IDENTITY_ENTRY_MASK; }
static struct granule *find_granule(unsigned long pa)
{
	for (unsigned int i = 0; i < 4U; i++)
		if (pa == ((i + 1UL) << 32U)) return &identity_pages[i];
	assert(false);
	return NULL;
}
static void inv_dcache_range(uintptr_t address, size_t bytes)
{
	unsigned int i = identity_mapped;
	assert(identity_pages[i].mapped && identity_tables[i].locked);
	assert(address == (uintptr_t)identity_cpu[i] && bytes <= GRANULE_SIZE);
	assert(identity_copies == 0U && identity_invalidations == 0U);
	memcpy(identity_cpu[i], identity_device[i], bytes);
	identity_invalidations++;
}
static void *identity_snapshot_copy(void *dst, const void *src, size_t bytes)
{
	assert(src == identity_cpu[identity_mapped] && bytes <= GRANULE_SIZE);
	assert(identity_invalidations == 1U && identity_copies == 0U);
	identity_copies++;
	memcpy(dst, src, bytes);
	/* The guest source changes after the snapshot. Later validation must only
	 * consume the private copy, even if the guest page becomes different. */
	if (identity_mutate_source) {
		memset(identity_cpu[identity_mapped], 0xee, bytes);
		memset(identity_device[identity_mapped], 0xee, bytes);
	}
	return dst;
}
#include "identity-translate.inc"
#define memcpy identity_snapshot_copy
#include "identity-copy.inc"
#undef memcpy
