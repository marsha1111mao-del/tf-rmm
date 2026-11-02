/* SPDX-License-Identifier: BSD-3-Clause */
/* Actual RSI copy/IPA translation and endpoint policy; synthetic REC, S2
 * descriptors, locks, slots and noncoherent memory. No physical GPC claim. */
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xshm_endpoint.h>

#define GRANULE_SIZE 4096UL
#define GRANULE_ALIGNED(v) (((v) & (GRANULE_SIZE - 1UL)) == 0UL)
#define GRANULE_STATE_RTT 1U
#define SLOT_RTT 2U
#define SLOT_RSI_CALL 3U
#define S2TT_PAGE_LEVEL 3
#define UPDATE_REC_RETURN_TO_REALM 1U
#define STAGE_2_TRANSLATION_FAULT 6U
#define INPUT_IPA 0x201000UL
#define ENTRY_MASK 7UL

enum ripas { RIPAS_EMPTY, RIPAS_RAM, RIPAS_DESTROYED };
enum s2_walk_status { WALK_SUCCESS, WALK_INVALID_PARAMS, WALK_FAIL };
enum entry_kind { ASSIGNED_RAM = 1, UNASSIGNED_RAM, ASSIGNED_EMPTY,
	UNASSIGNED_EMPTY, ASSIGNED_DESTROYED, UNASSIGNED_DESTROYED };
struct granule { unsigned int client; bool table, locked, mapped; };
struct s2tt_context { struct granule *g_rtt; unsigned int ipa_bits; };
struct rec { struct { const void *g_rd; struct s2tt_context s2_ctx; } realm_info; };
struct s2tt_walk { struct granule *g_llt; unsigned long index; int last_level; };
struct s2_walk_result {
	unsigned long pa, rtt_level;
	enum ripas ripas_val;
	struct granule *llt;
};
struct rsi_result { unsigned int action; unsigned long rtt_level; };
static unsigned char owners[4];
static struct granule tables[2], pages[2];
static struct rec records[2];
static unsigned long entries[2], expected_pa[2], requested_ipa;
static unsigned char device[2][GRANULE_SIZE], cpu[2][GRANULE_SIZE];
static unsigned char output[GRANULE_SIZE + 2U], saved[sizeof(output)];
static unsigned int locks, walks, maps, invalidations, copies, unlocks;
static unsigned int mapped_client;
static int last_level;
static size_t requested_bytes;
static bool active_copy;

static bool addr_in_rec_par(struct rec *rec, unsigned long ipa)
{
	return ipa < ((1UL << rec->realm_info.s2_ctx.ipa_bits) >> 1U);
}
static unsigned long s2tte_map_size(int level)
{
	assert(level >= 0 && level <= 3);
	return 1UL << (12U + 9U * (3U - (unsigned int)level));
}
static void granule_lock(struct granule *g, unsigned int state)
{
	assert(g->table && state == GRANULE_STATE_RTT && !g->locked && !g->mapped);
	g->locked = true;
	locks++;
}
static void granule_unlock(struct granule *g)
{
	assert(g->table && g->locked && !pages[g->client].mapped);
	g->locked = false;
	unlocks++;
}
static void s2tt_walk_lock_unlock(struct s2tt_context *ctx, unsigned long ipa,
		int level, struct s2tt_walk *walk)
{
	assert(ctx->g_rtt->locked && level == S2TT_PAGE_LEVEL && ipa == requested_ipa);
	*walk = (struct s2tt_walk){ ctx->g_rtt, 0UL, last_level };
	walks++;
}
static void *buffer_granule_map(struct granule *g, unsigned int slot)
{
	assert(!g->mapped && tables[g->client].locked);
	g->mapped = true;
	maps++;
	if (g->table) {
		assert(slot == SLOT_RTT);
		return &entries[g->client];
	}
	assert(slot == SLOT_RSI_CALL && !tables[g->client].mapped);
	mapped_client = g->client;
	return cpu[g->client];
}
static void buffer_unmap(void *address)
{
	for (unsigned int c = 0U; c < 2U; c++) {
		struct granule *g = address == &entries[c] ? &tables[c] :
			address == cpu[c] ? &pages[c] : NULL;
		if (g == NULL) continue;
		assert(g->mapped && (g->table || tables[c].locked));
		if (!g->table && active_copy) assert(copies == 1U);
		g->mapped = false;
		return;
	}
	assert(false);
}
static unsigned long s2tte_read(const unsigned long *entry) { return *entry; }
static bool s2tte_is_assigned_ram(struct s2tt_context *ctx, unsigned long e, int level)
{ (void)ctx; (void)level; return (e & ENTRY_MASK) == ASSIGNED_RAM; }
static bool s2tte_is_assigned_destroyed(struct s2tt_context *ctx, unsigned long e, int level)
{ (void)ctx; (void)level; return (e & ENTRY_MASK) == ASSIGNED_DESTROYED; }
static bool s2tte_is_unassigned_destroyed(struct s2tt_context *ctx, unsigned long e)
{ (void)ctx; return (e & ENTRY_MASK) == UNASSIGNED_DESTROYED; }
static bool s2tte_is_unassigned_ram(struct s2tt_context *ctx, unsigned long e)
{ (void)ctx; return (e & ENTRY_MASK) == UNASSIGNED_RAM; }
static unsigned long s2tte_pa(struct s2tt_context *ctx, unsigned long e, int level)
{ (void)ctx; (void)level; return e & ~ENTRY_MASK; }
static struct granule *find_granule(unsigned long pa)
{
	for (unsigned int c = 0U; c < 2U; c++)
		if (pa == expected_pa[c]) return &pages[c];
	assert(false); /* Includes a missing block-offset adjustment. */
	return NULL;
}
static void inv_dcache_range(uintptr_t address, size_t bytes)
{
	unsigned int c = mapped_client;
	assert(pages[c].mapped && tables[c].locked && copies == 0U);
	assert(address == (uintptr_t)cpu[c] && bytes == requested_bytes);
	memcpy(cpu[c], device[c], bytes);
	invalidations++;
}
static void *snapshot_copy(void *dst, const void *src, size_t bytes)
{
	assert(dst == output + 1U && src == cpu[mapped_client]);
	assert(bytes == requested_bytes && invalidations == 1U && copies == 0U);
	assert(pages[mapped_client].mapped && tables[mapped_client].locked);
	copies++;
	return memcpy(dst, src, bytes);
}

#include "input-translate.inc"
#define memcpy snapshot_copy
#include "input-copy.inc"
#undef memcpy

static void reset_input(unsigned long ipa, size_t bytes, enum entry_kind kind, int level)
{
	assert(!tables[0].locked && !tables[1].locked &&
		!pages[0].mapped && !pages[1].mapped);
	locks = walks = maps = invalidations = copies = unlocks = 0U;
	requested_ipa = ipa;
	requested_bytes = bytes;
	last_level = level;
	active_copy = true;
	memset(output, 0x5a, sizeof(output));
	memcpy(saved, output, sizeof(saved));
	for (unsigned int c = 0U; c < 2U; c++) {
		unsigned long base = (c + 1UL) << 39U;
		tables[c] = (struct granule){ .client = c, .table = true };
		pages[c] = (struct granule){ .client = c };
		records[c].realm_info.g_rd = &owners[c];
		records[c].realm_info.s2_ctx = (struct s2tt_context){ &tables[c], 24U };
		entries[c] = base | kind;
		expected_pa[c] = base + (ipa & (s2tte_map_size(level) - 1UL));
		memset(cpu[c], 0xa5, GRANULE_SIZE);
		for (size_t i = 0U; i < GRANULE_SIZE; i++)
			device[c][i] = (unsigned char)(i * 17U + bytes + c * 53U);
	}
}
static void test_copy(void)
{
	unsigned int cases = 0U;
	/* Every legal byte count, two different private pages at the same IPA. */
	for (size_t bytes = 1U; bytes <= GRANULE_SIZE; bytes++) {
		for (unsigned int client = 0U; client < 2U; client++) {
			reset_input(INPUT_IPA, bytes, ASSIGNED_RAM, 3);
			struct rsi_result res = { UPDATE_REC_RETURN_TO_REALM, ULONG_MAX };
			assert(copy_page_input(&records[client], INPUT_IPA, bytes, output + 1U, &res));
			assert(res.action == UPDATE_REC_RETURN_TO_REALM && res.rtt_level == ULONG_MAX);
			assert(locks == 1U && walks == 1U && maps == 2U &&
				invalidations == 1U && copies == 1U && unlocks == 1U);
			assert(!tables[client].locked && !pages[client].mapped);
			assert(memcmp(output + 1U, device[client], bytes) == 0);
			assert(output[0] == 0x5a);
			for (size_t i = bytes + 1U; i < sizeof(output); i++) assert(output[i] == 0x5a);
			memcpy(saved, output, sizeof(saved));
			memset(device[client], 0xee, GRANULE_SIZE);
			memset(cpu[client], 0xee, GRANULE_SIZE);
			assert(memcmp(saved, output, sizeof(saved)) == 0); /* Private snapshot. */
			cases++;
		}
	}
	/* Actual translation helper, including block offsets and failure unlocks. */
	for (int level = 0; level <= 3; level++) {
		for (unsigned int kind = ASSIGNED_RAM; kind <= UNASSIGNED_DESTROYED; kind++) {
			reset_input(INPUT_IPA, 64U, (enum entry_kind)kind, level);
			struct rsi_result res = { UPDATE_REC_RETURN_TO_REALM, ULONG_MAX };
			bool success = copy_page_input(&records[1], INPUT_IPA, 64U, output + 1U, &res);
			bool fault = kind == UNASSIGNED_RAM || kind == ASSIGNED_DESTROYED || kind == UNASSIGNED_DESTROYED;
			assert(success == (kind == ASSIGNED_RAM));
			assert(res.action == (fault ? STAGE_2_TRANSLATION_FAULT : UPDATE_REC_RETURN_TO_REALM));
			assert(res.rtt_level == (fault ? (unsigned long)level : ULONG_MAX));
			assert(locks == 1U && walks == 1U && unlocks == 1U && !tables[1].locked);
			if (!success) assert(maps == 1U && invalidations == 0U && copies == 0U && memcmp(output, saved, sizeof(output)) == 0);
			cases++;
		}
	}
	const struct { unsigned long ipa; size_t bytes; } bad[] = {
		{INPUT_IPA, 0U}, {INPUT_IPA, GRANULE_SIZE + 1U}, {INPUT_IPA, SIZE_MAX},
		{INPUT_IPA + 1UL, 64U}, {1UL << 23U, 64U}, {ULONG_MAX, 64U},
	};
	for (size_t i = 0U; i < sizeof(bad) / sizeof(bad[0]); i++) {
		reset_input(bad[i].ipa, bad[i].bytes, ASSIGNED_RAM, 3);
		struct rsi_result res = { UPDATE_REC_RETURN_TO_REALM, ULONG_MAX };
		assert(!copy_page_input(&records[0], bad[i].ipa, bad[i].bytes, output + 1U, &res));
		assert(res.action == UPDATE_REC_RETURN_TO_REALM && res.rtt_level == ULONG_MAX);
		assert(locks == 0U && walks == 0U && maps == 0U && invalidations == 0U && copies == 0U && unlocks == 0U);
		assert(memcmp(output, saved, sizeof(output)) == 0);
		cases++;
	}
	puts("GPU_INPUT_COPY=PASS actual copy_page_input/realm_ipa_to_pa, two REC roots, cache-before-copy, private snapshot, bounded copy, block offsets and RIPAS fault/unlock; MODEL_ONLY");
	printf("GPU_INPUT_COPY_CASES=%u\n", cases);
}
static unsigned long endpoint_call(unsigned int client, unsigned long op, unsigned long id)
{
	unsigned long result[4];
	assert(xshm_endpoint_call(&owners[client], op, id, 0UL, result) == XSHM_SUCCESS);
	return op == XSHM_REGISTER ? result[1] : result[0];
}
static void expect_peer(const void *owner, unsigned long channel, const void *expected, unsigned long id)
{
	unsigned long peer_id = ULONG_MAX;
	assert(xshm_endpoint_peer(owner, channel, &peer_id) == expected);
	assert(peer_id == id);
}
static void test_peer(void)
{
	unsigned int cycles = 96U;
	for (unsigned int cycle = 0U; cycle < cycles; cycle++) {
		unsigned long ids[3], channels[2];
		for (unsigned int c = 0U; c < 3U; c++) ids[c] = endpoint_call(c, XSHM_REGISTER, 0UL);
		for (unsigned int c = 0U; c < 2U; c++) {
			channels[c] = endpoint_call(c, XSHM_OFFER, ids[2]);
			expect_peer(&owners[c], channels[c], NULL, 0UL); /* Not accepted. */
			expect_peer(&owners[2], channels[c], NULL, 0UL);
			endpoint_call(2U, XSHM_ACCEPT, channels[c]);
			expect_peer(&owners[c], channels[c], &owners[2], ids[2]);
			expect_peer(&owners[2], channels[c], &owners[c], ids[c]);
			expect_peer(&owners[c ^ 1U], channels[c], NULL, 0UL);
			expect_peer(&owners[3], channels[c], NULL, 0UL);
			expect_peer(NULL, channels[c], NULL, 0UL);
		}
		expect_peer(&owners[2], 0UL, NULL, 0UL);
		expect_peer(&owners[2], ULONG_MAX, NULL, 0UL);
		endpoint_call(0U, XSHM_CLOSE, channels[0]);
		expect_peer(&owners[0], channels[0], NULL, 0UL);
		expect_peer(&owners[2], channels[0], NULL, 0UL);
		/* Reuse table slots and owner storage, never old IDs/channels. */
		xshm_endpoint_release(&owners[1]);
		unsigned long replacement = endpoint_call(1U, XSHM_REGISTER, 0UL);
		assert(replacement != ids[1]);
		expect_peer(&owners[1], channels[1], NULL, 0UL);
		expect_peer(&owners[2], channels[1], NULL, 0UL);
		unsigned long channel = endpoint_call(1U, XSHM_OFFER, ids[2]);
		assert(channel != channels[1] && channel != channels[0]);
		endpoint_call(2U, XSHM_ACCEPT, channel);
		expect_peer(&owners[2], channel, &owners[1], replacement);
		for (unsigned int c = 0U; c < 3U; c++) xshm_endpoint_release(&owners[c]);
		expect_peer(&owners[2], channel, NULL, 0UL);
	}
	printf("GPU_INPUT_PEER=PASS cycles=%u actual endpoint policy, live membership, instance replacement and stale-channel rejection; MODEL_ONLY\n", cycles);
}
int main(int argc, char **argv)
{
	assert(argc == 2);
	if (strcmp(argv[1], "copy") == 0) test_copy();
	else { assert(strcmp(argv[1], "peer") == 0); test_peer(); }
	return 0;
}
