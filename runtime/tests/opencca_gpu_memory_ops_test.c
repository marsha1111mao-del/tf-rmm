/* SPDX-License-Identifier: BSD-3-Clause */
/* Actual private RSI memory callbacks plus private core/xshm_rtt. Low-level
 * RD/RTT/granules, external busy probes and cache effects remain host models. */
#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <opencca_gpu_private.h>
#include <xshm_runtime.h>
#include "rtt-stubs/control_rtt_model.h"

#define SLOT_RSI_CALL 3U
#define IPA 0x400000UL
#define PA 0x60000000UL
#define PAGES 4U
static unsigned long entries[2][512];
static unsigned char cpu[2][PAGES][4096], device[2][PAGES][4096];
static struct granule owners[2], rtts[2], data[2][PAGES];
static struct rd realms[2];
static bool mapped[2][PAGES], rd_mapped[2], rtt_mapped[2];
static unsigned int maps, locks, unlocks, walks, checks, source_checks;
static bool shared_busy, iommu_busy, physical_busy;
static unsigned int selected;
static char events[32];
static unsigned int event_count;
static void expect(bool value, const char *reason)
{
	if (!value) {
		fprintf(stderr, "GPU_MEMORY_OPS_REJECT %s\n", reason);
		assert(false);
	}
}
static void event(char value)
{ assert(event_count + 1U < sizeof(events)); events[event_count++] = value; events[event_count] = 0; }
void granule_lock(struct granule *g, enum granule_state state)
{ assert(g && !g->locked && g->state == state); g->locked = true; locks++; }
void granule_unlock(struct granule *g)
{
	assert(g && g->locked);
	for (unsigned int c = 0; c < 2; c++) for (unsigned int p = 0; p < PAGES; p++)
		if (g == &data[c][p]) expect(!mapped[c][p], "unmap before data unlock");
	g->locked = false; unlocks++;
}
struct granule *find_granule(unsigned long pa)
{
	for (unsigned int c = 0; c < 2; c++) {
		if (pa == (unsigned long)&owners[c]) return &owners[c];
		for (unsigned int p = 0; p < PAGES; p++) if (pa == data[c][p].pa) return &data[c][p];
	}
	return NULL;
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
	assert(g->locked); maps++;
	for (unsigned int c = 0; c < 2; c++) {
		if (g == &owners[c]) { assert(slot == SLOT_RD && !rd_mapped[c]); rd_mapped[c] = true; return &realms[c]; }
		if (g == &rtts[c]) { assert(slot == SLOT_RTT && !rtt_mapped[c]); rtt_mapped[c] = true; return entries[c]; }
		for (unsigned int p = 0; p < PAGES; p++) if (g == &data[c][p]) {
			assert(slot == SLOT_RSI_CALL && !mapped[c][p]); mapped[c][p] = true; selected = c * PAGES + p; return cpu[c][p];
		}
	}
	assert(false); return NULL;
}
void buffer_unmap(void *memory)
{
	for (unsigned int c = 0; c < 2; c++) {
		if (memory == &realms[c]) { assert(rd_mapped[c]); rd_mapped[c] = false; return; }
		if (memory == entries[c]) { assert(rtt_mapped[c]); rtt_mapped[c] = false; return; }
		for (unsigned int p = 0; p < PAGES; p++) if (memory == cpu[c][p]) {
			assert(mapped[c][p] && data[c][p].locked); mapped[c][p] = false; event('U'); return;
		}
	}
	assert(false);
}
bool addr_in_par(const struct rd *rd, unsigned long ipa)
{ assert(rd == &realms[0] || rd == &realms[1]); return ipa >= IPA && ipa < IPA + PAGES * 4096UL; }
void s2tt_walk_lock_unlock(const struct s2tt_context *ctx, unsigned long ipa, int level, struct s2tt_walk *wi)
{ assert(ctx->g_rtt->locked && level == 3); walks++; *wi = (struct s2tt_walk){ctx->g_rtt, (ipa >> 12U) & 511U, 3}; }
unsigned long s2tte_read(const unsigned long *e) { return *e; }
void s2tte_write(unsigned long *e, unsigned long v) { *e = v; }
bool s2tte_is_assigned_ram(const struct s2tt_context *ctx, unsigned long e, long l)
{ (void)ctx; (void)l; return (e & 3UL) == 3UL; }
bool s2tte_is_assigned_empty(const struct s2tt_context *ctx, unsigned long e, long l)
{ (void)ctx; (void)l; return (e & 4095UL) == 16UL; }
bool s2tte_is_unassigned_ram(const struct s2tt_context *ctx, unsigned long e)
{ (void)ctx; return e == 32UL; }
unsigned long s2tte_pa(const struct s2tt_context *ctx, unsigned long e, long l)
{ (void)ctx; (void)l; return e & ~4095UL; }
unsigned long s2tte_create_assigned_ram(const struct s2tt_context *ctx, unsigned long pa, long l)
{ (void)ctx; (void)l; return pa | 0x3fUL; }
unsigned long s2tte_create_assigned_empty(const struct s2tt_context *ctx, unsigned long pa, long l)
{ (void)ctx; (void)l; return pa | 16UL; }
unsigned long s2tte_create_unassigned_ram(const struct s2tt_context *ctx) { (void)ctx; return 32UL; }
void s2tt_invalidate_page(const struct s2tt_context *ctx, unsigned long ipa)
{ assert(ctx->g_rtt->locked && GRANULE_ALIGNED(ipa)); }
bool xshm_memory_range_busy(const void *o, unsigned long ipa, unsigned long size)
{ return shared_busy && o == &owners[0] && ipa == IPA && size == 4096; }
bool opencca_iommu_range_busy(const void *o, unsigned long ipa, unsigned long size)
{ return iommu_busy && o == &owners[0] && ipa == IPA && size == 4096; }
static bool opencca_gpu_page_busy(unsigned long pa)
{ source_checks++; return physical_busy && pa == PA; }
static unsigned char *cache_address(uintptr_t address, size_t bytes, size_t *offset)
{
	unsigned int c = selected / PAGES, p = selected % PAGES;
	assert(mapped[c][p] && data[c][p].locked);
	assert(address >= (uintptr_t)cpu[c][p]); *offset = address - (uintptr_t)cpu[c][p];
	assert(*offset <= 4096 && bytes <= 4096 - *offset);
	return device[c][p] + *offset;
}
static void inv_dcache_range(uintptr_t address, size_t bytes)
{ size_t offset; unsigned char *src = cache_address(address, bytes, &offset); memcpy((void *)address, src, bytes); event('I'); }
static void clean_dcache_range(uintptr_t address, size_t bytes)
{ size_t offset; unsigned char *dst = cache_address(address, bytes, &offset); memcpy(dst, (void *)address, bytes); event('C'); }
static void flush_dcache_range(uintptr_t address, size_t bytes)
{ size_t offset; unsigned char *dst = cache_address(address, bytes, &offset); memcpy(dst, (void *)address, bytes); event('F'); }
static void barrier(void) { event('B'); }
#define dsb(scope) barrier()
#include "private-memory-ops.inc"
static void balanced(void)
{
	expect(locks == unlocks, "all locks released");
	for (unsigned int c = 0; c < 2; c++) {
		expect(!owners[c].locked && !rtts[c].locked && !rd_mapped[c] && !rtt_mapped[c], "RD/RTT released");
		for (unsigned int p = 0; p < PAGES; p++) expect(!data[c][p].locked && !mapped[c][p], "DATA released");
	}
}
static void setup(void)
{
	for (unsigned int c = 0; c < 2; c++) {
		rtts[c] = (struct granule){.state = GRANULE_STATE_RTT, .memory = entries[c], .refs = PAGES};
		realms[c].s2_ctx.g_rtt = &rtts[c];
		owners[c] = (struct granule){.state = GRANULE_STATE_RD, .memory = &realms[c]};
		for (unsigned int p = 0; p < PAGES; p++) {
			data[c][p] = (struct granule){.state = GRANULE_STATE_DATA, .pa = PA + (c * PAGES + p) * 4096UL};
			entries[c][p] = data[c][p].pa | 0x3fUL;
		}
	}
}
static void source_cases(void)
{
	unsigned long translated;
	for (unsigned int c = 0; c < 2; c++) for (unsigned int p = 0; p < PAGES; p++) {
		expect(source_page(&owners[c], IPA + p * 4096UL, &translated) && translated == data[c][p].pa, "owner RTT selects own HPA"); balanced(); checks++;
	}
	for (unsigned int which = 0; which < 3; which++) {
		shared_busy = which == 0; iommu_busy = which == 1; physical_busy = which == 2;
		unsigned int before = maps, probe = source_checks;
		expect(!source_page(&owners[0], IPA, &translated), "shared/IOMMU/physical alias denied");
		expect(maps == before + (which == 2 ? 2U : 0U) && source_checks == probe + (which == 2), "busy denial short circuit");
		expect(source_page(&owners[1], IPA, &translated) && translated == data[1][0].pa, "other owner remains usable"); balanced(); checks += 2;
	}
	shared_busy = iommu_busy = physical_busy = false;
	for (unsigned int which = 0; which < 6; which++) {
		unsigned long ipa = which == 0 ? IPA + 1 : which == 1 ? IPA - 4096 : which == 2 ? IPA + PAGES * 4096 : IPA;
		entries[0][0] = which == 3 ? 32UL : which == 4 ? PA | 16UL : PA | 0x3fUL;
		data[0][0].state = which == 5 ? GRANULE_STATE_NS : GRANULE_STATE_DATA;
		unsigned int probe = source_checks;
		expect(!source_page(&owners[0], ipa, &translated), "invalid address/entry/non-DATA denied");
		expect(source_checks == probe, "failed RTT skips physical probe"); balanced(); checks++;
	}
	data[0][0].state = GRANULE_STATE_DATA; entries[0][0] = PA | 0x3fUL;
	struct gpu_private_ops ops = {.source_page = source_page};
	struct gpu_private_result r;
	gpu_private_bo_create(&owners[0], &owners[1], 4096, GPU_PRIVATE_READ, &r);
	expect(r.status == GPU_PRIVATE_SUCCESS, "create source BO"); unsigned long bo = r.value[0], ipa = IPA;
	gpu_private_bo_append(&ops, &owners[0], bo, 0, &ipa, 1, &r);
	expect(r.status == GPU_PRIVATE_SUCCESS && gpu_private_range_busy(&owners[0], IPA, 4096), "real registration recorded");
	unsigned int before = maps;
	expect(!source_page(&owners[0], IPA, &translated) && maps == before, "registered IPA rejected before RTT lookup"); checks++;
	gpu_private_bo_destroy(&owners[0], bo, &r); expect(r.status == GPU_PRIVATE_SUCCESS, "destroy unsealed source BO");
	expect(source_page(&owners[0], IPA, &translated) && translated == PA, "destroyed registration reusable"); checks++;
	balanced();
}
static void physical_reset(void)
{
	balanced(); maps = locks = unlocks = 0; event_count = 0; events[0] = 0;
	memset(cpu, 0xa5, sizeof(cpu)); memset(device, 0x3c, sizeof(device));
}
static void physical_cases(void)
{
	unsigned char input[4096], output[4098], expected[4096]; memset(input, 0x72, sizeof(input));
	for (size_t bytes = 1; bytes <= 4096; bytes++) {
		size_t offset = 4096 - bytes; physical_reset();
		expect(write_page(PA, offset, input, bytes), "valid write");
		memset(expected, 0x3c, 4096); memcpy(expected + offset, input, bytes);
		expect(memcmp(device[0][0], expected, 4096) == 0 && !strcmp(events, "ICBU"), "exact write and cache order");
		expect(device[1][0][0] == 0x3c && cpu[1][0][0] == 0xa5, "write cannot touch other Client"); balanced(); checks++;
		physical_reset(); memset(output, 0xd7, sizeof(output));
		expect(read_page(PA, offset, output + 1, bytes), "valid read");
		for (size_t i = 0; i < sizeof(output); i++) expect(output[i] == (i >= 1 && i <= bytes ? 0x3c : 0xd7), "fresh exact read and output redzones");
		expect(!strcmp(events, "IBU"), "read barrier before unmap"); balanced(); checks++;
	}
	const size_t invalid[][2] = {{0,0},{4096,1},{4097,1},{1,4096},{SIZE_MAX,1},{1,SIZE_MAX}};
	for (unsigned int i = 0; i < sizeof(invalid)/sizeof(invalid[0]); i++) {
		physical_reset(); memset(output, 0xd7, sizeof(output));
		expect(!write_page(PA, invalid[i][0], input, invalid[i][1]) && !read_page(PA, invalid[i][0], output, invalid[i][1]), "invalid ranges rejected");
		expect(!maps && !locks && !event_count && output[0] == 0xd7 && device[0][0][0] == 0x3c, "range failure has no side effects"); checks++;
	}
	physical_reset(); expect(!write_page(PA,0,NULL,1) && !read_page(PA,0,NULL,1) && !maps, "null buffers denied"); checks++;
	for (unsigned int which = 0; which < 2; which++) {
		physical_reset(); unsigned long pa = which ? PA + 0x100000UL : PA;
		data[0][0].state = which ? GRANULE_STATE_DATA : GRANULE_STATE_NS;
		expect(!write_page(pa,0,input,1) && !read_page(pa,0,output,1) && !clear_page(pa) && !sync_page_for_device(pa) && !sync_page_for_cpu(pa), "absent/non-DATA denies all callbacks");
		expect(!maps && !event_count, "failed DATA lookup never maps"); checks++;
	}
	data[0][0].state = GRANULE_STATE_DATA;
	physical_reset(); expect(clear_page(PA), "clear donated control page");
	for (size_t i = 0; i < 4096; i++) expect(!device[0][0][i], "whole page scrub reaches device");
	expect(!strcmp(events,"ICBU"), "scrub ordering"); balanced(); checks++;
	physical_reset(); expect(sync_page_for_device(PA), "device handoff");
	for (size_t i = 0; i < 4096; i++) expect(device[0][0][i] == 0xa5, "CPU dirty data reaches device");
	expect(!strcmp(events,"FBU"), "device handoff ordering"); balanced(); checks++;
	physical_reset(); expect(sync_page_for_cpu(PA), "CPU handoff");
	for (size_t i = 0; i < 4096; i++) expect(device[0][0][i] == 0x3c && cpu[0][0][i] == 0x3c, "CPU return cannot overwrite GPU result");
	expect(!strcmp(events,"IBU"), "CPU handoff ordering"); balanced(); checks++;
	event_count = 0; events[0] = 0; expect(cache_barrier() && !strcmp(events,"B"), "explicit cache barrier"); checks++;
}
int main(void)
{
	setup(); source_cases(); physical_cases(); balanced();
	printf("GPU_MEMORY_OPS=PASS cases=%u actual source/physical callbacks/private core/xshm_rtt; RD/RTT/cache/external busy probes MODEL_ONLY\n", checks);
	return 0;
}
