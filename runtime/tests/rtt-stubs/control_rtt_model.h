/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef CONTROL_RTT_MODEL_H
#define CONTROL_RTT_MODEL_H
/* Test-only granules and synthetic S2 descriptors. Exercise the real RTT and
 * RMI policy source; this does not emulate CPU caches or hardware TLBI.
 */
#include <stdbool.h>
#include <stddef.h>

#define GRANULE_SIZE 4096UL
#define GRANULE_ALIGNED(v) (((v) & 4095UL) == 0UL)
#define S2TT_PAGE_LEVEL 3
#define S2TT_MAX_PA_BITS 48
#define SLOT_RD 0
#define SLOT_RTT 1

enum granule_state { GRANULE_STATE_RD, GRANULE_STATE_RTT, GRANULE_STATE_DATA, GRANULE_STATE_NS,
	GRANULE_STATE_DELEGATED };
struct granule {
	enum granule_state state;
	void *memory;
	unsigned long pa;
	unsigned int refs;
	bool locked;
};
struct s2tt_context { struct granule *g_rtt; bool enable_lpa2;
	unsigned int num_root_rtts, vmid; };
struct rd { struct s2tt_context s2_ctx; };
struct s2tt_walk { struct granule *g_llt; unsigned long index; int last_level; };

void granule_lock(struct granule *g, enum granule_state state);
void granule_unlock(struct granule *g);
struct granule *find_lock_granule(unsigned long pa, enum granule_state state);
struct granule *find_granule(unsigned long pa);
void atomic_granule_get(struct granule *g);
void atomic_granule_put(struct granule *g);
void *buffer_granule_map(struct granule *g, unsigned int slot);
void buffer_unmap(void *memory);
bool addr_in_par(const struct rd *rd, unsigned long ipa);
void s2tt_walk_lock_unlock(const struct s2tt_context *ctx, unsigned long ipa,
		int level, struct s2tt_walk *wi);
unsigned long s2tte_read(const unsigned long *entry);
void s2tte_write(unsigned long *entry, unsigned long value);
bool s2tte_is_assigned_ram(const struct s2tt_context *ctx, unsigned long entry, long level);
bool s2tte_is_assigned_empty(const struct s2tt_context *ctx, unsigned long entry, long level);
bool s2tte_is_unassigned_ram(const struct s2tt_context *ctx, unsigned long entry);
unsigned long s2tte_pa(const struct s2tt_context *ctx, unsigned long entry, long level);
unsigned long s2tte_create_assigned_ram(const struct s2tt_context *ctx, unsigned long pa, long level);
unsigned long s2tte_create_assigned_empty(const struct s2tt_context *ctx, unsigned long pa, long level);
unsigned long s2tte_create_unassigned_ram(const struct s2tt_context *ctx);
void s2tt_invalidate_page(const struct s2tt_context *ctx, unsigned long ipa);
#define s2tte_map_size(level) (1UL << (12U + 9U * (3U - (unsigned int)(level))))
#endif
