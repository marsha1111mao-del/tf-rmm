/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef XSHM_MEMORY_H
#define XSHM_MEMORY_H

#include <stdbool.h>
#include <stddef.h>

#define XSHM_MEM_OFFER 9UL
#define XSHM_MEM_ATTACH 10UL
#define XSHM_MEM_DETACH 11UL
#define XSHM_MEM_REVOKE 12UL
#define XSHM_MEM_STATUS 13UL
#define XSHM_MEM_CONTINUE 14UL
#define XSHM_MEM_DESCRIBE 15UL
#define XSHM_CAP_MEMORY 4UL
#define XSHM_CAP_MEMORY_IDENTITY 8UL
#define XSHM_MEMORY_REGIONS 64U
#define XSHM_MEMORY_PER_OWNER 8U
/* Bounded 512 MiB grants for large GPU workloads; per-owner quotas and
 * the 64-page continuation budget remain unchanged. */
#define XSHM_MEMORY_PAGES 131072U
#define XSHM_MEMORY_BUDGET 64U
#define XSHM_MEMORY_PAGE_SIZE 4096UL

enum xshm_memory_state {
	XSHM_MEMORY_FREE,
	XSHM_MEMORY_OFFERING,
	XSHM_MEMORY_OFFERED,
	XSHM_MEMORY_PREPARING,
	XSHM_MEMORY_INSTALLING,
	XSHM_MEMORY_ACTIVE,
	XSHM_MEMORY_UNMAPPING,
	XSHM_MEMORY_QUARANTINED,
};

/* Backend operations execute under the same policy gate as Host RTT/DATA
 * mutations. They neither trust caller-provided physical addresses nor modify
 * GPT/PAS. Destination entries must be unassigned protected RAM leaf entries.
 * The pinned source RTT remains authoritative; no duplicate PA list or
 * destination physical pages are retained. Source translations cannot change
 * while the grant exists, including during partial attach/revoke.
 * install/restore must validate the expected entry, maintain RTT refcounts and
 * complete the required TLBI before returning. Failure must not modify a PTE.
 */
struct xshm_memory_identity {
	const void *owner;
	unsigned long endpoint;
};

struct xshm_memory_ops {
	bool (*valid_range)(const void *owner, unsigned long ipa, unsigned long size);
	bool (*source_page)(const void *owner, unsigned long ipa, unsigned long *pa);
	bool (*target_page)(const void *owner, unsigned long ipa);
	bool (*install)(const void *owner, unsigned long ipa, unsigned long pa);
	bool (*restore)(const void *owner, unsigned long ipa, unsigned long pa);
};

/* Caller serialization also covers the three guard queries below. The peer
 * argument for OFFER/ATTACH is supplied by an authenticated live channel lookup, never by
 * an RSI payload. Progress is bounded; CONTINUE belongs to the current actor.
 */
unsigned long xshm_memory_call(const struct xshm_memory_ops *ops,
		const struct xshm_memory_identity *caller,
		const struct xshm_memory_identity *peer, unsigned long command,
		unsigned long id, unsigned long argument, unsigned long size,
		unsigned long output[4]);
unsigned long xshm_memory_channel(const struct xshm_memory_identity *caller,
				  unsigned long id);
bool xshm_memory_owner_busy(const void *owner);
bool xshm_memory_channel_busy(const void *owner, unsigned long channel);
bool xshm_memory_range_busy(const void *owner, unsigned long base,
			    unsigned long size);

#endif
