/* SPDX-License-Identifier: BSD-3-Clause */
#include <limits.h>
#include <xshm_endpoint.h>
#include <xshm_memory.h>

struct xshm_memory_region {
	const void *owner;
	const void *peer;
	const void *actor;
	unsigned long owner_id;
	unsigned long peer_id;
	unsigned long id;
	unsigned long channel;
	unsigned long source;
	unsigned long target;
	unsigned int pages;
	unsigned int cursor;
	unsigned int installed;
	enum xshm_memory_state state;
	bool target_bound;
	bool revoke;
	bool failed;
};

static struct xshm_memory_region regions[XSHM_MEMORY_REGIONS];
static unsigned long next_region_id;

static bool overlap(unsigned long a, unsigned long as,
		    unsigned long b, unsigned long bs)
{
	/* Subtraction avoids overflow, including malformed Host requests. */
	if ((as == 0UL) || (bs == 0UL))
		return false;
	return (a >= b) ? ((a - b) < bs) : ((b - a) < as);
}

static unsigned long region_size(const struct xshm_memory_region *region)
{
	return (unsigned long)region->pages * XSHM_MEMORY_PAGE_SIZE;
}

unsigned long xshm_memory_channel(const struct xshm_memory_identity *caller,
				  unsigned long id)
{
	if (caller == NULL || caller->owner == NULL || caller->endpoint == 0UL)
		return 0UL;
	for (unsigned int i = 0U; i < XSHM_MEMORY_REGIONS; i++) {
		const struct xshm_memory_region *region = &regions[i];

		if (region->state != XSHM_MEMORY_FREE && region->id == id &&
		    ((caller->owner == region->owner && caller->endpoint == region->owner_id) ||
		     (caller->owner == region->peer && caller->endpoint == region->peer_id)))
			return region->channel;
	}
	return 0UL;
}

bool xshm_memory_owner_busy(const void *owner)
{
	if (owner == NULL)
		return false;
	for (unsigned int i = 0U; i < XSHM_MEMORY_REGIONS; i++) {
		if ((regions[i].state != XSHM_MEMORY_FREE) &&
		    ((regions[i].owner == owner) ||
		     (regions[i].target_bound && regions[i].peer == owner)))
			return true;
	}
	return false;
}

bool xshm_memory_channel_busy(const void *owner, unsigned long channel)
{
	if (channel == 0UL)
		return false;
	for (unsigned int i = 0U; i < XSHM_MEMORY_REGIONS; i++) {
		if ((regions[i].state != XSHM_MEMORY_FREE) &&
		    (regions[i].channel == channel) &&
		    ((regions[i].owner == owner) ||
		     (regions[i].target_bound && regions[i].peer == owner)))
			return true;
	}
	return false;
}

bool xshm_memory_range_busy(const void *owner, unsigned long base,
			    unsigned long size)
{
	if (owner == NULL)
		return false;
	for (unsigned int i = 0U; i < XSHM_MEMORY_REGIONS; i++) {
		const struct xshm_memory_region *region = &regions[i];
		unsigned long length = region_size(region);

		if (region->state == XSHM_MEMORY_FREE)
			continue;
		if ((region->owner == owner) &&
		    overlap(base, size, region->source, length))
			return true;
		if (region->target_bound && (region->peer == owner) &&
		    overlap(base, size, region->target, length))
			return true;
	}
	return false;
}

static void snapshot(const struct xshm_memory_region *region,
		     unsigned long output[4])
{
	output[0] = region->id;
	output[1] = (unsigned long)region->state;
	output[2] = (region->state == XSHM_MEMORY_UNMAPPING) ?
		region->installed : region->cursor;
	output[3] = region->pages;
}

static void clear_region(struct xshm_memory_region *region)
{
	/* Only metadata is cleared. No borrowed/source physical page is freed. */
	region->state = XSHM_MEMORY_FREE;
	region->owner = NULL;
	region->peer = NULL;
	region->actor = NULL;
	region->owner_id = 0UL;
	region->peer_id = 0UL;
	region->id = 0UL;
	region->channel = 0UL;
	region->source = 0UL;
	region->target = 0UL;
	region->pages = 0U;
	region->cursor = 0U;
	region->installed = 0U;
	region->target_bound = false;
	region->revoke = false;
	region->failed = false;
}

static void detach_complete(struct xshm_memory_region *region)
{
	region->target = 0UL;
	region->target_bound = false;
	region->cursor = 0U;
	region->actor = NULL;
	region->state = XSHM_MEMORY_OFFERED;
}

static unsigned long advance(const struct xshm_memory_ops *ops,
			     struct xshm_memory_region *region)
{
	for (unsigned int work = 0U; work < XSHM_MEMORY_BUDGET; work++) {
		unsigned long pa;
		unsigned int index = region->cursor;
		unsigned long offset = (unsigned long)index * XSHM_MEMORY_PAGE_SIZE;

		switch (region->state) {
		case XSHM_MEMORY_OFFERING:
			if (!ops->source_page(region->owner, region->source + offset,
					      &pa)) {
				clear_region(region);
				return XSHM_ERROR_STATE;
			}
			region->cursor++;
			if (region->cursor == region->pages) {
				region->state = XSHM_MEMORY_OFFERED;
				region->actor = NULL;
				return XSHM_SUCCESS;
			}
			break;
		case XSHM_MEMORY_PREPARING:
			if (!ops->target_page(region->peer, region->target + offset)) {
				detach_complete(region);
				return XSHM_ERROR_STATE;
			}
			region->cursor++;
			if (region->cursor == region->pages) {
				region->state = XSHM_MEMORY_INSTALLING;
				region->cursor = 0U;
			}
			break;
		case XSHM_MEMORY_INSTALLING:
			if (!ops->source_page(region->owner, region->source + offset, &pa) ||
			    !ops->install(region->peer, region->target + offset, pa)) {
				/* Never publish ACTIVE after a partial install. */
				region->failed = true;
				region->state = XSHM_MEMORY_UNMAPPING;
				break;
			}
			region->installed++;
			region->cursor++;
			if (region->cursor == region->pages) {
				region->state = XSHM_MEMORY_ACTIVE;
				region->actor = NULL;
				return XSHM_SUCCESS;
			}
			break;
		case XSHM_MEMORY_UNMAPPING:
			if (region->installed != 0U) {
				index = region->installed - 1U;
				offset = (unsigned long)index * XSHM_MEMORY_PAGE_SIZE;
				if (!ops->source_page(region->owner, region->source + offset, &pa) ||
				    !ops->restore(region->peer, region->target + offset, pa)) {
					/* Keep all pins on any unexpected translation state. */
					region->state = XSHM_MEMORY_QUARANTINED;
					return XSHM_ERROR_STATE;
				}
				region->installed--;
			}
			if (region->installed == 0U) {
				bool failed = region->failed;

				if (region->revoke)
					clear_region(region);
				else {
					detach_complete(region);
					region->failed = false;
				}
				return failed ? XSHM_ERROR_STATE : XSHM_SUCCESS;
			}
			break;
		default:
			return XSHM_ERROR_STATE;
		}
	}
	return XSHM_FULL; /* RSI_INCOMPLETE: caller must explicitly CONTINUE. */
}

static bool valid_size(unsigned long base, unsigned long size)
{
	return (size != 0UL) &&
	       (size <= XSHM_MEMORY_PAGES * XSHM_MEMORY_PAGE_SIZE) &&
	       (((base | size) & (XSHM_MEMORY_PAGE_SIZE - 1UL)) == 0UL) &&
	       (base <= ULONG_MAX - size);
}

unsigned long xshm_memory_call(const struct xshm_memory_ops *ops,
		const struct xshm_memory_identity *caller,
		const struct xshm_memory_identity *peer, unsigned long command,
		unsigned long id, unsigned long argument, unsigned long size,
		unsigned long output[4])
{
	const void *owner = (caller == NULL) ? NULL : caller->owner;
	struct xshm_memory_region *region = NULL;
	unsigned long result, requested_id;

	if (output == NULL)
		return XSHM_ERROR_INPUT;
	for (unsigned int i = 0U; i < 4U; i++)
		output[i] = 0UL;
	if ((owner == NULL) || (caller->endpoint == 0UL) || (ops == NULL) ||
	    (command < XSHM_MEM_OFFER) || (command > XSHM_MEM_DESCRIBE) ||
	    ((command != XSHM_MEM_OFFER) && (size != 0UL)) ||
	    ((command != XSHM_MEM_OFFER) && (command != XSHM_MEM_ATTACH) &&
	     (argument != 0UL)))
		return XSHM_ERROR_INPUT;
	if (command == XSHM_MEM_OFFER) {
		if ((peer == NULL) || (peer->owner == NULL) || (peer->endpoint == 0UL) ||
		    (peer->owner == owner) || (id == 0UL) ||
		    !valid_size(argument, size) ||
		    !ops->valid_range(owner, argument, size) ||
		    xshm_memory_range_busy(owner, argument, size))
			return XSHM_ERROR_INPUT;
		unsigned int owned = 0U;

		for (unsigned int i = 0U; i < XSHM_MEMORY_REGIONS; i++)
			if (regions[i].state != XSHM_MEMORY_FREE && regions[i].owner == owner)
				owned++;
		if (owned == XSHM_MEMORY_PER_OWNER)
			return XSHM_FULL;
		if (next_region_id == ULONG_MAX)
			return XSHM_ERROR_STATE;
		for (unsigned int i = 0U; i < XSHM_MEMORY_REGIONS; i++) {
			if (regions[i].state == XSHM_MEMORY_FREE) {
				region = &regions[i];
				break;
			}
		}
		if (region == NULL)
			return XSHM_FULL;
		clear_region(region);
		region->id = ++next_region_id;
		region->channel = id;
		region->owner = owner;
		region->peer = peer->owner;
		region->owner_id = caller->endpoint;
		region->peer_id = peer->endpoint;
		region->actor = owner;
		region->source = argument;
		region->pages = (unsigned int)(size / XSHM_MEMORY_PAGE_SIZE);
		region->state = XSHM_MEMORY_OFFERING;
	} else {
		for (unsigned int i = 0U; i < XSHM_MEMORY_REGIONS; i++) {
			if ((regions[i].state != XSHM_MEMORY_FREE) &&
			    (regions[i].id == id)) {
				region = &regions[i];
				break;
			}
		}
		if (region == NULL)
			return XSHM_ERROR_STATE;
		if (!((owner == region->owner && caller->endpoint == region->owner_id) ||
		      (owner == region->peer && caller->endpoint == region->peer_id)))
			return XSHM_ERROR_INPUT;
		if (command == XSHM_MEM_STATUS) {
			snapshot(region, output);
			return XSHM_SUCCESS;
		}
		if (command == XSHM_MEM_DESCRIBE) {
			/* The grant and caller generation were authenticated above.
			 * Never export RD pointers or peer IPA/physical addresses.
			 * STATUS supplies state/size; this immutable identity binds a
			 * local kernel consumer to the actual RMM channel and peers.
			 */
			output[0] = region->channel;
			output[1] = region->owner_id;
			output[2] = region->peer_id;
			output[3] = owner == region->owner ? region->source :
				(region->target_bound ? region->target : 0UL);
			return XSHM_SUCCESS;
		}
		if (region->state == XSHM_MEMORY_QUARANTINED)
			return XSHM_ERROR_STATE;
		if (command == XSHM_MEM_ATTACH) {
			if (peer == NULL || peer->owner != region->owner ||
			    peer->endpoint != region->owner_id)
				return XSHM_ERROR_INPUT;
			if ((owner != region->peer) ||
			    (region->state != XSHM_MEMORY_OFFERED))
				return XSHM_ERROR_STATE;
			if (!valid_size(argument, region_size(region)) ||
			    !ops->valid_range(owner, argument, region_size(region)) ||
			    xshm_memory_range_busy(owner, argument, region_size(region)))
				return XSHM_ERROR_INPUT;
			region->target = argument;
			region->target_bound = true;
			region->cursor = 0U;
			region->actor = owner;
			region->state = XSHM_MEMORY_PREPARING;
		} else if ((command == XSHM_MEM_DETACH) ||
			   (command == XSHM_MEM_REVOKE)) {
			bool revoke = command == XSHM_MEM_REVOKE;

			if (owner != (revoke ? region->owner : region->peer))
				return XSHM_ERROR_INPUT;
			if (!revoke && region->revoke)
				return XSHM_ERROR_STATE;
			if (!revoke && !region->target_bound)
				return XSHM_ERROR_STATE;
			region->actor = owner;
			region->revoke = revoke;
			region->state = XSHM_MEMORY_UNMAPPING;
		} else if (owner != region->actor) {
			return XSHM_ERROR_INPUT;
		}
	}
	requested_id = region->id;
	result = advance(ops, region);
	snapshot(region, output);
	/* Retain the operation ID in the final response, even after release. */
	output[0] = requested_id;
	return result;
}
