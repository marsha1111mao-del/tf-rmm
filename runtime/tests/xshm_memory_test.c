/* SPDX-License-Identifier: BSD-3-Clause */
/* Test the real grant state machine with a bounded translation backend.
 * This does not replace testing the architectural RTT/TLBI backend on a Realm.
 */
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <xshm_endpoint.h>
#include <xshm_memory.h>
#include <xshm_service.h>

#define PAGES (XSHM_MEMORY_PAGES + 1U)
#define BASE 0x80000000UL
#define PAGE XSHM_MEMORY_PAGE_SIZE
static unsigned char owners[10];
static struct xshm_memory_identity identities[10];
static unsigned long tables[10][PAGES];
static unsigned long output[4];
static unsigned int installed_calls;
static unsigned int fail_install = UINT_MAX;
static bool fail_restore;

static unsigned int owner_index(const void *owner)
{
	for (unsigned int i = 0U; i < 10U; i++)
		if (owner == &owners[i])
			return i;
	assert(false);
	return 0U;
}

static bool valid_range(const void *owner, unsigned long ipa, unsigned long size)
{
	(void)owner_index(owner);
	return (ipa >= BASE) && (ipa - BASE < PAGES * PAGE) &&
	       (size <= PAGES * PAGE - (ipa - BASE));
}

static unsigned long *entry(const void *owner, unsigned long ipa)
{
	assert(valid_range(owner, ipa, PAGE));
	return &tables[owner_index(owner)][(ipa - BASE) / PAGE];
}

static bool source_page(const void *owner, unsigned long ipa, unsigned long *pa)
{
	*pa = *entry(owner, ipa);
	return *pa != 0UL;
}

static bool target_page(const void *owner, unsigned long ipa)
{
	return *entry(owner, ipa) == 0UL;
}

static bool install(const void *owner, unsigned long ipa, unsigned long pa)
{
	if ((installed_calls++ == fail_install) || (*entry(owner, ipa) != 0UL))
		return false;
	*entry(owner, ipa) = pa;
	return true;
}

static bool restore(const void *owner, unsigned long ipa, unsigned long pa)
{
	if (fail_restore || (*entry(owner, ipa) != pa))
		return false;
	*entry(owner, ipa) = 0UL;
	return true;
}

static const struct xshm_memory_ops ops = {
	.valid_range = valid_range, .source_page = source_page,
	.target_page = target_page, .install = install, .restore = restore,
};

static unsigned long call(unsigned int owner, unsigned long command,
		unsigned long id, unsigned long argument, unsigned long size)
{
	return xshm_memory_call(&ops, &identities[owner], &identities[owner == 1U ? 0U : 1U], command,
				id, argument, size, output);
}

static unsigned long finish(unsigned int owner, unsigned long id, unsigned long status)
{

	for (unsigned int calls = 0U; status == XSHM_FULL; calls++) {
		assert(calls < 10000U);
		assert(id != 0UL);
		status = call(owner, XSHM_MEM_CONTINUE, id, 0UL, 0UL);
	}
	return status;
}

static unsigned long offer(unsigned int pages)
{
	unsigned long status = call(0U, XSHM_MEM_OFFER, 100UL, BASE, pages * PAGE);
	unsigned long id = output[0];

	assert(finish(0U, id, status) == XSHM_SUCCESS);
	assert(output[1] == XSHM_MEMORY_OFFERED);
	return output[0];
}

static unsigned long service(unsigned int owner, unsigned long command,
		unsigned long id, unsigned long argument, unsigned long size)
{
	return xshm_service_call(&ops, &owners[owner], command, id,
				argument, size, output);
}

static void test_service(void)
{
	unsigned long endpoint, channel, id;

	assert(service(0U, XSHM_REGISTER, 0UL, 0UL, 0UL) == XSHM_SUCCESS);
	assert((output[2] & XSHM_CAP_MEMORY) != 0UL);
	assert(service(1U, XSHM_REGISTER, 0UL, 0UL, 0UL) == XSHM_SUCCESS);
	endpoint = output[1];
	assert(service(2U, XSHM_REGISTER, 0UL, 0UL, 0UL) == XSHM_SUCCESS);
	assert(service(0U, XSHM_OFFER, endpoint, 0UL, 0UL) == XSHM_SUCCESS);
	channel = output[0];
	assert(service(0U, XSHM_MEM_OFFER, channel, BASE, PAGE) == XSHM_ERROR_INPUT);
	assert(service(1U, XSHM_ACCEPT, channel, 0UL, 0UL) == XSHM_SUCCESS);
	assert(service(2U, XSHM_MEM_OFFER, channel, BASE, PAGE) == XSHM_ERROR_INPUT);
	assert(service(0U, XSHM_MEM_OFFER, channel, BASE, PAGE) == XSHM_SUCCESS);
	id = output[0];
	assert(service(0U, XSHM_UNREGISTER, 0UL, 0UL, 0UL) == XSHM_ERROR_STATE);
	assert(service(0U, XSHM_CLOSE, channel, 0UL, 0UL) == XSHM_ERROR_STATE);
	assert(service(2U, XSHM_MEM_ATTACH, id, BASE, 0UL) == XSHM_ERROR_INPUT);
	assert(service(1U, XSHM_CLOSE, channel, 0UL, 0UL) == XSHM_SUCCESS);
	assert(service(1U, XSHM_MEM_ATTACH, id, BASE, 0UL) == XSHM_ERROR_INPUT);
	assert(service(0U, XSHM_MEM_REVOKE, id, 0UL, 0UL) == XSHM_SUCCESS);

	assert(service(0U, XSHM_OFFER, endpoint, 0UL, 0UL) == XSHM_SUCCESS);
	channel = output[0];
	assert(service(1U, XSHM_ACCEPT, channel, 0UL, 0UL) == XSHM_SUCCESS);
	assert(service(0U, XSHM_MEM_OFFER, channel, BASE, PAGE) == XSHM_SUCCESS);
	id = output[0];
	assert(service(1U, XSHM_MEM_ATTACH, id, BASE, 0UL) == XSHM_SUCCESS);
	assert(tables[1][0] == tables[0][0]);
	assert(service(1U, XSHM_CLOSE, channel, 0UL, 0UL) == XSHM_ERROR_STATE);
	assert(service(1U, XSHM_UNREGISTER, 0UL, 0UL, 0UL) == XSHM_ERROR_STATE);
	assert(service(2U, XSHM_MEM_REVOKE, id, 0UL, 0UL) == XSHM_ERROR_INPUT);
	assert(service(1U, XSHM_MEM_OFFER, channel, BASE, PAGE) == XSHM_ERROR_INPUT);
	assert(service(1U, XSHM_MEM_DETACH, id, 0UL, 0UL) == XSHM_SUCCESS);
	assert(tables[1][0] == 0UL);
	assert(service(1U, XSHM_UNREGISTER, 0UL, 0UL, 0UL) == XSHM_SUCCESS);
	assert(service(1U, XSHM_REGISTER, 0UL, 0UL, 0UL) == XSHM_SUCCESS);
	assert(output[1] != endpoint);
	assert(service(1U, XSHM_MEM_ATTACH, id, BASE, 0UL) == XSHM_ERROR_INPUT);
	assert(service(0U, XSHM_MEM_REVOKE, id, 0UL, 0UL) == XSHM_SUCCESS);
	for (unsigned int i = 0U; i < 3U; i++)
		assert(service(i, XSHM_UNREGISTER, 0UL, 0UL, 0UL) == XSHM_SUCCESS);
}

int main(void)
{
	unsigned long id, previous, status, ids[XSHM_MEMORY_REGIONS];

	for (unsigned int owner = 0U; owner < 10U; owner++) {
		identities[owner].owner = &owners[owner];
		identities[owner].endpoint = 1UL + owner;
		if (owner == 1U)
			continue;
		for (unsigned int i = 0U; i < PAGES; i++)
			tables[owner][i] = 0x100000UL + owner * PAGES * PAGE + i * PAGE;
	}
	/* The resource ceiling is not an authorization bypass. Exercise the
	 * whole 512 MiB lease, then reject one page beyond the policy limit
	 * even though this test backend has room for that extra page.
	 */
	assert(XSHM_MEMORY_PAGES == 131072U);
	assert(call(0U, XSHM_MEM_OFFER, 100UL, BASE,
		    (XSHM_MEMORY_PAGES + 1UL) * PAGE) == XSHM_ERROR_INPUT);
	id = offer(XSHM_MEMORY_PAGES);
	assert(call(2U, XSHM_MEM_ATTACH, id, BASE, 0UL) == XSHM_ERROR_INPUT);
	assert(finish(1U, id, call(1U, XSHM_MEM_ATTACH, id, BASE, 0UL)) == XSHM_SUCCESS);
	assert(tables[1][0] == tables[0][0]);
	assert(tables[1][XSHM_MEMORY_PAGES - 1U] == tables[0][XSHM_MEMORY_PAGES - 1U]);
	assert(call(2U, XSHM_MEM_REVOKE, id, 0UL, 0UL) == XSHM_ERROR_INPUT);
	assert(finish(0U, id, call(0U, XSHM_MEM_REVOKE, id, 0UL, 0UL)) == XSHM_SUCCESS);
	assert(!xshm_memory_owner_busy(&owners[0]));
	assert(!xshm_memory_owner_busy(&owners[1]));
	for (unsigned int i = 0U; i < XSHM_MEMORY_PAGES; i++)
		assert(tables[1][i] == 0UL);
	assert(call(0U, XSHM_MEM_OFFER, 100UL, BASE + 1UL, PAGE) == XSHM_ERROR_INPUT);
	assert(call(0U, XSHM_MEM_OFFER, 100UL, ULONG_MAX - PAGE + 1UL,
		    2UL * PAGE) == XSHM_ERROR_INPUT);
	id = offer(129U);
	assert(call(0U, XSHM_MEM_DESCRIBE, id, 0UL, 0UL) == XSHM_SUCCESS);
	assert(output[0] == 100UL && output[1] == identities[0].endpoint &&
	       output[2] == identities[1].endpoint && output[3] == BASE);
	assert(call(1U, XSHM_MEM_DESCRIBE, id, 0UL, 0UL) == XSHM_SUCCESS);
	assert(output[3] == 0UL); /* No borrower mapping exists yet. */
	assert(call(2U, XSHM_MEM_DESCRIBE, id, 0UL, 0UL) == XSHM_ERROR_INPUT);
	assert(output[0] == 0UL && output[1] == 0UL && output[2] == 0UL && output[3] == 0UL);
	assert(xshm_memory_channel(&identities[0], id) == 100UL);
	assert(xshm_memory_channel(&identities[2], id) == 0UL);
	/* Closing the channel before attachment revokes attach authorization. */
	assert(xshm_memory_call(&ops, &identities[1], NULL, XSHM_MEM_ATTACH,
		id, BASE, 0UL, output) == XSHM_ERROR_INPUT);
	assert(xshm_memory_owner_busy(&owners[0]));
	assert(!xshm_memory_owner_busy(&owners[1]));
	assert(!xshm_memory_owner_busy(&owners[2]));
	assert(xshm_memory_channel_busy(&owners[0], 100UL));
	assert(!xshm_memory_channel_busy(&owners[1], 100UL));
	assert(xshm_memory_range_busy(&owners[0], BASE, PAGE));
	assert(!xshm_memory_range_busy(&owners[1], BASE, PAGE));
	assert(call(2U, XSHM_MEM_ATTACH, id, BASE, 0UL) == XSHM_ERROR_INPUT);
	assert(call(2U, XSHM_MEM_REVOKE, id, 0UL, 0UL) == XSHM_ERROR_INPUT);
	status = call(1U, XSHM_MEM_ATTACH, id, BASE, 0UL);
	assert(status == XSHM_FULL);
	assert(output[1] == XSHM_MEMORY_PREPARING);
	assert(xshm_memory_owner_busy(&owners[1]));
	assert(xshm_memory_channel_busy(&owners[1], 100UL));
	assert(xshm_memory_range_busy(&owners[1], BASE, PAGE));
	assert(call(0U, XSHM_MEM_CONTINUE, id, 0UL, 0UL) == XSHM_ERROR_INPUT);
	assert(finish(1U, id, status) == XSHM_SUCCESS);
	assert(output[1] == XSHM_MEMORY_ACTIVE);
	assert(call(1U, XSHM_MEM_DESCRIBE, id, 0UL, 0UL) == XSHM_SUCCESS);
	assert(output[0] == 100UL && output[3] == BASE);
	for (unsigned int i = 0U; i < 129U; i++)
		assert(tables[1][i] == tables[0][i]);
	/* A borrower cannot regrant an alias or cancel the provider's revoke. */
	assert(xshm_memory_call(&ops, &identities[1], &identities[2], XSHM_MEM_OFFER,
		100UL, BASE, PAGE, output) == XSHM_ERROR_INPUT);
	status = call(0U, XSHM_MEM_REVOKE, id, 0UL, 0UL);
	assert(status == XSHM_FULL);
	assert(call(1U, XSHM_MEM_DETACH, id, 0UL, 0UL) == XSHM_ERROR_STATE);
	assert(finish(0U, id, status) == XSHM_SUCCESS);
	assert(!xshm_memory_owner_busy(&owners[0]));
	assert(!xshm_memory_owner_busy(&owners[1]));
	assert(call(1U, XSHM_MEM_STATUS, id, 0UL, 0UL) == XSHM_ERROR_STATE);
	assert(call(1U, XSHM_MEM_DESCRIBE, id, 0UL, 0UL) == XSHM_ERROR_STATE);
	for (unsigned int i = 0U; i < 129U; i++)
		assert(tables[1][i] == 0UL);
	previous = id;

	/* Failure after partial installation must restore every installed alias. */
	id = offer(129U);
	assert(id != previous);
	installed_calls = 0U;
	fail_install = 70U;
	assert(finish(1U, id, call(1U, XSHM_MEM_ATTACH, id, BASE, 0UL)) == XSHM_ERROR_STATE);
	assert(call(0U, XSHM_MEM_STATUS, id, 0UL, 0UL) == XSHM_SUCCESS);
	assert(output[1] == XSHM_MEMORY_OFFERED);
	assert(!xshm_memory_range_busy(&owners[1], BASE, PAGE));
	for (unsigned int i = 0U; i < 129U; i++)
		assert(tables[1][i] == 0UL);
	fail_install = UINT_MAX;
	assert(finish(1U, id, call(1U, XSHM_MEM_ATTACH, id, BASE, 0UL)) == XSHM_SUCCESS);
	assert(finish(1U, id, call(1U, XSHM_MEM_DETACH, id, 0UL, 0UL)) == XSHM_SUCCESS);
	assert(xshm_memory_owner_busy(&owners[0])); /* Only the owner releases the lease. */
	assert(finish(0U, id, call(0U, XSHM_MEM_REVOKE, id, 0UL, 0UL)) == XSHM_SUCCESS);

	/* Endpoint generations prevent an unregistered peer or reused RD from
	 * attaching an old offer. An unattached offer does not pin that peer. */
	id = offer(1U);
	assert(!xshm_memory_owner_busy(&owners[1]));
	identities[1].endpoint += 100UL;
	assert(call(1U, XSHM_MEM_ATTACH, id, BASE, 0UL) == XSHM_ERROR_INPUT);
	assert(call(1U, XSHM_MEM_STATUS, id, 0UL, 0UL) == XSHM_ERROR_INPUT);
	assert(call(1U, XSHM_MEM_DESCRIBE, id, 0UL, 0UL) == XSHM_ERROR_INPUT);
	assert(call(0U, XSHM_MEM_REVOKE, id, 0UL, 0UL) == XSHM_SUCCESS);

	/* Per-provider quotas and global exhaustion preserve existing grants. */
	for (unsigned int provider = 0U; provider < 8U; provider++) {
		unsigned int owner = provider == 0U ? 0U : provider + 1U;

		for (unsigned int i = 0U; i < XSHM_MEMORY_PER_OWNER; i++) {
			assert(call(owner, XSHM_MEM_OFFER, 100UL,
				BASE + i * PAGE, PAGE) == XSHM_SUCCESS);
			ids[provider * XSHM_MEMORY_PER_OWNER + i] = output[0];
		}
		assert(call(owner, XSHM_MEM_OFFER, 100UL,
			BASE + 32UL * PAGE, PAGE) == XSHM_FULL);
		assert(output[0] == 0UL);
	}
	assert(call(9U, XSHM_MEM_OFFER, 100UL, BASE, PAGE) == XSHM_FULL);
	for (unsigned int provider = 0U; provider < 8U; provider++) {
		unsigned int owner = provider == 0U ? 0U : provider + 1U;

		for (unsigned int i = 0U; i < XSHM_MEMORY_PER_OWNER; i++)
			assert(call(owner, XSHM_MEM_REVOKE,
				ids[provider * XSHM_MEMORY_PER_OWNER + i],
				0UL, 0UL) == XSHM_SUCCESS);
	}

	test_service();

	/* On an unexpected restore failure all pins remain quarantined. */
	id = offer(1U);
	assert(finish(1U, id, call(1U, XSHM_MEM_ATTACH, id, BASE, 0UL)) == XSHM_SUCCESS);
	fail_restore = true;
	assert(call(0U, XSHM_MEM_REVOKE, id, 0UL, 0UL) == XSHM_ERROR_STATE);
	assert(call(1U, XSHM_MEM_STATUS, id, 0UL, 0UL) == XSHM_SUCCESS);
	assert(output[1] == XSHM_MEMORY_QUARANTINED);
	assert(xshm_memory_owner_busy(&owners[0]));
	assert(xshm_memory_owner_busy(&owners[1]));
	assert(xshm_memory_range_busy(&owners[0], BASE, PAGE));
	assert(xshm_memory_range_busy(&owners[1], BASE, PAGE));
	assert(call(1U, XSHM_MEM_DETACH, id, 0UL, 0UL) == XSHM_ERROR_STATE);
	puts("XSHM_MEMORY_POLICY_TEST=PASS");
	return 0;
}
