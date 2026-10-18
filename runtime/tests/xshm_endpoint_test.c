/* SPDX-License-Identifier: BSD-3-Clause */
/* Native policy tests: no mock GPU or claim of hardware Realm protection. */
#include <assert.h>
#include <stdio.h>
#include <xshm_endpoint.h>
#include <xshm_memory.h>
#include "linux/realm_xshm.h"

/* The kernel frontend and RMM are built separately; detect ABI drift here. */
#define CHECK_COMMAND(name) \
	_Static_assert(XSHM_##name == REALM_XSHM_##name, "command ABI: " #name)
CHECK_COMMAND(REGISTER);
CHECK_COMMAND(OFFER);
CHECK_COMMAND(ACCEPT);
CHECK_COMMAND(CLOSE);
CHECK_COMMAND(NOTIFY);
CHECK_COMMAND(ARM);
CHECK_COMMAND(ACK);
CHECK_COMMAND(QUERY);
CHECK_COMMAND(UNREGISTER);
CHECK_COMMAND(MEM_OFFER);
CHECK_COMMAND(MEM_ATTACH);
CHECK_COMMAND(MEM_DETACH);
CHECK_COMMAND(MEM_REVOKE);
CHECK_COMMAND(MEM_STATUS);
CHECK_COMMAND(MEM_CONTINUE);
CHECK_COMMAND(MEM_DESCRIBE);
CHECK_COMMAND(IRQ_BIND);
CHECK_COMMAND(ACK_ARM);
_Static_assert(XSHM_MEMORY_ACTIVE == REALM_XSHM_MEMORY_ACTIVE, "active state ABI");
_Static_assert(sizeof(struct realm_xshm_pool) == 48U, "pool ioctl ABI");
_Static_assert(sizeof(struct realm_xshm_call) == 72U, "Guest ioctl ABI");

static unsigned char owners[XSHM_MAX_ENDPOINTS + 4U];
static unsigned long output[4];

static unsigned long call(unsigned int owner, unsigned long command,
			  unsigned long id, unsigned long sequence)
{
	return xshm_endpoint_call(&owners[owner], command, id, sequence, output);
}

int main(void)
{
	unsigned long a, b, c, channel, replacement, seen;

	assert(call(0U, XSHM_REGISTER, 0UL, 0UL) == XSHM_SUCCESS);
	a = output[1];
	assert(output[0] == XSHM_ABI_VERSION);
	assert(output[2] == (XSHM_CAP_ENDPOINT | XSHM_CAP_EVENT_STATE));
	assert(call(1U, XSHM_REGISTER, 0UL, 0UL) == XSHM_SUCCESS);
	b = output[1];
	assert(call(2U, XSHM_REGISTER, 0UL, 0UL) == XSHM_SUCCESS);
	c = output[1];
	assert((a != b) && (b != c) && (a != c));
	assert(call(0U, XSHM_REGISTER, 0UL, 0UL) == XSHM_SUCCESS);
	assert(output[1] == a);
	assert(call(0U, XSHM_OFFER, a, 0UL) == XSHM_ERROR_INPUT);
	assert(call(0U, XSHM_OFFER, b, 0UL) == XSHM_SUCCESS);
	channel = output[0];
	assert(call(0U, XSHM_NOTIFY, channel, 0UL) == XSHM_ERROR_STATE);
	assert(call(0U, XSHM_ACCEPT, channel, 0UL) == XSHM_ERROR_INPUT);
	assert(call(2U, XSHM_ACCEPT, channel, 0UL) == XSHM_ERROR_INPUT);
	assert(call(2U, XSHM_CLOSE, channel, 0UL) == XSHM_ERROR_INPUT);
	assert(call(1U, XSHM_ACCEPT, channel, 0UL) == XSHM_SUCCESS);

	assert(call(1U, XSHM_IRQ_BIND, 1UL, 0UL) == XSHM_ERROR_INPUT);
	assert(call(1U, XSHM_IRQ_BIND, 0UL, 1UL) == XSHM_ERROR_INPUT);
	assert(call(1U, XSHM_IRQ_BIND, 0UL, 0UL) == XSHM_SUCCESS);
	assert(output[0] == REALM_XSHM_IRQ_INTID);
	assert(!xshm_endpoint_irq_take(&owners[1]));
	/* Notify after ARM wakes once; further events are coalesced but retained. */
	assert(call(1U, XSHM_ARM, channel, 0UL) == XSHM_SUCCESS);
	assert((output[2] & XSHM_EVENT_ARMED) != 0UL);
	assert(call(0U, XSHM_NOTIFY, channel, 0UL) == XSHM_SUCCESS);
	assert((output[0] == 1UL) && (output[1] == b) && (output[2] == 1UL));
	assert(call(0U, XSHM_NOTIFY, channel, 0UL) == XSHM_SUCCESS);
	assert((output[0] == 2UL) && (output[2] == 0UL));
	assert(xshm_endpoint_irq_take(&owners[1]));
	assert(!xshm_endpoint_irq_take(&owners[1]));
	assert(!xshm_endpoint_irq_take(&owners[0]));
	assert(call(2U, XSHM_NOTIFY, channel, 0UL) == XSHM_ERROR_INPUT);
	assert(!xshm_endpoint_irq_take(&owners[1]));
	assert(call(2U, XSHM_ACK, channel, 2UL) == XSHM_ERROR_INPUT);
	assert(call(1U, XSHM_QUERY, channel, 0UL) == XSHM_SUCCESS);
	assert((output[0] == 2UL) && (output[1] == 0UL));
	assert(call(1U, XSHM_ACK, channel, 3UL) == XSHM_ERROR_INPUT);
	assert(call(1U, XSHM_ARM, channel, 2UL) == XSHM_ERROR_INPUT);
	assert(call(1U, XSHM_ACK, channel, 1UL) == XSHM_SUCCESS);
	assert(call(1U, XSHM_ARM, channel, 1UL) == XSHM_SUCCESS);
	assert((output[0] == 2UL) && ((output[2] & XSHM_EVENT_ARMED) == 0UL));
	assert(call(1U, XSHM_ACK, channel, 2UL) == XSHM_SUCCESS);
	assert(call(1U, XSHM_ARM, channel, 2UL) == XSHM_SUCCESS);
	assert(call(1U, XSHM_ACK, channel, 1UL) == XSHM_ERROR_INPUT);

	/* Exercise the event-arrives-between-query/ACK/ARM interleaving repeatedly. */
	for (unsigned int i = 0U; i < 10000U; i++) {
		assert(call(1U, XSHM_QUERY, channel, 0UL) == XSHM_SUCCESS);
		seen = output[0];
		assert(call(0U, XSHM_NOTIFY, channel, 0UL) == XSHM_SUCCESS);
		assert(call(1U, XSHM_ACK, channel, seen) == XSHM_SUCCESS);
		assert(call(1U, XSHM_ARM, channel, seen) == XSHM_SUCCESS);
		assert((output[0] == seen + 1UL) &&
		       ((output[2] & XSHM_EVENT_ARMED) == 0UL));
		assert(call(1U, XSHM_ACK, channel, seen + 1UL) == XSHM_SUCCESS);
		assert(call(1U, XSHM_ARM, channel, seen + 1UL) == XSHM_SUCCESS);
	}
	assert(call(1U, XSHM_QUERY, channel, 0UL) == XSHM_SUCCESS);
	assert((output[0] == 10002UL) && (output[1] == 10002UL));
	assert(call(0U, XSHM_QUERY, channel, 0UL) == XSHM_SUCCESS);
	assert((output[0] == 0UL) && (output[1] == 0UL));
	/* Atomic rearm cannot be used by a nonparticipant. Events arriving
	 * before it remain represented by queued data (consumer rechecks),
	 * while events arriving after it must generate a fresh wakeup.
	 */
	assert(call(2U, XSHM_ACK_ARM, channel, 0UL) == XSHM_ERROR_INPUT);
	assert(call(1U, XSHM_ACK_ARM, channel, 1UL) == XSHM_ERROR_INPUT);
	for (unsigned int i = 0U; i < 10000U; i++) {
		assert(call(0U, XSHM_NOTIFY, channel, 0UL) == XSHM_SUCCESS);
		assert(call(1U, XSHM_ACK_ARM, channel, 0UL) == XSHM_SUCCESS);
		assert(output[0] == output[1]);
		assert(output[2] & XSHM_EVENT_ARMED);
		(void)xshm_endpoint_irq_take(&owners[1]);
		assert(call(0U, XSHM_NOTIFY, channel, 0UL) == XSHM_SUCCESS);
		assert(output[2] == 1UL);
		assert(xshm_endpoint_irq_take(&owners[1]));
		assert(call(1U, XSHM_QUERY, channel, 0UL) == XSHM_SUCCESS);
		assert(output[0] == output[1] + 1UL);
	}

	/* Teardown closes bindings before an RD address can be recycled. */
	xshm_endpoint_release(&owners[1]);
	assert(call(0U, XSHM_QUERY, channel, 0UL) == XSHM_ERROR_STATE);
	assert(call(1U, XSHM_REGISTER, 0UL, 0UL) == XSHM_SUCCESS);
	replacement = output[1];
	assert(replacement != b);
	assert(call(0U, XSHM_OFFER, b, 0UL) == XSHM_ERROR_INPUT);
	assert(call(0U, XSHM_OFFER, replacement, 0UL) == XSHM_SUCCESS);
	assert(output[0] != channel);
	channel = output[0];
	assert(call(1U, XSHM_ACCEPT, channel, 0UL) == XSHM_SUCCESS);
	assert(output[0] == 0UL);
	assert(call(1U, XSHM_CLOSE, channel, 0UL) == XSHM_SUCCESS);
	assert((output[1] == a) && (output[2] == 1UL));
	assert(call(0U, XSHM_NOTIFY, channel, 0UL) == XSHM_ERROR_STATE);

	/* Capacity failures leave existing identities and channels intact. */
	for (unsigned int i = 3U; i < XSHM_MAX_ENDPOINTS; i++)
		assert(call(i, XSHM_REGISTER, 0UL, 0UL) == XSHM_SUCCESS);
	assert(call(XSHM_MAX_ENDPOINTS, XSHM_REGISTER, 0UL, 0UL) == XSHM_FULL);
	for (unsigned int i = 0U; i < XSHM_MAX_CHANNELS; i++)
		assert(call(0U, XSHM_OFFER, replacement, 0UL) == XSHM_SUCCESS);
	assert(call(0U, XSHM_OFFER, replacement, 0UL) == XSHM_FULL);
	assert(call(0U, XSHM_REGISTER, 0UL, 0UL) == XSHM_SUCCESS);
	assert(output[1] == a);
	for (unsigned int i = 0U; i < XSHM_MAX_ENDPOINTS; i++)
		xshm_endpoint_release(&owners[i]);
	assert(call(0U, XSHM_QUERY, channel, 0UL) == XSHM_ERROR_STATE);
	assert(xshm_endpoint_call(NULL, XSHM_REGISTER, 0UL, 0UL, output) == XSHM_ERROR_INPUT);
	puts("XSHM_ENDPOINT_POLICY_TEST=PASS");
	return 0;
}
