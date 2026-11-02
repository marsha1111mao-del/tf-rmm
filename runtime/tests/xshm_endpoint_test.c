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
CHECK_COMMAND(NOTIFY_TIMED);
CHECK_COMMAND(RESIDENT_BIND);
CHECK_COMMAND(RESIDENT_STATS);
CHECK_COMMAND(FAST_IRQ_BIND);
CHECK_COMMAND(FAST_IRQ_STATS);
_Static_assert(XSHM_CAP_FAST_IRQ == REALM_XSHM_CAP_FAST_IRQ, "fast IRQ ABI");
_Static_assert(XSHM_CAP_RESIDENT_WAKE == REALM_XSHM_CAP_RESIDENT_WAKE, "resident ABI");
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

static void test_resident_request_wake(void)
{
	unsigned long channel, mpidr;

	assert(call(0U, XSHM_REGISTER, 0UL, 0UL) == XSHM_SUCCESS);
	assert(call(1U, XSHM_REGISTER, 0UL, 0UL) == XSHM_SUCCESS);
	assert(call(0U, XSHM_OFFER, output[1], 0UL) == XSHM_SUCCESS);
	channel = output[0];
	assert(call(1U, XSHM_ACCEPT, channel, 0UL) == XSHM_SUCCESS);
	assert(call(1U, XSHM_RESIDENT_BIND, 1UL, 0UL) == XSHM_ERROR_INPUT);
	assert(call(1U, XSHM_IRQ_BIND, 0UL, 0UL) == XSHM_SUCCESS);
	assert(call(0U, XSHM_IRQ_BIND, 0UL, 0UL) == XSHM_SUCCESS);
	xshm_endpoint_resident_enter(&owners[1], 0x100UL);
	assert(!xshm_endpoint_resident_target(&owners[1], &mpidr));
	assert(call(1U, XSHM_RESIDENT_BIND, 2UL, 0UL) == XSHM_ERROR_INPUT);
	assert(call(1U, XSHM_RESIDENT_BIND, 1UL, 1UL) == XSHM_ERROR_INPUT);
	assert(call(1U, XSHM_RESIDENT_BIND, 1UL, 0UL) == XSHM_SUCCESS);
	xshm_endpoint_resident_enter(&owners[1], 0x100UL);
	assert(!xshm_endpoint_resident_target(&owners[1], &mpidr));
	assert(call(1U, XSHM_ACK_ARM, channel, 0UL) == XSHM_SUCCESS);
	assert(call(0U, XSHM_NOTIFY, channel, 0UL) == XSHM_SUCCESS);
	assert(xshm_endpoint_resident_target(&owners[1], &mpidr));
	assert(mpidr == 0x100UL);
	assert(!xshm_endpoint_resident_target(&owners[1], NULL));
	xshm_endpoint_wake_record(&owners[1], true);
	assert(xshm_endpoint_resident_leave(&owners[1], true));
	assert(!xshm_endpoint_resident_target(&owners[1], &mpidr));
	assert(xshm_endpoint_irq_take(&owners[1]));
	assert(!xshm_endpoint_irq_take(&owners[1]));
	xshm_endpoint_resident_enter(&owners[1], 0x200UL);
	assert(call(1U, XSHM_ACK_ARM, channel, 0UL) == XSHM_SUCCESS);
	assert(!xshm_endpoint_resident_leave(&owners[1], true));
	assert(call(0U, XSHM_NOTIFY, channel, 0UL) == XSHM_SUCCESS);
	assert(!xshm_endpoint_resident_target(&owners[1], &mpidr));
	xshm_endpoint_wake_record(&owners[1], false);
	xshm_endpoint_resident_enter(&owners[1], 0x200UL);
	assert(xshm_endpoint_resident_target(&owners[1], &mpidr));
	assert(mpidr == 0x200UL);
	assert(!xshm_endpoint_resident_leave(&owners[1], false));
	assert(xshm_endpoint_irq_take(&owners[1]));
	assert(call(1U, XSHM_RESIDENT_STATS, 0UL, 0UL) == XSHM_SUCCESS);
	assert(output[0] == 1UL && output[1] == 1UL && output[2] == 1UL && output[3] == 1UL);
	assert(call(0U, XSHM_ACK_ARM, channel, 0UL) == XSHM_SUCCESS);
	xshm_endpoint_resident_enter(&owners[0], 0x300UL);
	assert(call(1U, XSHM_NOTIFY, channel, 0UL) == XSHM_SUCCESS);
	assert(!xshm_endpoint_resident_target(&owners[0], &mpidr));
	assert(!xshm_endpoint_resident_leave(&owners[0], true));
	assert(xshm_endpoint_irq_take(&owners[0]));
	assert(call(1U, XSHM_RESIDENT_BIND, 0UL, 0UL) == XSHM_SUCCESS);
	xshm_endpoint_resident_enter(&owners[1], 0x400UL);
	assert(!xshm_endpoint_resident_target(&owners[1], &mpidr));
	assert(call(1U, XSHM_RESIDENT_STATS, 1UL, 0UL) == XSHM_ERROR_INPUT);
	xshm_endpoint_release(&owners[1]);
	assert(!xshm_endpoint_resident_leave(&owners[1], true));
	assert(call(1U, XSHM_REGISTER, 0UL, 0UL) == XSHM_SUCCESS);
	assert(call(1U, XSHM_RESIDENT_STATS, 0UL, 0UL) == XSHM_SUCCESS);
	assert((output[0] | output[1] | output[2] | output[3]) == 0UL);
	assert(!xshm_endpoint_resident_leave(NULL, true));
	xshm_endpoint_release(&owners[0]);
	xshm_endpoint_release(&owners[1]);
	puts("XSHM_RESIDENT_REQUEST_WAKE_TEST=PASS");
}

static void test_fast_irq(void)
{
	unsigned long channel;

	assert(call(0U, XSHM_REGISTER, 0UL, 0UL) == XSHM_SUCCESS);
	assert(call(1U, XSHM_REGISTER, 0UL, 0UL) == XSHM_SUCCESS);
	assert(call(0U, XSHM_OFFER, output[1], 0UL) == XSHM_SUCCESS);
	channel = output[0];
	assert(call(1U, XSHM_ACCEPT, channel, 0UL) == XSHM_SUCCESS);
	assert(call(1U, XSHM_FAST_IRQ_BIND, 1UL, 0UL) == XSHM_ERROR_INPUT);
	assert(call(1U, XSHM_IRQ_BIND, 0UL, 0UL) == XSHM_SUCCESS);
	assert(call(1U, XSHM_FAST_IRQ_BIND, 1UL, 0UL) == XSHM_ERROR_INPUT);
	assert(call(1U, XSHM_RESIDENT_BIND, 1UL, 0UL) == XSHM_SUCCESS);
	assert(call(1U, XSHM_FAST_IRQ_BIND, 2UL, 0UL) == XSHM_ERROR_INPUT);
	assert(call(1U, XSHM_FAST_IRQ_BIND, 1UL, 1UL) == XSHM_ERROR_INPUT);
	assert(call(1U, XSHM_FAST_IRQ_BIND, 1UL, 0UL) == XSHM_SUCCESS);
	assert(!xshm_endpoint_fast_irq_enabled(NULL));
	assert(!xshm_endpoint_fast_irq_enabled(&owners[0]));
	assert(!xshm_endpoint_fast_irq_take(&owners[1], 0x100UL));
	xshm_endpoint_resident_enter(&owners[1], 0x100UL);
	assert(!xshm_endpoint_fast_irq_take(&owners[1], 0x100UL));
	for (unsigned int iteration = 0U; iteration < 10000U; iteration++) {
		assert(call(1U, XSHM_ACK_ARM, channel, 0UL) == XSHM_SUCCESS);
		assert(call(0U, XSHM_NOTIFY, channel, 0UL) == XSHM_SUCCESS);
		assert(!xshm_endpoint_fast_irq_take(&owners[0], 0x100UL));
		assert(!xshm_endpoint_fast_irq_take(&owners[1], 0x200UL));
		assert(!xshm_endpoint_fast_irq_pending(&owners[0], 0x100UL));
		assert(!xshm_endpoint_fast_irq_pending(&owners[1], 0x200UL));
		assert(xshm_endpoint_fast_irq_pending(&owners[1], 0x100UL));
		assert(xshm_endpoint_fast_irq_pending(&owners[1], 0x100UL));
		assert(xshm_endpoint_fast_irq_take(&owners[1], 0x100UL));
		assert(!xshm_endpoint_fast_irq_pending(&owners[1], 0x100UL));
		assert(!xshm_endpoint_fast_irq_take(&owners[1], 0x100UL));
		assert(!xshm_endpoint_irq_take(&owners[1]));
		assert(call(1U, XSHM_QUERY, channel, 0UL) == XSHM_SUCCESS);
		assert(output[0] == iteration + 1UL && output[1] == iteration);
	}
	assert(call(1U, XSHM_FAST_IRQ_STATS, 0UL, 0UL) == XSHM_SUCCESS);
	assert(output[0] == 10000UL && output[1] == 1UL);
	assert(call(1U, XSHM_ACK_ARM, channel, 0UL) == XSHM_SUCCESS);
	assert(call(0U, XSHM_NOTIFY, channel, 0UL) == XSHM_SUCCESS);
	assert(call(1U, XSHM_FAST_IRQ_BIND, 0UL, 0UL) == XSHM_SUCCESS);
	assert(!xshm_endpoint_fast_irq_take(&owners[1], 0x100UL));
	assert(call(1U, XSHM_FAST_IRQ_BIND, 1UL, 0UL) == XSHM_SUCCESS);
	assert(xshm_endpoint_resident_leave(&owners[1], true));
	assert(!xshm_endpoint_fast_irq_take(&owners[1], 0x100UL));
	xshm_endpoint_resident_enter(&owners[1], 0x200UL);
	assert(!xshm_endpoint_fast_irq_take(&owners[1], 0x100UL));
	assert(xshm_endpoint_fast_irq_take(&owners[1], 0x200UL));
	assert(call(1U, XSHM_ACK_ARM, channel, 0UL) == XSHM_SUCCESS);
	assert(call(0U, XSHM_NOTIFY, channel, 0UL) == XSHM_SUCCESS);
	assert(call(1U, XSHM_RESIDENT_BIND, 0UL, 0UL) == XSHM_SUCCESS);
	assert(!xshm_endpoint_fast_irq_enabled(&owners[1]));
	assert(!xshm_endpoint_fast_irq_take(&owners[1], 0x200UL));
	assert(xshm_endpoint_irq_take(&owners[1]));
	assert(call(1U, XSHM_FAST_IRQ_STATS, 1UL, 0UL) == XSHM_ERROR_INPUT);
	xshm_endpoint_release(&owners[1]);
	assert(!xshm_endpoint_fast_irq_take(&owners[1], 0x200UL));
	assert(call(1U, XSHM_REGISTER, 0UL, 0UL) == XSHM_SUCCESS);
	assert(call(1U, XSHM_FAST_IRQ_STATS, 0UL, 0UL) == XSHM_SUCCESS);
	assert(output[0] == 0UL && output[1] == 0UL);
	xshm_endpoint_release(&owners[0]);
	xshm_endpoint_release(&owners[1]);
	puts("XSHM_FAST_IRQ_POLICY_TEST=PASS");
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
	test_resident_request_wake();
	test_fast_irq();
	puts("XSHM_ENDPOINT_POLICY_TEST=PASS");
	return 0;
}
