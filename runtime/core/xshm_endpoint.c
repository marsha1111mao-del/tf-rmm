/* SPDX-License-Identifier: BSD-3-Clause */
#include <limits.h>
#include <stdbool.h>
#include <xshm_endpoint.h>
#include <xshm_irq.h>

struct xshm_endpoint {
	const void *owner;
	unsigned long id;
	bool irq_enabled;
	bool irq_pending;
};

struct xshm_event {
	unsigned long pending;
	unsigned long acknowledged;
	bool armed;
};

struct xshm_channel {
	unsigned long id;
	unsigned long endpoint[2];
	struct xshm_event event[2];
	bool live;
};

static struct xshm_endpoint endpoints[XSHM_MAX_ENDPOINTS];
static struct xshm_channel channels[XSHM_MAX_CHANNELS];
static unsigned long next_endpoint_id;
static unsigned long next_channel_id;

static struct xshm_endpoint *endpoint_by_owner(const void *owner)
{
	for (unsigned int i = 0U; i < XSHM_MAX_ENDPOINTS; i++) {
		if (endpoints[i].owner == owner)
			return &endpoints[i];
	}
	return NULL;
}

unsigned long xshm_endpoint_id(const void *owner)
{
	struct xshm_endpoint *endpoint = owner == NULL ? NULL : endpoint_by_owner(owner);

	return endpoint == NULL ? 0UL : endpoint->id;
}

const void *xshm_endpoint_peer(const void *owner, unsigned long id,
			     unsigned long *peer_id)
{
	unsigned long own_id = xshm_endpoint_id(owner);

	*peer_id = 0UL;
	if (own_id == 0UL || id == 0UL)
		return NULL;
	for (unsigned int i = 0U; i < XSHM_MAX_CHANNELS; i++) {
		const struct xshm_channel *channel = &channels[i];
		unsigned long peer;

		if (channel->id != id || !channel->live)
			continue;
		if (channel->endpoint[0] == own_id)
			peer = channel->endpoint[1];
		else if (channel->endpoint[1] == own_id)
			peer = channel->endpoint[0];
		else
			return NULL;
		for (unsigned int j = 0U; j < XSHM_MAX_ENDPOINTS; j++) {
			if (endpoints[j].id == peer) {
				*peer_id = peer;
				return endpoints[j].owner;
			}
		}
	}
	return NULL;
}

bool xshm_endpoint_irq_enabled(const void *owner)
{
	struct xshm_endpoint *ep = owner == NULL ? NULL : endpoint_by_owner(owner);

	return ep != NULL && ep->irq_enabled;
}

bool xshm_endpoint_irq_take(const void *owner)
{
	struct xshm_endpoint *ep = owner == NULL ? NULL : endpoint_by_owner(owner);
	bool pending = ep != NULL && ep->irq_enabled && ep->irq_pending;

	if (ep != NULL)
		ep->irq_pending = false;
	return pending;
}

static void irq_mark(unsigned long id)
{
	for (unsigned int i = 0U; i < XSHM_MAX_ENDPOINTS; i++) {
		if (endpoints[i].id == id && endpoints[i].irq_enabled) {
			endpoints[i].irq_pending = true;
			return;
		}
	}
}

static bool endpoint_exists(unsigned long id)
{
	for (unsigned int i = 0U; i < XSHM_MAX_ENDPOINTS; i++) {
		if (endpoints[i].id == id)
			return true;
	}
	return false;
}

void xshm_endpoint_release(const void *owner)
{
	struct xshm_endpoint *endpoint;

	if (owner == NULL)
		return;
	endpoint = endpoint_by_owner(owner);
	if (endpoint == NULL)
		return;
	for (unsigned int i = 0U; i < XSHM_MAX_CHANNELS; i++) {
		if ((channels[i].endpoint[0] == endpoint->id) ||
		    (channels[i].endpoint[1] == endpoint->id))
			channels[i] = (struct xshm_channel){0};
	}
	*endpoint = (struct xshm_endpoint){0};
}

static unsigned long register_endpoint(const void *owner,
				       unsigned long output[4])
{
	struct xshm_endpoint *endpoint = endpoint_by_owner(owner);

	if (endpoint == NULL) {
		if (next_endpoint_id == ULONG_MAX)
			return XSHM_ERROR_STATE;
		for (unsigned int i = 0U; i < XSHM_MAX_ENDPOINTS; i++) {
			if (endpoints[i].owner == NULL) {
				endpoint = &endpoints[i];
				endpoint->owner = owner;
				endpoint->id = ++next_endpoint_id;
				break;
			}
		}
		if (endpoint == NULL)
			return XSHM_FULL;
	}
	output[0] = XSHM_ABI_VERSION;
	output[1] = endpoint->id;
	output[2] = XSHM_CAP_ENDPOINT | XSHM_CAP_EVENT_STATE;
	output[3] = XSHM_MAX_CHANNELS;
	return XSHM_SUCCESS;
}

static unsigned long offer_channel(const struct xshm_endpoint *owner,
				   unsigned long peer, unsigned long output[4])
{
	if ((peer == 0UL) || (peer == owner->id) || !endpoint_exists(peer))
		return XSHM_ERROR_INPUT;
	if (next_channel_id == ULONG_MAX)
		return XSHM_ERROR_STATE;
	for (unsigned int i = 0U; i < XSHM_MAX_CHANNELS; i++) {
		struct xshm_channel *channel = &channels[i];

		if (channel->id != 0UL)
			continue;
		*channel = (struct xshm_channel){0};
		channel->id = ++next_channel_id;
		channel->endpoint[0] = owner->id;
		channel->endpoint[1] = peer;
		output[0] = channel->id;
		output[1] = peer;
		return XSHM_SUCCESS;
	}
	return XSHM_FULL;
}

static void event_snapshot(const struct xshm_channel *channel,
			   unsigned int side, unsigned long output[4])
{
	const struct xshm_event *event = &channel->event[side];

	output[0] = event->pending;
	output[1] = event->acknowledged;
	output[2] = (channel->live ? XSHM_EVENT_LIVE : 0UL) |
		    (event->armed ? XSHM_EVENT_ARMED : 0UL);
	output[3] = channel->endpoint[side ^ 1U];
}

unsigned long xshm_endpoint_call(const void *owner, unsigned long command,
				 unsigned long id, unsigned long sequence,
				 unsigned long output[4])
{
	struct xshm_endpoint *endpoint;
	struct xshm_channel *channel = NULL;
	struct xshm_event *event;
	unsigned int side;

	if (output == NULL)
		return XSHM_ERROR_INPUT;
	for (unsigned int i = 0U; i < 4U; i++)
		output[i] = 0UL;
	if ((owner == NULL) || ((command > XSHM_UNREGISTER) &&
	    (command != XSHM_IRQ_BIND) && (command != XSHM_ACK_ARM)) ||
	    (((command != XSHM_ARM) && (command != XSHM_ACK)) &&
	     (sequence != 0UL)))
		return XSHM_ERROR_INPUT;
	if (command == XSHM_REGISTER)
		return (id == 0UL) ? register_endpoint(owner, output) : XSHM_ERROR_INPUT;
	endpoint = endpoint_by_owner(owner);
	if (endpoint == NULL)
		return XSHM_ERROR_STATE;
	if (command == XSHM_IRQ_BIND) {
		if (id != 0UL)
			return XSHM_ERROR_INPUT;
		endpoint->irq_enabled = true;
		output[0] = XSHM_IRQ_INTID;
		return XSHM_SUCCESS;
	}
	if (command == XSHM_UNREGISTER) {
		if (id != 0UL)
			return XSHM_ERROR_INPUT;
		xshm_endpoint_release(owner);
		return XSHM_SUCCESS;
	}
	if (command == XSHM_OFFER)
		return offer_channel(endpoint, id, output);
	if (id == 0UL)
		return XSHM_ERROR_INPUT;
	for (unsigned int i = 0U; i < XSHM_MAX_CHANNELS; i++) {
		if (channels[i].id == id) {
			channel = &channels[i];
			break;
		}
	}
	if (channel == NULL)
		return XSHM_ERROR_STATE;
	if (channel->endpoint[0] == endpoint->id)
		side = 0U;
	else if (channel->endpoint[1] == endpoint->id)
		side = 1U;
	else
		return XSHM_ERROR_INPUT;

	if (command == XSHM_ACCEPT) {
		if (side != 1U)
			return XSHM_ERROR_INPUT;
		channel->live = true;
		event_snapshot(channel, side, output);
		return XSHM_SUCCESS;
	}
	if (command == XSHM_CLOSE) {
		/* The receiver must recheck channel state after a terminal wake. */
		output[1] = channel->endpoint[side ^ 1U];
		output[2] = 1UL;
		irq_mark(channel->endpoint[side ^ 1U]);
		*channel = (struct xshm_channel){0};
		return XSHM_SUCCESS;
	}
	if (!channel->live)
		return XSHM_ERROR_STATE;
	event = &channel->event[side];
	switch (command) {
	case XSHM_NOTIFY:
		event = &channel->event[side ^ 1U];
		if (event->pending == ULONG_MAX)
			return XSHM_ERROR_STATE;
		event->pending++;
		output[0] = event->pending;
		output[1] = channel->endpoint[side ^ 1U];
		/* Only a transition from an armed wait requires a wake hint.
		 * The event remains pending even if that hint is lost.
		 */
		output[2] = event->armed ? 1UL : 0UL;
		if (event->armed)
			irq_mark(channel->endpoint[side ^ 1U]);
		event->armed = false;
		break;
	case XSHM_ARM:
		if ((sequence > event->pending) || (sequence > event->acknowledged))
			return XSHM_ERROR_INPUT;
		event->armed = sequence == event->pending;
		event_snapshot(channel, side, output);
		break;
	case XSHM_ACK:
		if ((sequence < event->acknowledged) || (sequence > event->pending))
			return XSHM_ERROR_INPUT;
		event->acknowledged = sequence;
		event_snapshot(channel, side, output);
		break;
	case XSHM_ACK_ARM:
		/* Only this authenticated receiver's event is changed. Queue data
		 * is not consumed here. A receiver must recheck its queue after
		 * arming: an event predating this call may already have queued data;
		 * a later NOTIFY sees armed and injects the trusted wakeup.
		 */
		event->acknowledged = event->pending;
		event->armed = true;
		event_snapshot(channel, side, output);
		break;
	case XSHM_QUERY:
		event_snapshot(channel, side, output);
		break;
	default:
		return XSHM_ERROR_INPUT;
	}
	return XSHM_SUCCESS;
}
