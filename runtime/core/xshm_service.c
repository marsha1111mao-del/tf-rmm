/* SPDX-License-Identifier: BSD-3-Clause */
#include <xshm_endpoint.h>
#include <xshm_service.h>

unsigned long xshm_service_call(const struct xshm_memory_ops *ops,
		const void *owner, unsigned long command, unsigned long id,
		unsigned long argument, unsigned long size, unsigned long output[4])
{
	unsigned long status;

	if (output == NULL)
		return XSHM_ERROR_INPUT;
	for (unsigned int i = 0U; i < 4U; i++)
		output[i] = 0UL;
	if (command >= XSHM_MEM_OFFER && command != XSHM_IRQ_BIND &&
	    command != XSHM_ACK_ARM) {
		struct xshm_memory_identity caller = {
			.owner = owner,
			.endpoint = xshm_endpoint_id(owner),
		};
		struct xshm_memory_identity peer = {0};

		if (command == XSHM_MEM_OFFER || command == XSHM_MEM_ATTACH) {
			unsigned long channel = command == XSHM_MEM_OFFER ? id :
				xshm_memory_channel(&caller, id);

			peer.owner = xshm_endpoint_peer(owner, channel, &peer.endpoint);
		}
		return xshm_memory_call(ops, &caller, &peer, command, id,
					argument, size, output);
	}
	if (size != 0UL)
		return XSHM_ERROR_INPUT;
	if ((command == XSHM_UNREGISTER && xshm_memory_owner_busy(owner)) ||
	    (command == XSHM_CLOSE && xshm_memory_channel_busy(owner, id)))
		return XSHM_ERROR_STATE;
	status = xshm_endpoint_call(owner, command, id, argument, output);
	if (command == XSHM_REGISTER && status == XSHM_SUCCESS && ops != NULL)
		output[2] |= XSHM_CAP_MEMORY | XSHM_CAP_MEMORY_IDENTITY |
			     XSHM_CAP_EVENT_IRQ | XSHM_CAP_ACK_ARM;
	return status;
}
