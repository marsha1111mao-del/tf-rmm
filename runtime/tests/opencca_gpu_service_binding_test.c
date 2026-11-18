/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <opencca_gpu.h>
#include <opencca_gpu_lease.h>
#include <stdio.h>
#include <xshm_endpoint.h>

static unsigned char service, client;
static unsigned int resets, revokes;

static bool reset(bool preserve_irqs)
{
	assert(!preserve_irqs);
	resets++;
	return true;
}

static bool revoke(const void *owner)
{
	assert(owner == &service);
	revokes++;
	return true;
}

static bool valid_opp(unsigned long frequency)
{
	return frequency == 600000000UL;
}

static const struct opencca_gpu_ops ops = {
	.reset = reset,
	.revoke_mmio = revoke,
	.opp_valid = valid_opp
};

static unsigned long register_endpoint(const void *owner)
{
	unsigned long output[4];

	assert(xshm_endpoint_call(owner, XSHM_REGISTER, 0UL, 0UL,
				 output) == XSHM_SUCCESS);
	return output[1];
}

int main(void)
{
	unsigned long output[4], client_id, service_id, fresh_id;
	unsigned long channel, fresh_channel, peer_id, page = 0x80000000UL;
	const void *peer;

	assert(opencca_gpu_control(&ops, NULL, OPENCCA_GPU_POWER_ON,
				   0UL, 0UL));
	assert(opencca_gpu_mmio_grant(&service));
	assert(!opencca_gpu_claim(&service, 0UL));
	assert(opencca_gpu_state() == OPENCCA_GPU_DESIGNATED);

	client_id = register_endpoint(&client);
	service_id = register_endpoint(&service);
	assert(client_id != 0UL && service_id != 0UL && client_id != service_id);
	assert(!opencca_gpu_service_running(&service, client_id));
	assert(opencca_gpu_claim(&service, service_id));
	assert(opencca_gpu_service_running(&service, service_id));
	assert(!opencca_gpu_service_running(&service, client_id));
	assert(!opencca_gpu_service_isolated(&service, client_id));
	assert(opencca_gpu_lease_acquire(&service, &page, 1U));
	assert(opencca_gpu_service_isolate(&ops, &service, service_id));
	assert(opencca_gpu_service_isolated(&service, service_id));
	assert(!opencca_gpu_service_isolated(&service, client_id));
	assert(opencca_gpu_lease_active() == 0U);

	assert(xshm_endpoint_call(&service, XSHM_OFFER, client_id, 0UL,
				  output) == XSHM_SUCCESS);
	channel = output[0];
	assert(xshm_endpoint_call(&client, XSHM_ACCEPT, channel, 0UL,
				  output) == XSHM_SUCCESS);
	peer = xshm_endpoint_peer(&client, channel, &peer_id);
	assert(peer == &service && peer_id == service_id);

	assert(xshm_endpoint_call(&service, XSHM_UNREGISTER, 0UL, 0UL,
				  output) == XSHM_SUCCESS);
	opencca_gpu_service_invalidate(&service);
	assert(xshm_endpoint_id(&service) == 0UL);
	assert(!opencca_gpu_service_running(&service, service_id));
	assert(!opencca_gpu_service_isolated(&service, service_id));
	assert(!opencca_gpu_service_isolate(&ops, &service, service_id));
	assert(!opencca_gpu_mmio_allowed(&service));
	assert(opencca_gpu_state() == OPENCCA_GPU_QUARANTINED);
	assert(xshm_endpoint_peer(&client, channel, &peer_id) == NULL &&
	       peer_id == 0UL);

	fresh_id = register_endpoint(&service);
	assert(fresh_id != service_id);
	assert(xshm_endpoint_call(&service, XSHM_OFFER, service_id, 0UL,
				  output) == XSHM_ERROR_INPUT);
	assert(!opencca_gpu_service_running(&service, fresh_id));
	assert(!opencca_gpu_service_isolated(&service, fresh_id));
	assert(!opencca_gpu_claim(&service, fresh_id));

	assert(opencca_gpu_control(&ops, NULL, OPENCCA_GPU_RELEASE,
				   0UL, 0UL));
	assert(opencca_gpu_pm_destroy_begin(&service));
	opencca_gpu_mmio_release(&service);
	assert(opencca_gpu_mmio_grant(&service));
	assert(opencca_gpu_claim(&service, fresh_id));
	assert(opencca_gpu_service_running(&service, fresh_id));
	assert(xshm_endpoint_peer(&client, channel, &peer_id) == NULL);

	assert(xshm_endpoint_call(&service, XSHM_OFFER, client_id, 0UL,
				  output) == XSHM_SUCCESS);
	fresh_channel = output[0];
	assert(xshm_endpoint_call(&client, XSHM_ACCEPT, fresh_channel, 0UL,
				  output) == XSHM_SUCCESS);
	peer = xshm_endpoint_peer(&client, fresh_channel, &peer_id);
	assert(peer == &service && peer_id == fresh_id);
	assert(opencca_gpu_service_isolate(&ops, &service, fresh_id));
	assert(opencca_gpu_service_isolated(&service, fresh_id));
	assert(resets >= 3U && revokes >= 3U);

	puts("GPU_SERVICE_BINDING=PASS registered endpoint claim, owner+generation checks, unregister/RD invalidation, fresh same-RD instance, old channel rejection; MODEL_ONLY");
	return 0;
}
