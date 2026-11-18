/* SPDX-License-Identifier: BSD-3-Clause */
/* Reuse the actual platform/core fixture, including the extracted production
 * RSI dispatcher. REC/RTT/channel/device adapters remain host models.
 */
#define main gpu_backend_existing_main
#include <stdlib.h>
#include "opencca_gpu_backend_test.c"
#undef main

int main(int argc, char **argv)
{
	struct gpu_private_result r, before, replay;
	unsigned long context, bo, token, sequence;
	unsigned long ipas[2] = { 0x100000UL, 0x101000UL };
	struct gpu_private_map_request request = {
		.request_id = 1UL, .iova = 0x200000UL, .count = 2UL,
		.prot = GPU_PRIVATE_READ | GPU_PRIVATE_WRITE
	};
	unsigned int scenario = argc == 2 ? (unsigned int)strtoul(argv[1], NULL, 0) : 99U;

	assert(scenario < 3U);
	initialize();
	assert(opencca_gpu_control(&device_ops, NULL, OPENCCA_GPU_POWER_ON, 0UL, 0UL));
	assert(opencca_gpu_mmio_grant(&service) &&
	       opencca_gpu_claim(&service, SERVICE_ENDPOINT));
	assert(opencca_gpu_service_isolate(&device_ops, &service,
					    SERVICE_ENDPOINT));
	domain_rsi_call(&client_a, GPU_PRIVATE_VERSION, 0, 0, 0, 0, 0, 0, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS && (r.value[1] & GPU_PRIVATE_CAP_MAP_TRANSACTION));
	domain_rsi_call(&client_a, GPU_PRIVATE_CONTEXT_CREATE, 7, 0, 0, 0, 0, 0, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	context = r.value[0];
	domain_rsi_call(&client_a, GPU_PRIVATE_BO_CREATE, 7, 8192, 3, 0, 0, 0, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	bo = request.object = r.value[0];
	/* This fixture's RSI adapter source callback is for donated service
	 * controls. Register ordinary Client data through its real core adapter. */
	gpu_private_bo_append(&private_ops, &client_a, bo, 0UL, ipas, 2U, &r);
	assert(r.status == GPU_PRIVATE_SUCCESS);
	unsigned int old_writes = writes;
	for (unsigned int caller = 0U; caller < 2U; caller++) {
		domain_rsi_call(caller ? (void *)&service : (void *)&client_b,
			GPU_PRIVATE_MAP_BEGIN, context, (uintptr_t)&request, 0, 0, 0, 0, &r);
		assert(r.status == GPU_PRIVATE_INPUT);
	}
	domain_input_fault = true;
	domain_rsi_call(&client_a, GPU_PRIVATE_MAP_BEGIN, context, (uintptr_t)&request, 0, 0, 0, 0, &r);
	assert(r.status == GPU_PRIVATE_INPUT);
	domain_input_fault = false;
	for (unsigned int reserved = 0U; reserved < 4U; reserved++) {
		unsigned long values[4] = {0};

		values[reserved] = 1UL;
		domain_rsi_call(&client_a, GPU_PRIVATE_MAP_BEGIN, context, (uintptr_t)&request,
			values[0], values[1], values[2], values[3], &r);
		assert(r.status == GPU_PRIVATE_INPUT);
	}
	domain_rsi_call(&client_a, GPU_PRIVATE_MAP_BEGIN, context, (uintptr_t)&request, 0, 0, 0, 0, &r);
	assert(r.status == GPU_PRIVATE_INCOMPLETE && r.value[3] == GPU_PRIVATE_MAP_RESERVE);
	token = r.value[0];
	before = r;
	/* Changing the original source does not change the trusted transaction. */
	request.iova = 0x600000UL;
	domain_rsi_call(&client_a, GPU_PRIVATE_MAP_BEGIN, context, (uintptr_t)&request, 0, 0, 0, 0, &r);
	assert(r.status == GPU_PRIVATE_STATE);
	domain_rsi_call(&client_b, GPU_PRIVATE_MAP_STEP, token, 0, 0, 0, 0, 0, &r);
	assert(r.status == GPU_PRIVATE_INPUT);
	domain_rsi_call(&client_a, GPU_PRIVATE_MAP_STEP, token, 0, 1, 0, 0, 0, &r);
	assert(r.status == GPU_PRIVATE_INPUT);
	domain_rsi_call(&service, GPU_PRIVATE_SERVICE_MAPPING_VERSION, context, 7, 0, 0, 0, 0, &r);
	assert(r.status == GPU_PRIVATE_STATE);
	if (scenario == 1U) {
		domain_rsi_call(&client_a, GPU_PRIVATE_MAP_ABORT, token, 0, 0, 0, 0, 0, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS && r.value[3] == GPU_PRIVATE_MAP_ABORTED);
		domain_rsi_call(&client_a, GPU_PRIVATE_MAPPING_CHECK, context, 0, 0, 0x200000UL, 2, 0, &r);
		assert(r.status == GPU_PRIVATE_SUCCESS);
	} else {
		r = before;
		while (r.status == GPU_PRIVATE_INCOMPLETE) {
			sequence = r.value[2];
			if (scenario == 2U && r.value[3] == GPU_PRIVATE_MAP_COMMIT)
				drain_barrier_failure = true;
			domain_rsi_call(&client_a, GPU_PRIVATE_MAP_STEP, token, sequence, 0, 0, 0, 0, &r);
			if (r.status != GPU_PRIVATE_STATE) {
				domain_rsi_call(&client_a, GPU_PRIVATE_MAP_STEP, token, sequence, 0, 0, 0, 0, &replay);
				assert(memcmp(&r, &replay, sizeof(r)) == 0);
			}
		}
		if (scenario == 2U) {
			assert(r.status == GPU_PRIVATE_STATE && r.value[1] == 0UL);
			domain_rsi_call(&client_a, GPU_PRIVATE_QUERY, context, 0, 0, 0, 0, 0, &r);
			assert(r.status == GPU_PRIVATE_SUCCESS && r.value[0] == 2UL && r.value[1] == 1UL);
			domain_rsi_call(&client_a, GPU_PRIVATE_BO_DESTROY, bo, 0, 0, 0, 0, 0, &r);
			assert(r.status == GPU_PRIVATE_STATE);
		} else {
			assert(r.status == GPU_PRIVATE_SUCCESS && r.value[1] == 1UL);
			domain_rsi_call(&client_a, GPU_PRIVATE_MAPPING_CHECK, context, bo, 0, 0x200000UL, 2, 3, &r);
			assert(r.status == GPU_PRIVATE_SUCCESS && r.value[0] == 8192UL);
			domain_rsi_call(&client_a, GPU_PRIVATE_MAPPING_CHECK, context, 0, 0, request.iova, 2, 0, &r);
			assert(r.status == GPU_PRIVATE_SUCCESS);
			domain_rsi_call(&service, GPU_PRIVATE_SERVICE_MAPPING_VERSION, context, 8, 0, 0, 0, 0, &r);
			assert(r.status == GPU_PRIVATE_INPUT);
			domain_rsi_call(&service, GPU_PRIVATE_SERVICE_MAPPING_VERSION, context, 7, 0, 0, 0, 0, &r);
			assert(r.status == GPU_PRIVATE_SUCCESS && r.value[0] == 1UL);
			domain_rsi_call(&client_b, GPU_PRIVATE_MAPPING_VERSION, context, 0, 0, 0, 0, 0, &r);
			assert(r.status == GPU_PRIVATE_INPUT);
		}
	}
	assert(writes == old_writes); /* Idle mapping never starts or reprograms AS. */
	printf("MAP_TRANSACTION_RSI scenario=%u PASS; actual dispatcher/core, host adapters\n", scenario);
	return 0;
}
