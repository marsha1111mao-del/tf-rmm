/* SPDX-License-Identifier: BSD-3-Clause */
/* Included by the host-only RSI boundary checker after the ordinary backend
 * doubles and actual RSI dispatcher. These are hostile calls against valid,
 * live objects, not merely random handles rejected before object lookup. */
void gpu_boundary_private_snapshot(bool save);
void gpu_boundary_firmware_snapshot(bool save);

struct boundary_request {
	unsigned long op, handle, a, b, c, d, e;
};

static void boundary_denied(const void *caller, struct boundary_request request,
		unsigned int ordinal)
{
	struct gpu_private_result r;
	unsigned int written = writes, controls = control_writes, reads = control_reads;
	unsigned int device_reads = mmio_reads;
	unsigned int bells = firmware_doorbells, commands = as_count;
	unsigned int synced = data_syncs, returned = cpu_returns;
	uint32_t saved_registers[sizeof(registers) / sizeof(registers[0])];

	memcpy(saved_registers, registers, sizeof(registers));
	domain_rsi_call(caller, request.op, request.handle, request.a, request.b,
		request.c, request.d, request.e, &r);
	if (r.status != GPU_PRIVATE_INPUT || r.value[0] || r.value[1] ||
	    r.value[2] || r.value[3]) {
		fprintf(stderr, "GPU_RSI_BOUNDARY_REJECT ordinal=%u op=%lu status=%lu values=%lu/%lu/%lu/%lu\n",
			ordinal, request.op, r.status, r.value[0], r.value[1], r.value[2], r.value[3]);
		assert(false);
	}
	assert(writes == written && control_writes == controls && control_reads == reads &&
		mmio_reads == device_reads &&
		firmware_doorbells == bells && as_count == commands &&
		data_syncs == synced && cpu_returns == returned);
	assert(memcmp(saved_registers, registers, sizeof(registers)) == 0);
	/* Compare actual private state byte-for-byte. A failed request must not
	 * silently consume a grant, advance an epoch, or alter an internal anchor.
	 * Input-copy scratch and diagnostic policy-lock counts are not authority.
	 */
	gpu_boundary_private_snapshot(false);
	gpu_boundary_firmware_snapshot(false);
}

static void domain_rsi_boundary(unsigned long context, unsigned long group,
		unsigned long token, unsigned long bo, unsigned int client,
		const char *lifecycle)
{
	const void *other = client == 0U ? (void *)&client_b : (void *)&client_a;
	const void *callers[] = { other, &service, &stranger };
	unsigned long wrong_channel = client == 0U ? 8UL : 7UL;
	unsigned long right_channel = client == 0U ? 7UL : 8UL;
	unsigned int attempts = 0U;
	struct gpu_firmware_task_command command = { .start = 0x100000UL, .bytes = 64UL, .queue = 1U };
	struct gpu_firmware_queue_config queue[2] = {{.ring_bytes = 4096U}, {.ring_bytes = 4096U}};
	const struct boundary_request client_requests[] = {
		{GPU_PRIVATE_BO_DESTROY, bo, 0, 0, 0, 0, 0},
		{GPU_PRIVATE_BO_SEAL, bo, 0, 0, 0, 0, 0},
		{GPU_PRIVATE_BO_RELEASE, bo, 0, 0, 0, 0, 0},
		{GPU_PRIVATE_BO_UNCACHED, bo, 0, 0, 0, 0, 0},
		{GPU_PRIVATE_CONTEXT_DESTROY, context, 0, 0, 0, 0, 0},
		{GPU_PRIVATE_QUERY, context, 0x100000UL, 0, 0, 0, 0},
		{GPU_PRIVATE_MAP, context, bo, 0, 0x200000UL, 1, GPU_PRIVATE_READ},
		{GPU_PRIVATE_MAP_AUTHORIZE, context, bo, 0, 0x200000UL, 1, GPU_PRIVATE_READ},
		{GPU_PRIVATE_UNMAP, context, 0x100000UL, 1, 0, 0, 0},
		{GPU_PRIVATE_UNMAP_BO, context, bo, 0, 0x100000UL, 1, 0},
		{GPU_PRIVATE_MAPPING_CHECK, context, bo, 0, 0x100000UL, 1, GPU_PRIVATE_READ},
		{GPU_PRIVATE_GROUP_DESTROY, group, 0, 0, 0, 0, 0},
		{GPU_PRIVATE_GROUP_CONFIGURE, group, (unsigned long)(uintptr_t)queue, 7, 2, 0, 0},
		{GPU_PRIVATE_TASK_STAGE_BATCH, group, (unsigned long)(uintptr_t)&command, 7, 1, GPU_PRIVATE_TASK_DEFERRED, 0},
		{GPU_PRIVATE_TASK_CANCEL, token, 0, 0, 0, 0, 0},
		{GPU_PRIVATE_TASK_READY, token, 7, 0, 0, 0, 0},
		{GPU_PRIVATE_TASK_READY_PUBLISH, token, 7, 0, 0, 0, 0},
		{GPU_PRIVATE_TASK_READY_LAUNCH, token, 7, 0, 0, 0, 0},
		{GPU_PRIVATE_TASK_PUBLISH, token, 7, 1, 0, 0, 0},
		{GPU_PRIVATE_TASK_PROGRESS, token, 7, 0, 0, 0, 0},
		{GPU_PRIVATE_TASK_COMPLETE, token, 7, 0, 0, 0, 0},
		{GPU_PRIVATE_TASK_RETURN, token, 7, 0, 0, 0, 0},
		{GPU_PRIVATE_TASK_RETIRE, token, 7, 0, 0, 0, 0},
		{GPU_PRIVATE_TASK_RECLAIM, token, 7, 0, 0, 0, 0},
		{GPU_PRIVATE_TASK_FINISH, token, 7, 0, 0, 0, 0},
		{GPU_PRIVATE_TASK_HEAP_EVENT, token, 7, 0, 0, 0, 0},
	};
	const unsigned long service_actions[] = {
		GPU_PRIVATE_TASK_VALIDATE, GPU_PRIVATE_TASK_PREPARE,
		GPU_PRIVATE_TASK_PREPARE_LAUNCH, GPU_PRIVATE_TASK_DISPATCH,
		GPU_PRIVATE_TASK_START, GPU_PRIVATE_TASK_QUIESCE,
	};

	gpu_boundary_private_snapshot(true);
	gpu_boundary_firmware_snapshot(true);
	for (unsigned int i = 0U; i < sizeof(callers) / sizeof(callers[0]); i++)
		for (unsigned int j = 0U; j < sizeof(client_requests) / sizeof(client_requests[0]); j++)
			boundary_denied(callers[i], client_requests[j], ++attempts);
	boundary_denied(&service, (struct boundary_request){GPU_PRIVATE_BO_INSPECT,
		wrong_channel, bo, 0, 0, 0, 0}, ++attempts);
	boundary_denied(&service, (struct boundary_request){GPU_PRIVATE_CONTEXT_INSPECT,
		wrong_channel, context, 0, 0, 0, 0}, ++attempts);
	boundary_denied(&service, (struct boundary_request){GPU_PRIVATE_GROUP_INSPECT,
		group, wrong_channel, 0, 0, 0, 0}, ++attempts);
	boundary_denied(&service, (struct boundary_request){GPU_PRIVATE_GROUP_VALIDATE,
		group, wrong_channel, context, 2, 0, 0}, ++attempts);
	boundary_denied(&service, (struct boundary_request){GPU_PRIVATE_SERVICE_UNMAP,
		context, wrong_channel, 0x100000UL, 1, 0, 0}, ++attempts);
	for (unsigned int i = 0U; i < sizeof(service_actions) / sizeof(service_actions[0]); i++) {
		struct boundary_request req = { service_actions[i], token, wrong_channel, context, group, 0, 0 };

		boundary_denied(&service, req, ++attempts);
		req.a = right_channel;
		boundary_denied(other, req, ++attempts); /* Client cannot claim the service role. */
		for (unsigned int reserved = 0U; reserved < 2U; reserved++) {
			req.d = reserved == 0U ? 1UL : 0UL;
			req.e = reserved == 1U ? 1UL : 0UL;
			boundary_denied(&service, req, ++attempts);
		}
	}
	/* Deterministic permutations of caller/channel/generation, all targeting
	 * the same valid token. No random pointer is dereferenced by the doubles.
	 */
	for (unsigned int bit = 16U; bit < 48U; bit++)
		boundary_denied(&service, (struct boundary_request){GPU_PRIVATE_TASK_VALIDATE,
			token ^ (1UL << bit), right_channel, context, group, 0, 0}, ++attempts);
	printf("GPU_RSI_BOUNDARY=PASS client=%u lifecycle=%s attempts=%u actual RSI/core, metadata/PT byte equality, no MMIO/control/cache effects; MODEL_ONLY\n",
		client, lifecycle, attempts);
}
