/* SPDX-License-Identifier: BSD-3-Clause */
/* Integrated hostile requests through actual helpers and dispatcher. */
void gpu_boundary_private_snapshot(bool save);
void gpu_boundary_firmware_snapshot(bool save);

static void identity_expect(bool condition, const char *where)
{
	if (!condition) {
		fprintf(stderr, "GPU_RSI_IDENTITY_REJECT %s\n", where);
		assert(false);
	}
}
static void identity_denied(const void *owner, unsigned long op,
		unsigned long handle, unsigned long a, unsigned long b,
		unsigned long c, unsigned long d)
{
	struct gpu_private_result r;
	unsigned int counts[] = { writes, control_writes, control_reads, mmio_reads,
		firmware_doorbells, as_count, data_syncs, cpu_returns };
	uint32_t saved_registers[sizeof(registers) / sizeof(registers[0])];
	memcpy(saved_registers, registers, sizeof(registers));
	domain_rsi_call(owner, op, handle, a, b, c, d, 0UL, &r);
	identity_expect(r.status == GPU_PRIVATE_INPUT && !r.value[0] && !r.value[1] &&
		!r.value[2] && !r.value[3], "request must be rejected before authority changes");
	unsigned int after[] = { writes, control_writes, control_reads, mmio_reads,
		firmware_doorbells, as_count, data_syncs, cpu_returns };
	identity_expect(memcmp(counts, after, sizeof(counts)) == 0 &&
		memcmp(saved_registers, registers, sizeof(registers)) == 0, "device side effects");
	gpu_boundary_private_snapshot(false);
	gpu_boundary_firmware_snapshot(false);
}
static void domain_identity_boundary(unsigned long context, unsigned long group,
		unsigned long token, unsigned long bo, unsigned int client,
		const char *lifecycle)
{
	(void)context; (void)group; (void)token;
	const void *owner = client == 0U ? (void *)&client_a : (void *)&client_b;
	const void *attackers[] = { client == 0U ? (void *)&client_b : (void *)&client_a,
		&service, &stranger };
	unsigned int attempts = 0U, copies = 0U;
	unsigned long output[4];
	identity_manual_input = true;
	for (unsigned int actor = 0; actor < 3U; actor++) {
		unsigned int index = identity_index(attackers[actor]);
		for (unsigned int kind = 0; kind < 12U; kind++) {
			identity_reset();
			unsigned long ipa = IDENTITY_IPA, count = kind == 1U ? GPU_PRIVATE_BATCH : 1UL;
			unsigned long reserved = 0UL;
			if (kind == 2U) ipa++;
			if (kind == 3U) ipa = 1UL << 23U;
			if (kind == 4U) ipa += GRANULE_SIZE;
			if (kind == 5U) identity_entries[index] = IDENTITY_EMPTY;
			if (kind == 6U) identity_entries[index] = IDENTITY_UNASSIGNED_RAM;
			if (kind == 7U) identity_entries[index] = IDENTITY_DESTROYED;
			if (kind == 8U) identity_entries[index] = IDENTITY_UNASSIGNED_DESTROYED;
			if (kind == 9U) count = 0UL;
			if (kind == 10U) count = GPU_PRIVATE_BATCH + 1UL;
			if (kind == 11U) reserved = 1UL;
			unsigned long expected[GPU_PRIVATE_BATCH];
			memcpy(expected, identity_device[index], sizeof(expected));
			identity_mutate_source = true;
			identity_denied(attackers[actor], GPU_PRIVATE_BO_APPEND, bo, ipa, count, 0, reserved);
			attempts++;
			if (kind <= 1U) {
				identity_expect(identity_copies == 1U && identity_invalidations == 1U &&
					identity_maps == 2U && identity_locks == 1U && identity_unlocks == 1U,
					"exactly one private input copy under RTT lock");
				identity_expect(memcmp(input_pages[0], expected, count * sizeof(unsigned long)) == 0,
					"REC must select its own page; snapshot must survive source mutation");
				identity_expect(memcmp(identity_device[index], expected, sizeof(unsigned long)) != 0,
					"source mutation must actually occur");
				copies++;
			} else {
				identity_expect(!identity_copies && !identity_invalidations, "failed input must not be copied");
				bool walked = kind >= 4U && kind <= 8U;
				identity_expect(identity_walks == (unsigned int)walked &&
					identity_locks == (unsigned int)walked && identity_maps == (unsigned int)walked,
					"argument/RTT rejection boundary");
			}
			identity_expect(identity_last_action == (kind >= 6U && kind <= 8U ?
				STAGE_2_TRANSLATION_FAULT : UPDATE_REC_RETURN_TO_REALM), "translation fault action");
			if (kind >= 6U && kind <= 8U)
				identity_expect(identity_last_level == S2TT_PAGE_LEVEL, "fault level must be reported");
		}
	}
	identity_reset();
	identity_denied(owner, GPU_PRIVATE_BO_CREATE, domain_channels[client ^ 1U], GRANULE_SIZE, GPU_PRIVATE_READ, 0, 0);
	attempts++;
	identity_denied(&stranger, GPU_PRIVATE_BO_CREATE, domain_channels[client], GRANULE_SIZE, GPU_PRIVATE_READ, 0, 0);
	attempts++;
	unsigned long offered = identity_open(owner, false);
	identity_denied(owner, GPU_PRIVATE_BO_CREATE, offered, GRANULE_SIZE, GPU_PRIVATE_READ, 0, 0);
	attempts++;
	assert(xshm_endpoint_call(owner, XSHM_ACCEPT, offered, 0, output) == XSHM_SUCCESS);
	struct gpu_private_result r;
	domain_rsi_call(&service, GPU_PRIVATE_BO_INSPECT, offered, bo, 0, 0, 0, 0, &r);
	identity_expect(r.status == GPU_PRIVATE_SUCCESS, "accepted channel must resolve the correct Client BO");
	assert(xshm_endpoint_call(owner, XSHM_CLOSE, offered, 0, output) == XSHM_SUCCESS);
	identity_denied(owner, GPU_PRIVATE_BO_CREATE, offered, GRANULE_SIZE, GPU_PRIVATE_READ, 0, 0);
	attempts++;
	unsigned long stale = identity_open(&stranger, true);
	unsigned long old_id = xshm_endpoint_id(&stranger);
	xshm_endpoint_release(&stranger);
	assert(xshm_endpoint_call(&stranger, XSHM_REGISTER, 0, 0, output) == XSHM_SUCCESS);
	identity_expect(output[1] != old_id, "re-registration must acquire a new endpoint identity");
	identity_denied(&stranger, GPU_PRIVATE_BO_CREATE, stale, GRANULE_SIZE, GPU_PRIVATE_READ, 0, 0);
	attempts++;
	gpu_boundary_private_snapshot(false);
	gpu_boundary_firmware_snapshot(false);
	identity_manual_input = false;
	printf("GPU_RSI_IDENTITY=PASS client=%u lifecycle=%s hostile_requests=%u snapshot_copies=%u actual endpoint/copy/IPA/RSI/core; synthetic REC/S2/cache/device\n",
		client, lifecycle, attempts, copies);
}
