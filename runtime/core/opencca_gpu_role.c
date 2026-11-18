/* SPDX-License-Identifier: BSD-3-Clause */
#include <opencca_gpu_role.h>
#include <stdint.h>
#include <string.h>

struct opencca_gpu_role_claim {
	unsigned char magic[8];
	uint64_t version;
	uint64_t endpoint_id;
};

static const unsigned char opencca_gpu_role_magic[8] = { 'O', 'C', 'C', 'A',
							 'G', 'P', 'U', '1' };

void opencca_gpu_role_measure(enum hash_algo algorithm,
			      unsigned long endpoint_id,
			      unsigned char measurement[MAX_MEASUREMENT_SIZE])
{
	struct opencca_gpu_role_claim input = {
		.version = UINT64_C(1), .endpoint_id = (uint64_t)endpoint_id
	};

	(void)endpoint_id;
	(void)memcpy(input.magic, opencca_gpu_role_magic,
		     sizeof(opencca_gpu_role_magic));
	measurement_hash_compute(algorithm, &input, sizeof(input), measurement);
}

void opencca_gpu_role_clear(unsigned char measurement[MAX_MEASUREMENT_SIZE])
{
	(void)memset(measurement, 0, MAX_MEASUREMENT_SIZE);
}
