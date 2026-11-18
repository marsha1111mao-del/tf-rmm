/* SPDX-License-Identifier: BSD-3-Clause */
#include <assert.h>
#include <measurement.h>
#include <opencca_gpu_role.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static enum hash_algo hashed_algorithm;
static unsigned char hashed_input[32];
static size_t hashed_input_size;

void measurement_hash_compute(enum hash_algo algorithm, void *data,
			      size_t size, unsigned char *out)
{
	hashed_algorithm = algorithm;
	hashed_input_size = size;
	(void)memcpy(hashed_input, data, size);
	(void)memset(out, 0xa5, MAX_MEASUREMENT_SIZE);
}

static uint64_t decode64(const unsigned char *bytes)
{
	uint64_t value;

	(void)memcpy(&value, bytes, sizeof(value));
	return value;
}

int main(void)
{
	unsigned char measurement[MAX_MEASUREMENT_SIZE];

	(void)memset(measurement, 0x5a, sizeof(measurement));
	opencca_gpu_role_measure(HASH_SHA_512, 0x123456789abcdef0UL,
				 measurement);
	assert(hashed_algorithm == HASH_SHA_512);
	assert(hashed_input_size == 24U);
	assert(hashed_input[0] == 'O' && hashed_input[7] == '1');
	assert(decode64(&hashed_input[8]) == UINT64_C(1));
	assert(decode64(&hashed_input[16]) == UINT64_C(0x123456789abcdef0));
	assert(measurement[0] == 0xa5);

	opencca_gpu_role_measure(HASH_SHA_512, 0x23456789abcdef01UL,
				 measurement);
	assert(decode64(&hashed_input[16]) == UINT64_C(0x23456789abcdef01));

	opencca_gpu_role_clear(measurement);
	for (unsigned int i = 0U; i < MAX_MEASUREMENT_SIZE; i++)
		assert(measurement[i] == 0U);
	assert(OPENCCA_GPU_ROLE_MEASUREMENT_SLOT == MEASUREMENT_SLOT_NR - 1U);

	puts("GPU_ROLE_CLAIM=PASS endpoint-bound private claim encoding and clear; SLOT=4");
	return 0;
}
