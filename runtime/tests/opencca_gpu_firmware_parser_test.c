/* SPDX-License-Identifier: BSD-3-Clause */
/* Exercise the actual firmware section parser independently of digest approval. */
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../core/opencca_gpu_firmware.c"

static unsigned char approved_image[GPU_FIRMWARE_IMAGE_SIZE];

static void reset_parser(void)
{
	memcpy(image, approved_image, sizeof(image));
	memset(sections, 0, sizeof(sections));
	section_count = 0U;
	memory_size = 0UL;
}

static void put32(unsigned long offset, uint32_t value)
{
	image[offset] = (unsigned char)value;
	image[offset + 1U] = (unsigned char)(value >> 8U);
	image[offset + 2U] = (unsigned char)(value >> 16U);
	image[offset + 3U] = (unsigned char)(value >> 24U);
}

int main(int argc, char **argv)
{
	FILE *file;

	assert(argc == 2);
	file = fopen(argv[1], "rb");
	assert(file != NULL);
	assert(fread(approved_image, 1U, sizeof(approved_image), file) == sizeof(approved_image));
	assert(fgetc(file) == EOF);
	assert(fclose(file) == 0);

	reset_parser();
	assert(parse_sections());
	assert(section_count == 7U && memory_size == 720896UL);

	for (unsigned int scenario = 0U; scenario < 6U; scenario++) {
		reset_parser();
		switch (scenario) {
		case 0U:
			/* data_size exceeds the declared VA extent. */
			put32(0x14U + 20U, 0x402000U);
			break;
		case 1U:
			put32(0x14U + 12U, 0x400000U); /* Zero VA extent. */
			break;
		case 2U:
			/* First section overlaps the second section. */
			put32(0x14U + 8U, 0x401000U);
			put32(0x14U + 12U, 0x403000U);
			break;
		case 3U:
			put32(16U, 0x33U); /* Truncated, misaligned metadata end. */
			break;
		case 4U:
			put32(0x14U, 252U << 8U); /* Metadata record exceeds end. */
			break;
		default:
			put32(16U, UINT32_MAX); /* Metadata end bound before addition. */
			break;
		}
		assert(!parse_sections());
	}
	puts("GPU_FIRMWARE_PARSER=PASS actual section parser rejects oversized/zero/overlap/truncated/wrapped metadata; MODEL_ONLY");
	return 0;
}
