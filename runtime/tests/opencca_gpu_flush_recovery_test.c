#define main gpu_backend_fixture_main
#include "opencca_gpu_backend_test.c"
#undef main

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);

	initialize();
	assert(plat_opencca_gpu_reset(true));
	assert(soft_commands == 1U && hard_commands == 0U);
	assert(registers[0x28U / 4U] == 0x77U);
	assert(registers[0x1008U / 4U] == 0x55U);
	assert(registers[0x2008U / 4U] == 0x33U);

	initialize();
	soft_succeeds = false;
	assert(plat_opencca_gpu_reset(false));
	assert(soft_commands == 1U && hard_commands == 1U);
	assert(registers[0x28U / 4U] == 0U);
	assert(registers[0x1008U / 4U] == 0U);
	assert(registers[0x2008U / 4U] == 0U);

	initialize();
	soft_succeeds = false;
	hard_succeeds = false;
	assert(!plat_opencca_gpu_reset(true));
	assert(soft_commands == 1U && hard_commands == 1U);
	assert(registers[0x28U / 4U] == 0U);
	assert(registers[0x1008U / 4U] == 0U);
	assert(registers[0x2008U / 4U] == 0U);
	assert(clock_ticks > 0UL && barriers == 3U);

	puts("GPU_FLUSH_RECOVERY=PASS bounded soft ACK loss fallback, exact hard command, "
	     "double-ACK fail-closed timeout, and final barrier");
	return 0;
}
