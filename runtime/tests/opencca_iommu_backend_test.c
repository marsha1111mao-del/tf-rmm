#include <assert.h>
#include <opencca_iommu.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define DEVICE 0xfdb50800UL
#define VOP 0xfdd97e00UL
#define ROOT 0x1287654000UL

static const unsigned long bases[] = {DEVICE, VOP, VOP + 0x100UL};
static uint32_t registers[3][16];
static struct {
	unsigned int bank;
	unsigned long offset;
	uint32_t value;
} writes[16];
static unsigned int write_count, read_count, barriers;
static unsigned long ticks;
static bool corrupt_root;

static unsigned int bank_at(uintptr_t address)
{
	for (unsigned int bank = 0U; bank < 3U; bank++) {
		if (address >= bases[bank] && address < bases[bank] + sizeof(registers[bank]))
			return bank;
	}
	assert(false);
	return 0U;
}

uint32_t read32(const volatile void *address)
{
	uintptr_t physical = (uintptr_t)address;
	unsigned int bank = bank_at(physical);

	assert((physical & 3UL) == 0UL);
	read_count++;
	return registers[bank][(physical - bases[bank]) / 4UL];
}

void write32(uint32_t value, volatile void *address)
{
	uintptr_t physical = (uintptr_t)address;
	unsigned int bank = bank_at(physical);
	unsigned long offset = physical - bases[bank];

	assert((physical & 3UL) == 0UL && write_count < 16U);
	writes[write_count].bank = bank;
	writes[write_count].offset = offset;
	writes[write_count++].value = value;
	if (offset == 0x18UL) {
		registers[bank][0x20U / 4U] &= ~value;
		if (corrupt_root)
			registers[bank][0] ^= 0x1000U;
	} else {
		assert(offset == 8UL && (value == 4U || value == 5U));
	}
}

unsigned long read_cntpct_el0(void)
{
	return ticks++;
}

unsigned long read_cntfrq_el0(void)
{
	return 1000000UL;
}

void test_dsb(void)
{
	barriers++;
}

static void reset(void)
{
	memset(registers, 0, sizeof(registers));
	memset(writes, 0, sizeof(writes));
	write_count = 0U;
	read_count = 0U;
	barriers = 0U;
	corrupt_root = false;
	for (unsigned int bank = 0U; bank < 3U; bank++) {
		registers[bank][0] = 0x87654210U;
		registers[bank][1] = 1U;
		registers[bank][0x0cU / 4U] = 0x12345000U + bank * 0x1000U;
	}
}

static struct opencca_iommu_result fault(unsigned long device, bool success)
{
	struct opencca_iommu_result result = {0};

	assert(plat_opencca_iommu_fault(device, ROOT, &result) == success);
	return result;
}

static void check_write(unsigned int index, unsigned int bank,
			unsigned long offset, uint32_t value)
{
	assert(index < write_count && writes[index].bank == bank);
	assert(writes[index].offset == offset && writes[index].value == value);
}

int main(void)
{
	struct opencca_iommu_result result;

	reset();
	result = fault(DEVICE, true);
	assert(result.value[0] == 0UL && result.value[1] == 0UL && write_count == 0U);

	registers[0][0x20U / 4U] = 1U;
	result = fault(DEVICE, true);
	assert(result.value[0] == 1UL && result.value[1] == 0x12345000UL);
	assert(result.value[2] == 0UL && write_count == 3U && barriers == 1U);
	check_write(0U, 0U, 8UL, 4U);
	check_write(1U, 0U, 8UL, 5U);
	check_write(2U, 0U, 0x18UL, 1U);
	assert(registers[0][0x20U / 4U] == 0U);

	reset();
	registers[0][1] |= 1U << 5U;
	registers[0][0x20U / 4U] = 3U;
	result = fault(DEVICE, true);
	assert(result.value[0] == (3UL | OPENCCA_IOMMU_FAULT_WRITE));
	assert(write_count == 3U);
	check_write(2U, 0U, 0x18UL, 3U);

	reset();
	registers[0][1] |= 1U << 5U;
	registers[0][0x20U / 4U] = 2U;
	result = fault(DEVICE, true);
	assert(result.value[0] == 2UL && write_count == 1U);
	check_write(0U, 0U, 0x18UL, 2U);

	reset();
	registers[1][0x20U / 4U] = 2U;
	registers[2][1] |= 1U << 5U;
	registers[2][0x20U / 4U] = 1U;
	result = fault(VOP, true);
	assert(result.value[0] == (2UL | (0x101UL << 16U)));
	assert(result.value[1] == 0x12346000UL && result.value[2] == 0x12347000UL);
	assert(write_count == 4U && barriers == 2U);
	check_write(0U, 1U, 0x18UL, 2U);
	check_write(1U, 2U, 8UL, 4U);
	check_write(2U, 2U, 8UL, 5U);
	check_write(3U, 2U, 0x18UL, 1U);

	reset();
	registers[1][0x20U / 4U] = 1U;
	registers[2][0] ^= 0x1000U;
	(void)fault(VOP, false);
	assert(write_count == 0U);

	reset();
	registers[1][0x20U / 4U] = 1U;
	registers[2][0x20U / 4U] = 4U;
	(void)fault(VOP, false);
	assert(write_count == 0U);

	reset();
	registers[0][1] = 0U;
	registers[0][0x20U / 4U] = 1U;
	(void)fault(DEVICE, false);
	assert(write_count == 0U);

	reset();
	memset(&result, 0, sizeof(result));
	assert(!plat_opencca_iommu_fault(DEVICE + 0x1000UL, ROOT, &result));
	assert(!plat_opencca_iommu_fault(DEVICE, 0UL, &result));
	assert(!plat_opencca_iommu_fault(DEVICE, ROOT + 1UL, &result));
	assert(!plat_opencca_iommu_fault(DEVICE, 1UL << 40U, &result));
	assert(read_count == 0U && write_count == 0U);

	reset();
	corrupt_root = true;
	registers[0][0x20U / 4U] = 1U;
	(void)fault(DEVICE, false);
	assert(write_count == 3U);
	puts("RK IOMMU fault backend: read/write/bus IRQ, two banks, root validation and acknowledgement ordering PASS");
	return 0;
}
