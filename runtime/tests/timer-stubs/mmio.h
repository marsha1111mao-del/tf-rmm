#ifndef TIMER_TEST_MMIO_H
#define TIMER_TEST_MMIO_H
#include <stdint.h>
uint64_t read64(const volatile void *address);
uint32_t read32(const volatile void *address);
void write32(uint32_t value, volatile void *address);
#endif
