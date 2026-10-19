/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef TEST_MMIO_H
#define TEST_MMIO_H
#include <stdint.h>
uint32_t read32(const volatile void *address);
void write32(uint32_t value, volatile void *address);
#endif
