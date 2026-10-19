#ifndef VMID_TEST_ATOMICS_H
#define VMID_TEST_ATOMICS_H

#include <stdbool.h>
#include <stdint.h>

static inline bool atomic_bit_set_acquire_release_64(uint64_t *location,
						   unsigned int bit)
{
	uint64_t mask = UINT64_C(1) << bit;

	return (__atomic_fetch_or(location, mask, __ATOMIC_ACQ_REL) & mask) != 0U;
}

static inline void atomic_bit_clear_release_64(uint64_t *location,
					       unsigned int bit)
{
	__atomic_fetch_and(location, ~(UINT64_C(1) << bit), __ATOMIC_RELEASE);
}

#endif
