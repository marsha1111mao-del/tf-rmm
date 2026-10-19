#ifndef VMID_TEST_ARCH_FEATURES_H
#define VMID_TEST_ARCH_FEATURES_H

#include <stdbool.h>

extern bool test_vmid16;

static inline bool is_feat_vmid16_present(void)
{
	return test_vmid16;
}

#endif
