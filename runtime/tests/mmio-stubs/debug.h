/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef TEST_GPU_DEBUG_H
#define TEST_GPU_DEBUG_H
#include <stdio.h>
#define ERROR(...) fprintf(stderr, __VA_ARGS__)
#define INFO(...) do { } while (0)
#endif
