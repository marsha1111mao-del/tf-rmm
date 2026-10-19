/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef TEST_ARCH_HELPERS_H
#define TEST_ARCH_HELPERS_H
unsigned long read_cntpct_el0(void);
unsigned long read_cntfrq_el0(void);
void test_dsb(void);
#define dsb(scope) test_dsb()
#endif
