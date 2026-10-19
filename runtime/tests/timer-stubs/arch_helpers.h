#ifndef TIMER_TEST_ARCH_HELPERS_H
#define TIMER_TEST_ARCH_HELPERS_H
#include <stdint.h>
#define CNTx_CTL_ENABLE 1UL
#define CNTx_CTL_IMASK 2UL
#define CNTx_CTL_ISTATUS 4UL
#define EL1_VIRT_TIMER_PPI 27U
#define EL1_PHYS_TIMER_PPI 30U
#define EXTRACT(field, value) ((value) & 0xffffffUL)
unsigned long read_cntv_ctl_el02(void);
unsigned long read_cntp_ctl_el02(void);
unsigned long read_icc_hppir1_el1(void);
unsigned long read_mpidr_el1(void);
void test_dsb(void);
#define dsb(scope) test_dsb()
#endif
