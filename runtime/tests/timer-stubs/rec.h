#ifndef TIMER_TEST_REC_H
#define TIMER_TEST_REC_H
struct rec {
	struct {
		unsigned long cntv_ctl_el0;
		unsigned long cntp_ctl_el0;
	} sysregs;
};
#endif
