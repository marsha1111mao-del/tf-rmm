#include <arch_helpers.h>
#include <rec.h>
#include <timers.h>

#define TIMER_ASSERTED(control) \
	(((control) & (CNTx_CTL_ENABLE | CNTx_CTL_ISTATUS | CNTx_CTL_IMASK)) == \
	 (CNTx_CTL_ENABLE | CNTx_CTL_ISTATUS))

bool opencca_check_pending_timers(struct rec *rec)
{
	bool virtual_asserted = TIMER_ASSERTED(read_cntv_ctl_el02());
	bool physical_asserted = TIMER_ASSERTED(read_cntp_ctl_el02());

	plat_opencca_timers_mask(virtual_asserted, physical_asserted);
	for (unsigned int attempt = 0U; attempt < 64U; attempt++) {
		unsigned long hppir = read_icc_hppir1_el1();
		unsigned int intid = (unsigned int)EXTRACT(ICC_HPPIR1_EL1_INTID, hppir);

		if ((!virtual_asserted || intid != EL1_VIRT_TIMER_PPI) &&
		    (!physical_asserted || intid != EL1_PHYS_TIMER_PPI))
			return virtual_asserted != TIMER_ASSERTED(rec->sysregs.cntv_ctl_el0) ||
			       physical_asserted != TIMER_ASSERTED(rec->sysregs.cntp_ctl_el0);
	}
	return true;
}
