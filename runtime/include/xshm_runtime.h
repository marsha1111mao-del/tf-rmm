/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef XSHM_RUNTIME_H
#define XSHM_RUNTIME_H

#include <stdbool.h>
#include <xshm_memory.h>

extern const struct xshm_memory_ops xshm_rtt_ops;
/* Preserve DATA ownership and assigned PA while removing/restoring the CPU
 * leaf. Callers hold policy lock and retain the donated-page lifetime record.
 */
bool gpu_control_rtt_hide(const void *owner, unsigned long ipa, unsigned long pa);
bool gpu_control_rtt_restore(const void *owner, unsigned long ipa, unsigned long pa);
bool gpu_private_rtt_restore_uncached(const void *owner, unsigned long ipa, unsigned long pa);
/* Acquired before RD/RTT locks. Never held across REC_ENTER/Realm execution. */
void xshm_policy_lock(void);
void xshm_policy_unlock(void);
bool xshm_rmi_allowed(unsigned int fid, unsigned long arg0,
		     unsigned long arg1, unsigned long arg2, unsigned long arg3);
#endif
