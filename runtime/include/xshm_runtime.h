/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef XSHM_RUNTIME_H
#define XSHM_RUNTIME_H

#include <stdbool.h>
#include <xshm_memory.h>

extern const struct xshm_memory_ops xshm_rtt_ops;
/* Acquired before RD/RTT locks. Never held across REC_ENTER/Realm execution. */
void xshm_policy_lock(void);
void xshm_policy_unlock(void);
bool xshm_rmi_allowed(unsigned int fid, unsigned long arg0,
		     unsigned long arg1, unsigned long arg2, unsigned long arg3);
#endif
