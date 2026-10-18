/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef XSHM_SERVICE_H
#define XSHM_SERVICE_H
#include <xshm_memory.h>

/* The caller holds the policy gate; owner is the executing REC's RD. */
unsigned long xshm_service_call(const struct xshm_memory_ops *ops,
		const void *owner, unsigned long command, unsigned long id,
		unsigned long argument, unsigned long size, unsigned long output[4]);
#endif
