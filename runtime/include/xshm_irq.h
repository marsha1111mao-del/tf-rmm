/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef XSHM_IRQ_H
#define XSHM_IRQ_H
#include <stdbool.h>
#include <stddef.h>

#define XSHM_IRQ_INTID 127UL
/* Experimental platform ABI: Host relays a scheduling hint, never an IRQ. */
#define XSHM_RMI_EXIT_NOTIFY 0x70U

/* The final hardware LR is private to the RMM and never exported to Host. */
bool xshm_irq_host_valid(const unsigned long *lrs, size_t count);
void xshm_irq_inject(unsigned long *lrs, size_t count);
#endif
