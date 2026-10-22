/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef XSHM_ENDPOINT_H
#define XSHM_ENDPOINT_H

#include <stddef.h>
#include <stdbool.h>

#define XSHM_ABI_VERSION 1UL
#define XSHM_CAP_ENDPOINT 1UL
#define XSHM_CAP_EVENT_STATE 2UL

#define XSHM_REGISTER 0UL
#define XSHM_OFFER 1UL
#define XSHM_ACCEPT 2UL
#define XSHM_CLOSE 3UL
#define XSHM_NOTIFY 4UL
#define XSHM_ARM 5UL
#define XSHM_ACK 6UL
#define XSHM_QUERY 7UL
#define XSHM_UNREGISTER 8UL
#define XSHM_IRQ_BIND 16UL
#define XSHM_ACK_ARM 17UL
#define XSHM_NOTIFY_TIMED 18UL
#define XSHM_CAP_EVENT_IRQ 16UL
#define XSHM_CAP_ACK_ARM 32UL
#define XSHM_CAP_NOTIFY_TIMING 64UL

#define XSHM_SUCCESS 0UL
#define XSHM_ERROR_INPUT 1UL
#define XSHM_ERROR_STATE 2UL
#define XSHM_FULL 3UL

#define XSHM_EVENT_LIVE 1UL
#define XSHM_EVENT_ARMED 2UL
#define XSHM_MAX_ENDPOINTS 64U
#define XSHM_MAX_CHANNELS 128U

/* The caller serializes all operations, including realm teardown. Owner is
 * the actual RD from the executing REC, never a guest- or Host-supplied ID.
 * IDs are unique within this RMM boot and are never recycled.
 * Endpoints authenticate instances; peer selection still requires a trusted
 * provisioning/attestation policy in the participating Realm.
 */
unsigned long xshm_endpoint_call(const void *owner, unsigned long command,
				 unsigned long id, unsigned long sequence,
				 unsigned long output[4]);
unsigned long xshm_endpoint_id(const void *owner);
const void *xshm_endpoint_peer(const void *owner, unsigned long channel,
			     unsigned long *peer_id);
void xshm_endpoint_release(const void *owner);
bool xshm_endpoint_irq_enabled(const void *owner);
bool xshm_endpoint_irq_take(const void *owner);

#endif
