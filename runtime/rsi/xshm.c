/* SPDX-License-Identifier: BSD-3-Clause */
#include <rec.h>
#include <rsi-handler.h>
#include <smc-rsi.h>
#include <xshm_runtime.h>
#include <xshm_service.h>
#include <xshm_endpoint.h>
#include <xshm_irq.h>
#include <smc-rmi.h>
#include <granule.h>
#include <arch_helpers.h>

_Static_assert(XSHM_SUCCESS == RSI_SUCCESS, "XSHM status ABI");
_Static_assert(XSHM_ERROR_INPUT == RSI_ERROR_INPUT, "XSHM status ABI");
_Static_assert(XSHM_ERROR_STATE == RSI_ERROR_STATE, "XSHM status ABI");
_Static_assert(XSHM_FULL == RSI_INCOMPLETE, "XSHM status ABI");

static unsigned long xshm_counter(void)
{
	isb();
	return read_cntpct_el0();
}

void handle_rsi_opencca_xshm(struct rec *rec, struct rmi_rec_exit *rec_exit,
			      struct rsi_result *res)
{
	unsigned long output[4];
	unsigned long status, peer_id;
	unsigned long command = rec->regs[1];
	bool timed = command == XSHM_NOTIFY_TIMED;
	unsigned long entered = timed ? xshm_counter() : 0UL;
	unsigned long locked = 0UL;
	const void *peer = NULL;

	res->action = UPDATE_REC_RETURN_TO_REALM;
	for (unsigned int i = 0U; i < SMC_RESULT_REGS; i++)
		res->smc_res.x[i] = 0UL;
	if ((rec->regs[5] | rec->regs[6] | rec->regs[7]) != 0UL) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		return;
	}
	/* No Host-supplied VMID or caller-supplied owner enters this decision. */
	/* This platform's event IRQ is routed to REC0, not an arbitrary caller. */
	if (rec->regs[1] == XSHM_IRQ_BIND && rec->rec_idx != 0UL) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		return;
	}
	if (timed)
		command = XSHM_NOTIFY;
	xshm_policy_lock();
	if (timed)
		locked = xshm_counter();
	if (command == XSHM_NOTIFY || command == XSHM_CLOSE)
		peer = xshm_endpoint_peer(rec->realm_info.g_rd,
					 rec->regs[2], &peer_id);
	status = xshm_service_call(&xshm_rtt_ops, rec->realm_info.g_rd,
		command, rec->regs[2], rec->regs[3], rec->regs[4], output);
	if (status == XSHM_SUCCESS && output[2] == 1UL &&
	    peer != NULL && xshm_endpoint_irq_enabled(peer)) {
		/* Only a scheduler hint crosses to Host. The interrupt's pending
		 * state and LR remain private, and are rechecked on REC entry.
		 */
		rec_exit->exit_reason = XSHM_RMI_EXIT_NOTIFY;
		rec_exit->gprs[0] = granule_addr((struct granule *)peer);
		res->action = UPDATE_REC_EXIT_TO_HOST;
	}
	xshm_policy_unlock();
	res->smc_res.x[0] = status;
	for (unsigned int i = 0U; i < 4U; i++)
		res->smc_res.x[i + 1U] = output[i];
	if (timed && status == XSHM_SUCCESS) {
		res->smc_res.x[1] = entered;
		res->smc_res.x[2] = locked;
		res->smc_res.x[3] = xshm_counter();
		res->smc_res.x[4] = (read_cntfrq_el0() << 32U) |
			(res->action == UPDATE_REC_EXIT_TO_HOST ? 1UL : 0UL);
	}
}

void opencca_xshm_release_realm(struct granule *g_rd)
{
	/* Called only after unused RD and empty RTT checks succeed. A live REC
	 * holds its RD reference, so registration cannot race RD recycling.
	 */
	/* The RMI dispatch already holds the policy gate. */
	xshm_endpoint_release(g_rd);
}
