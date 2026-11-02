/* SPDX-License-Identifier: BSD-3-Clause */
/* Execute the unmodified production RSI dispatcher against actual GPU cores.
 * REC, channel lookup, input copy and policy-lock primitives are host doubles.
 * Included only by the backend's GPU_DOMAIN_RSI_TEST build. */
#define MAX_CPUS 1U
#define UPDATE_REC_RETURN_TO_REALM 1U
struct rec { struct { const void *g_rd; } realm_info; unsigned long regs[8]; };
struct rsi_result { unsigned int action; struct { unsigned long x[8]; } smc_res; };
static unsigned long input_pages[MAX_CPUS][GPU_PRIVATE_BATCH];
static struct gpu_firmware_queue_config input_queues[MAX_CPUS][GPU_FIRMWARE_STREAMS];
static struct gpu_firmware_task_command input_commands[MAX_CPUS][GPU_PRIVATE_TASK_BATCH];
static bool domain_input_fault, domain_disconnected;
static unsigned int domain_policy_calls;
static unsigned int my_cpuid(void) { return 0U; }
static void xshm_policy_lock(void)
{
	assert(!domain_policy_locked);
	domain_policy_locked = true;
	domain_policy_calls++;
}
static void xshm_policy_unlock(void)
{
	assert(domain_policy_locked);
	domain_policy_locked = false;
}
static const void *xshm_endpoint_peer(const void *owner, unsigned long channel,
		unsigned long *peer)
{
	assert(domain_policy_locked);
	if (domain_disconnected) return NULL;
	*peer = 123UL; /* Deliberately unrelated to Client slot/RD. */
	if (owner == &service) return channel == 7UL ? &client_a : channel == 8UL ? &client_b : NULL;
	return channel == 7UL && (owner == &client_a || owner == &client_b) ? &service : NULL;
}
static bool copy_page_input(struct rec *rec, unsigned long ipa, size_t bytes,
		void *destination, struct rsi_result *res)
{
	assert(domain_policy_locked && rec != NULL && res != NULL);
	if (domain_input_fault || ipa == 0UL || bytes > sizeof(input_commands[0])) return false;
	memcpy(destination, (void *)(uintptr_t)ipa, bytes);
	return true;
}
bool opencca_gpu_isolate_service(const void *owner)
{
	(void)owner;
	assert(false); /* Not an input to any domain lifecycle scenario. */
	return false;
}
#define operations donated_ops
#define firmware_operations fw_ops
#include "opencca_gpu_domain_dispatch.inc"
#undef operations
#undef firmware_operations

static void domain_rsi_call(const void *owner, unsigned long op, unsigned long handle,
		unsigned long a, unsigned long b, unsigned long c, unsigned long d,
		unsigned long e, struct gpu_private_result *result)
{
	struct rec rec = { .realm_info = {owner}, .regs = {0, op, handle, a, b, c, d, e} };
	struct rsi_result res;
	unsigned int before = domain_policy_calls;

	memset(&res, 0xa5, sizeof(res));
	domain_dispatch_active = true;
	handle_rsi_opencca_gpu_private(&rec, &res);
	domain_dispatch_active = false;
	assert(!domain_policy_locked && domain_policy_calls == before + 1U &&
		res.action == UPDATE_REC_RETURN_TO_REALM);
	result->status = res.smc_res.x[0];
	for (unsigned int i = 0U; i < 4U; i++) result->value[i] = res.smc_res.x[i + 1U];
	for (unsigned int i = 5U; i < 8U; i++) assert(res.smc_res.x[i] == 0UL);
}
static unsigned long domain_service_channel(const void *candidate)
{ return candidate == &service ? 7UL : 99UL; }
static void domain_rsi_finish(const struct gpu_firmware_ops *f, const struct gpu_private_ops *m,
		const void *s, const void *o, unsigned long t, struct gpu_private_result *r)
{
	assert(f == &fw_ops && m == &donated_ops);
	domain_rsi_call(o, GPU_PRIVATE_TASK_FINISH, t, domain_service_channel(s), 0, 0, 0, 0, r);
}
static void domain_rsi_stage(const struct gpu_firmware_ops *f, const struct gpu_private_ops *m,
		const void *s, const void *o, unsigned long g,
		const struct gpu_firmware_task_command *commands, unsigned int count,
		unsigned long flags, struct gpu_private_result *r)
{
	assert(f == &fw_ops && m == &donated_ops);
	domain_rsi_call(o, GPU_PRIVATE_TASK_STAGE_BATCH, g, (unsigned long)(uintptr_t)commands,
		domain_service_channel(s), count, flags, 0, r);
}
static void domain_rsi_prepare(const struct gpu_firmware_ops *f, const struct gpu_private_ops *m,
		const void *s, const void *o, unsigned long context, unsigned long group,
		unsigned long task, struct gpu_private_result *r)
{
	assert(f == &fw_ops && m == &donated_ops);
	domain_rsi_call(s, GPU_PRIVATE_TASK_PREPARE_LAUNCH, task,
		o == &client_a ? 7UL : o == &client_b ? 8UL : 99UL, context, group, 0, 0, r);
}
static void domain_rsi_dispatch(const struct gpu_firmware_ops *f, const struct gpu_private_ops *m,
        const void *s, const void *o, unsigned long context, unsigned long group,
        unsigned long task, struct gpu_private_result *r)
{
    assert(f == &fw_ops && m == &donated_ops);
    domain_rsi_call(s, GPU_PRIVATE_TASK_DISPATCH, task,
        o == &client_a ? 7UL : o == &client_b ? 8UL : 99UL, context, group, 0UL, 0UL, r);
}
static void domain_rsi_ready(const struct gpu_firmware_ops *f, const struct gpu_private_ops *m,
		const void *s, const void *o, unsigned long task, struct gpu_private_result *r)
{
	assert(f == &fw_ops && m == &donated_ops);
	domain_rsi_call(o, GPU_PRIVATE_TASK_READY_LAUNCH, task, domain_service_channel(s), 0, 0, 0, 0, r);
}
static void domain_rsi_cancel(const struct gpu_private_ops *m, const void *o,
		unsigned long task, struct gpu_private_result *r)
{
	assert(m == &donated_ops);
	domain_rsi_call(o, GPU_PRIVATE_TASK_CANCEL, task, 0, 0, 0, 0, 0, r);
}
/* Only domain fixtures use these routes. The rest of the backend regression
 * remains a direct independent caller of the production core APIs. */
#define gpu_firmware_task_finish_domain domain_rsi_finish
#define gpu_firmware_task_stage_domain domain_rsi_stage
#define gpu_firmware_task_prepare_launch domain_rsi_prepare
#define gpu_firmware_task_ready_launch domain_rsi_ready
#define gpu_firmware_task_cancel_staged domain_rsi_cancel

#define gpu_firmware_task_dispatch domain_rsi_dispatch
