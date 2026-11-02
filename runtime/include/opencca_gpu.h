/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef OPENCCA_GPU_H
#define OPENCCA_GPU_H

#include <stdbool.h>

struct gpu_firmware_config;

#define OPENCCA_GPU_MMIO_BASE 0xfb000000UL
#define OPENCCA_GPU_MMIO_SIZE 0x200000UL

/* RMI GPU_PM: x1=operation, x2=argument, x3=completion error. RESET and
 * RELEASE execute the reset in RMM; Host cannot assert reset completion.
 */
enum opencca_gpu_operation {
	OPENCCA_GPU_RESET = 0U,
	OPENCCA_GPU_RELEASE = 1U,
	OPENCCA_GPU_OPP_BEGIN = 2U,
	OPENCCA_GPU_OPP_END = 3U,
	OPENCCA_GPU_STATUS = 4U,
	OPENCCA_GPU_POWER_OFF = 5U,
	OPENCCA_GPU_POWER_ON = 6U,
	/* Host cleanup request: argument is an RD, never a page/root address.
	 * RMM requires zero RECs, a non-NEW Realm and trusted GPU revocation.
	 */
	OPENCCA_GPU_PRIVATE_RECLAIM = 7U
};

enum opencca_gpu_state {
	OPENCCA_GPU_UNOWNED,
	OPENCCA_GPU_DESIGNATED,
	OPENCCA_GPU_RUNNING,
	OPENCCA_GPU_RESETTING,
	OPENCCA_GPU_POWERING,
	OPENCCA_GPU_QUARANTINED,
	OPENCCA_GPU_REVOKED,
	OPENCCA_GPU_DESTROYING,
	OPENCCA_GPU_OFF,
	/* Authenticated service retained, raw MMIO revoked and reset verified. */
	OPENCCA_GPU_MEDIATED
};

struct opencca_gpu_ops {
	bool (*reset)(bool preserve_irqs);
	bool (*revoke_mmio)(const void *owner);
	bool (*opp_valid)(unsigned long frequency);
};

/* All state/lease operations are serialized by the adapter's mapping lock. */
bool opencca_gpu_mmio_grant(const void *owner);
bool opencca_gpu_mmio_allowed(const void *owner);
bool opencca_gpu_mmio_running(const void *owner);
bool opencca_gpu_service_running(const void *owner);
bool opencca_gpu_service_isolated(const void *owner);
/* Service-initiated, irreversible until owner teardown. This is a control
 * handoff, not permission to run firmware or launch a private workload.
 */
bool opencca_gpu_service_isolate(const struct opencca_gpu_ops *ops,
		const void *owner);
/* RSI adapter: mapping lock + trusted reset + private-context revocation.
 * The caller must hold xshm_policy_lock.
 */
bool opencca_gpu_isolate_service(const void *owner);
/* Internal trusted callbacks: no RSI accepts a root HPA or register script. */
bool opencca_gpu_private_pt_install(unsigned long root, unsigned int slot);
bool opencca_gpu_private_pt_sync(unsigned long root);
bool opencca_gpu_private_pt_prepare(unsigned long root, unsigned int slot, unsigned long firmware_root, bool existing);
bool opencca_gpu_private_pt_check_running(unsigned long root, unsigned int slot,
		unsigned long firmware_root, struct gpu_firmware_config *config);
bool opencca_gpu_private_pt_extend(unsigned long root, unsigned int slot, unsigned long firmware_root);
bool opencca_gpu_private_pt_flush_live(unsigned long root, unsigned int slot, unsigned long firmware_root);
bool opencca_gpu_private_pt_detach(unsigned long root, unsigned int slot, unsigned long firmware_root, bool detached);
bool opencca_gpu_firmware_install(unsigned long root);
bool opencca_gpu_firmware_boot(unsigned long root);
bool opencca_gpu_firmware_configuration(unsigned long root, struct gpu_firmware_config *config);
bool opencca_gpu_firmware_notify(unsigned long root);
bool opencca_gpu_mapping_allowed(const void *owner, unsigned long ipa,
		unsigned long pa, unsigned long size, unsigned long shared_base);
bool opencca_gpu_authorize_mapping(const void *owner, unsigned long ipa,
		unsigned long pa, unsigned long size, unsigned long shared_base);
bool opencca_gpu_claim(const void *owner);
bool opencca_gpu_control(const struct opencca_gpu_ops *ops, const void *caller,
			 unsigned long operation, unsigned long argument,
			 unsigned long error);
enum opencca_gpu_state opencca_gpu_state(void);
void opencca_gpu_mmio_release(const void *owner);
bool opencca_gpu_pm_destroy_blocked(const void *owner);
bool opencca_gpu_pm_destroy_begin(const void *owner);

bool plat_opencca_gpu_reset(bool preserve_irqs);
bool plat_opencca_gpu_opp_valid(unsigned long frequency);
unsigned long plat_opencca_gpu_pa_bits(void);
/* Client PT backend supports only an isolated, stopped MCU/GPU. Slot zero is
 * reserved for the trusted firmware address space. These operations
 * configure translation, never enable the MCU or ring a doorbell.
 */
bool plat_opencca_gpu_pt_install(unsigned long root, unsigned int slot);
bool plat_opencca_gpu_pt_sync(unsigned long root);
/* Prepare an unused nonzero Client AS while the trusted MCU remains running.
 * Repeated matching roots are checked without reprogramming a live AS.
 */
bool plat_opencca_gpu_pt_prepare(unsigned long root, unsigned int slot, unsigned long firmware_root, bool existing);
bool plat_opencca_gpu_pt_check_running(unsigned long root, unsigned int slot,
		unsigned long firmware_root, struct gpu_firmware_config *config);
/* Additive leaf publication only: check exact live roots/attributes and no
 * duplicate AS, issue PT flush, then check again. Does not change any root.
 */
bool plat_opencca_gpu_pt_extend(unsigned long root, unsigned int slot, unsigned long firmware_root);
/* Trusted memory visibility primitive, also used by detach before disabling
 * the AS. Validate the same live roots/configuration around LOCK/FLUSH_MEM;
 * leave translation, queues and ownership intact. This does not establish
 * job completion or quiescence, stop later writes, return CPU cache ownership,
 * or authorize reuse/reclamation. A future live consumer must prove those
 * separate conditions. Failure may follow partial MMIO: retain all backing.
 */
bool plat_opencca_gpu_pt_flush_live(unsigned long root, unsigned int slot, unsigned long firmware_root);
/* Only after trusted firmware has stopped every CSG referencing this AS.
 * Flush MEM, clear root/attributes, switch to UNMAPPED and wait for UPDATE.
 * A detached replay checks disabled hardware without writing registers.
 */
bool plat_opencca_gpu_pt_detach(unsigned long root, unsigned int slot, unsigned long firmware_root, bool detached);
/* Internal fixed policy: pinned arch10.8 image, AS0 only, no Client queues. */
bool plat_opencca_gpu_firmware_install(unsigned long root);
bool plat_opencca_gpu_firmware_boot(unsigned long root);
bool plat_opencca_gpu_firmware_configuration(unsigned long root, struct gpu_firmware_config *config);
bool plat_opencca_gpu_firmware_notify(unsigned long root);

#endif
