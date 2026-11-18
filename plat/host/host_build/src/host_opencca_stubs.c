/* SPDX-License-Identifier: BSD-3-Clause */

#include <opencca_gpu.h>
#include <opencca_iommu.h>

bool plat_opencca_gpu_reset(bool preserve_irqs)
{
	(void)preserve_irqs;
	return true;
}

bool plat_opencca_gpu_opp_valid(unsigned long frequency)
{
	(void)frequency;
	return false;
}

unsigned long plat_opencca_gpu_pa_bits(void)
{
	return 0UL;
}

bool plat_opencca_gpu_pt_install(unsigned long root, unsigned int slot)
{
	(void)root;
	(void)slot;
	return false;
}

bool plat_opencca_gpu_pt_sync(unsigned long root)
{
	(void)root;
	return false;
}

bool plat_opencca_gpu_pt_prepare(unsigned long root, unsigned int slot,
				 unsigned long firmware_root, bool existing)
{
	(void)root;
	(void)slot;
	(void)firmware_root;
	(void)existing;
	return false;
}

bool plat_opencca_gpu_pt_check_running(unsigned long root, unsigned int slot,
					unsigned long firmware_root,
					struct gpu_firmware_config *config)
{
	(void)root;
	(void)slot;
	(void)firmware_root;
	(void)config;
	return false;
}

bool plat_opencca_gpu_pt_extend(unsigned long root, unsigned int slot,
				 unsigned long firmware_root)
{
	(void)root;
	(void)slot;
	(void)firmware_root;
	return false;
}

bool plat_opencca_gpu_pt_flush_live(unsigned long root, unsigned int slot,
				     unsigned long firmware_root)
{
	(void)root;
	(void)slot;
	(void)firmware_root;
	return false;
}

bool plat_opencca_gpu_pt_detach(unsigned long root, unsigned int slot,
				 unsigned long firmware_root, bool detached)
{
	(void)root;
	(void)slot;
	(void)firmware_root;
	(void)detached;
	return false;
}

bool plat_opencca_gpu_firmware_install(unsigned long root)
{
	(void)root;
	return false;
}

bool plat_opencca_gpu_firmware_boot(unsigned long root)
{
	(void)root;
	return false;
}

bool plat_opencca_gpu_firmware_configuration(unsigned long root,
					      struct gpu_firmware_config *config)
{
	(void)root;
	(void)config;
	return false;
}

bool plat_opencca_gpu_firmware_notify(unsigned long root)
{
	(void)root;
	return false;
}

bool plat_opencca_iommu_device_valid(unsigned long device)
{
	(void)device;
	return false;
}

bool plat_opencca_iommu_mmio_overlaps(unsigned long pa, unsigned long size)
{
	(void)pa;
	(void)size;
	return false;
}

bool plat_opencca_iommu_device(unsigned long device, unsigned long root,
				enum opencca_iommu_device_command command)
{
	(void)device;
	(void)root;
	(void)command;
	return false;
}

bool plat_opencca_iommu_fault(unsigned long device, unsigned long root,
			       struct opencca_iommu_result *result)
{
	(void)device;
	(void)root;
	(void)result;
	return false;
}
