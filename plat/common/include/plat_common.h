/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */

#ifndef PLAT_COMMON_H
#define PLAT_COMMON_H

/* Forward declaration */
struct xlat_mmap_region;

int plat_cmn_init_el3_ifc(unsigned long x0, unsigned long x1,
		   unsigned long x2, unsigned long x3);
int plat_cmn_setup(struct xlat_mmap_region *plat_regions,
		   unsigned int nregions);
int plat_cmn_warmboot_setup(void);

/* RMM-only VA slots, not additional physical control-page capacity. */
#define PLAT_CMN_GPU_CONTROL_BASE 0xf0000000UL
#define PLAT_CMN_GPU_CONTROL_SLOTS 8192U
int plat_cmn_gpu_control_map(unsigned int index, unsigned long pa, void **address);
int plat_cmn_gpu_control_unmap(unsigned int index, unsigned long pa);

#endif /* PLAT_COMMON_H */
