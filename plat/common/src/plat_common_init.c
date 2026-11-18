/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */

#ifndef CBMC

#include <arch_helpers.h>
#include <assert.h>
#include <buffer.h>
#include <cpuid.h>
#include <debug.h>
#include <errno.h>
#include <gic.h>
#include <plat_cmn_arch.h>
#include <plat_common.h>
#include <rmm_el3_ifc.h>
#include <sizes.h>
#include <stdint.h>
#include <string.h>
#include <xlat_contexts.h>
#include <xlat_high_va.h>
#include <xlat_tables.h>


IMPORT_SYM(uintptr_t, rmm_text_start, RMM_CODE_START);
IMPORT_SYM(uintptr_t, rmm_text_end, RMM_CODE_END);
IMPORT_SYM(uintptr_t, rmm_ro_start, RMM_RO_START);
IMPORT_SYM(uintptr_t, rmm_ro_end, RMM_RO_END);
IMPORT_SYM(uintptr_t, rmm_rw_start, RMM_RW_START);
IMPORT_SYM(uintptr_t, rmm_rw_end, RMM_RW_END);

/*
 * Memory map REGIONS used for the RMM runtime (static mappings)
 */
#define RMM_CODE_SIZE		(RMM_CODE_END - RMM_CODE_START)
#define RMM_RO_SIZE		(RMM_RO_END - RMM_RO_START)
#define RMM_RW_SIZE		(RMM_RW_END - RMM_RW_START)

#define RMM_CODE		MAP_REGION_FLAT(			\
					RMM_CODE_START,			\
					RMM_CODE_SIZE,			\
					(MT_CODE | MT_REALM))

#define RMM_RO			MAP_REGION_FLAT(			\
					RMM_RO_START,			\
					RMM_RO_SIZE,			\
					(MT_RO_DATA | MT_REALM))

#define RMM_RW			MAP_REGION_FLAT(			\
					RMM_RW_START,			\
					RMM_RW_SIZE,			\
					(MT_RW_DATA | MT_REALM))

/*
 * Leave an invalid page between the end of RMM memory and the beginning
 * of the shared buffer VA. This will help to detect any memory access
 * underflow by RMM.
 */
#define RMM_SHARED_BUFFER_START	(RMM_RW_END + SZ_4K)

/*
 * Some of the fields for the RMM_SHARED region will be populated
 * at runtime.
 */
#define RMM_SHARED		MAP_REGION(				\
					0U,				\
					RMM_SHARED_BUFFER_START,	\
					0U,				\
					(MT_RW_DATA | MT_REALM))

/* RMM supports only a single console */
#define RMM_CSL			MAP_REGION_FLAT(			\
					0,				\
					0,				\
					(MT_DEVICE | MT_RW | MT_REALM))

/* Number of common memory mapping regions */
#define COMMON_REGIONS		(4U)

/* Total number of memory mapping regions */
#define TOTAL_MMAP_REGIONS	(COMMON_REGIONS + PLAT_CMN_EXTRA_MMAP_REGIONS)

/* Memory mapping regions for the system runtime */
static struct xlat_mmap_region static_regions[TOTAL_MMAP_REGIONS];

/*
 * Allocate the runtime translation tables.
 * Although a base table at level -1 when FEAT_LPA2 is enabled only has
 * 16 entries, all tables are allocated a page for simplicity.
 */
#define GPU_CONTROL_LEAF_TABLES (PLAT_CMN_GPU_CONTROL_SLOTS / XLAT_TABLE_ENTRIES)
#define GPU_CONTROL_STATIC_TABLES (PLAT_CMN_CTX_MAX_XLAT_TABLES - GPU_CONTROL_LEAF_TABLES)
_Static_assert(PLAT_CMN_CTX_MAX_XLAT_TABLES > GPU_CONTROL_LEAF_TABLES,
	"Preserve the total original S1 table budget");
static uint64_t gpu_control_s1tt[GPU_CONTROL_LEAF_TABLES][XLAT_TABLE_ENTRIES]
	__aligned(XLAT_TABLES_ALIGNMENT);
/* Only dedicated control leaves are writable. Code, MMIO, ordinary data
 * mappings and upper tables remain in the original protected RO section.
 */
static uint64_t static_s1tt[XLAT_TABLE_ENTRIES * GPU_CONTROL_STATIC_TABLES]
					__aligned(XLAT_TABLES_ALIGNMENT)
					__section("xlat_static_tables");

/* Structures to hold the runtime translation context information  */
static struct xlat_ctx_tbls runtime_tbls;
static struct xlat_ctx_cfg runtime_xlat_ctx_cfg;
static struct xlat_ctx runtime_xlat_ctx;

/* The low-VA tables are shared by RMM PEs. The ordinary xlat transient
 * helpers invalidate only the local PE and cannot retire these aliases alone.
 */
static void gpu_control_publish_tte(struct xlat_llt_info *table, uintptr_t va)
{
	uint64_t *entry = xlat_get_tte_ptr(table, va);

	assert(entry != NULL);
	clean_dcache_range((uintptr_t)entry, sizeof(*entry));
	dsb(ishst);
	tlbivae2is(TLBI_ADDR(va));
	dsb(ish);
	isb();
}

int plat_cmn_gpu_control_map(unsigned int index, unsigned long pa, void **address)
{
	struct xlat_llt_info table;
	uintptr_t va;

	if (index >= PLAT_CMN_GPU_CONTROL_SLOTS || address == NULL ||
	    pa == 0UL || !GRANULE_ALIGNED(pa) || pa >= (1UL << 40U) ||
	    !XLAT_TABLES_CTX_CFG_VALID(&runtime_xlat_ctx))
		return -EINVAL;
	va = PLAT_CMN_GPU_CONTROL_BASE + (uintptr_t)index * GRANULE_SIZE;
	if (xlat_get_llt_from_va(&table, &runtime_xlat_ctx, va) != 0 ||
	    table.level != 3 || table.table != &gpu_control_s1tt[index / XLAT_TABLE_ENTRIES][0] ||
	    xlat_map_memory_page_with_attrs(&table, va, pa,
		XLAT_NG_DATA_ATTR | MT_REALM) != 0)
		return -EFAULT;
	gpu_control_publish_tte(&table, va);
	*address = (void *)va;
	return 0;
}

int plat_cmn_gpu_control_unmap(unsigned int index, unsigned long pa)
{
	struct xlat_llt_info table;
	uintptr_t va;
	uint64_t *entry, descriptor;

	if (index >= PLAT_CMN_GPU_CONTROL_SLOTS || pa == 0UL ||
	    !GRANULE_ALIGNED(pa) || pa >= (1UL << 40U) ||
	    !XLAT_TABLES_CTX_CFG_VALID(&runtime_xlat_ctx))
		return -EINVAL;
	va = PLAT_CMN_GPU_CONTROL_BASE + (uintptr_t)index * GRANULE_SIZE;
	if (xlat_get_llt_from_va(&table, &runtime_xlat_ctx, va) != 0 || table.level != 3 ||
	    table.table != &gpu_control_s1tt[index / XLAT_TABLE_ENTRIES][0])
		return -EFAULT;
	entry = xlat_get_tte_ptr(&table, va);
	if (entry == NULL)
		return -EFAULT;
	descriptor = xlat_read_tte(entry);
	/* A failed earlier installation/unmap may leave an invalid transient
	 * entry. Still broadcast invalidation before releasing its lifetime hold.
	 * Never unmap an unexpected valid target or a non-transient entry.
	 */
	if (descriptor != TRANSIENT_DESC) {
		if ((descriptor & (TRANSIENT_DESC | 3UL)) != (TRANSIENT_DESC | 3UL) ||
		    (descriptor & UINT64_C(0x000000fffffff000)) != pa ||
		    xlat_unmap_memory_page(&table, va) != 0)
			return -EFAULT;
	}
	gpu_control_publish_tte(&table, va);
	return 0;
}


static int gpu_control_install_leaf_tables(void)
{
	/* Cold boot only, before any PE enables these tables. Select exactly
	 * the L2 parent of each preallocated, wholly invalid control L3 table.
	 * Never change runtime permissions of the immutable table pool.
	 */
	assert(!is_mmu_enabled());
	for (unsigned int i = 0U; i < GPU_CONTROL_LEAF_TABLES; i++) {
		uintptr_t va = PLAT_CMN_GPU_CONTROL_BASE +
			(uintptr_t)i * XLAT_TABLE_ENTRIES * GRANULE_SIZE;
		uint64_t *parent = runtime_tbls.tables;
		struct xlat_llt_info leaf;

		for (int level = runtime_xlat_ctx_cfg.base_level; level < 2; level++) {
			unsigned int index = (unsigned int)((va >> XLAT_ADDR_SHIFT(level)) &
				(XLAT_TABLE_ENTRIES - 1U));
			uint64_t desc = xlat_read_tte(&parent[index]);
			if ((desc & 3UL) != 3UL) return -EFAULT;
			parent = (void *)(uintptr_t)(desc & UINT64_C(0x0000fffffffff000));
		}
		unsigned int index = (unsigned int)((va >> XLAT_ADDR_SHIFT(2)) &
			(XLAT_TABLE_ENTRIES - 1U));
		uint64_t desc = xlat_read_tte(&parent[index]);
		if ((desc & 3UL) != 3UL ||
		    xlat_get_llt_from_va(&leaf, &runtime_xlat_ctx, va) != 0 || leaf.level != 3 ||
		    (uintptr_t)leaf.table != (desc & UINT64_C(0x0000fffffffff000)))
			return -EFAULT;
		for (unsigned int j = 0U; j < XLAT_TABLE_ENTRIES; j++) {
			if (xlat_read_tte(&leaf.table[j]) != TRANSIENT_DESC) return -EFAULT;
			gpu_control_s1tt[i][j] = TRANSIENT_DESC;
		}
		xlat_write_tte(&parent[index],
			(desc & ~UINT64_C(0x0000fffffffff000)) |
			(uintptr_t)&gpu_control_s1tt[i][0]);
	}
	clean_dcache_range((uintptr_t)gpu_control_s1tt, sizeof(gpu_control_s1tt));
	clean_dcache_range((uintptr_t)static_s1tt, sizeof(static_s1tt));
	dsb(sy);
	return 0;
}


int plat_cmn_init_el3_ifc(unsigned long x0, unsigned long x1,
			   unsigned long x2, unsigned long x3)
{
	/* Initialize the RMM <-> EL3 interface */
	return rmm_el3_ifc_init(x0, x1, x2, x3, get_shared_buf_va(x3));
}

/*
 * Platform common cold boot setup for RMM.
 *
 * This function should only be invoked once during cold boot
 * and is expected to setup architecture and platform components
 * common for all PEs executing RMM. The rmm_el3_ifc, the xlat tables
 * and GIC driver are initialized by this function.
 */
int plat_cmn_setup(struct xlat_mmap_region *plat_regions,
		   unsigned int nregions)
{
	int ret;
	unsigned int plat_offset, cmn_offset;

	/* Common regions sorted by ascending VA */
	struct xlat_mmap_region regions[COMMON_REGIONS] = {
		RMM_CODE,
		RMM_RO,
		RMM_RW,
		RMM_SHARED
	};

	if (nregions > PLAT_CMN_EXTRA_MMAP_REGIONS) {
		return -ERANGE;
	}

	if ((nregions != 0U) && (plat_regions == NULL)) {
		return -EINVAL;
	}

	/* Setup the parameters of the shared area */
	regions[3].base_pa = get_shared_buf_pa();
	regions[3].size = rmm_el3_ifc_get_shared_buf_size();

	plat_offset = COMMON_REGIONS;
	cmn_offset = 0U;
	if (nregions != 0U) {
		/*
		 * Combine the common memory regions with the platform ones
		 * in an array where they are sorted as per VA.
		 */
		if (plat_regions[0].base_va < RMM_CODE_START) {
			plat_offset = 0U;
			cmn_offset = nregions;
		}
		(void)memcpy((void *)&static_regions[plat_offset],
			     (void *)&plat_regions[0U],
			     sizeof(struct xlat_mmap_region) * nregions);
	}

	(void)memcpy((void *)&static_regions[cmn_offset], (void *)&regions[0U],
		     sizeof(struct xlat_mmap_region) * COMMON_REGIONS);

	ret = xlat_ctx_cfg_init(&runtime_xlat_ctx_cfg, VA_LOW_REGION,
				&static_regions[0], nregions + COMMON_REGIONS,
				PLAT_CMN_VIRT_ADDR_SPACE_SIZE);

	if (ret != 0) {
		ERROR("%s (%u): %s (%i)\n",
			__func__, __LINE__,
			"Failed to initialize the xlat ctx within the xlat library ",
			ret);
		return ret;
	}

	ret = xlat_ctx_init(&runtime_xlat_ctx, &runtime_xlat_ctx_cfg,
			    &runtime_tbls,
			    &static_s1tt[0],
			    GPU_CONTROL_STATIC_TABLES);

	if (ret != 0) {
		ERROR("%s (%u): %s (%i)\n",
			__func__, __LINE__,
			"Failed to create the xlat ctx within the xlat library ",
			ret);
		return ret;
	}

	ret = gpu_control_install_leaf_tables();
	if (ret != 0) return ret;

	/* Read supported GIC virtualization features and init GIC variables */
	gic_get_virt_features();

	return 0;
}

/*
 * Local PE common platform setup for RMM.
 *
 * This function will only be invoked during
 * warm boot and is expected to setup architecture and platform
 * components local to a PE executing RMM.
 */
int plat_cmn_warmboot_setup(void)
{
	int ret;
	struct xlat_mmu_cfg mmu_config;


	/* Setup the MMU cfg for the low region (runtime context) */
	ret = xlat_arch_setup_mmu_cfg(&runtime_xlat_ctx, &mmu_config);
	if (ret != 0) {
		ERROR("%s (%u): Failed to setup xlat tables for CPU[%u]\n",
			__func__, __LINE__, my_cpuid());
		return ret;
	}

	xlat_arch_write_mmu_cfg(&mmu_config);

	/* Perform warm boot initialization of the high VA region */
	ret = xlat_high_va_setup();
	if (ret != 0) {
		ERROR("%s (%u): Failed to setup high VA for CPU[%u]\n",
			__func__, __LINE__, my_cpuid());
		return ret;
	}

	VERBOSE("xlat tables configured for CPU[%u]\n", my_cpuid());
	return 0;
}

#endif /* CBMC */
