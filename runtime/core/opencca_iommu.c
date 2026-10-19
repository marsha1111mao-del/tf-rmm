/* SPDX-License-Identifier: BSD-3-Clause */
#include <limits.h>
#include <opencca_iommu.h>
#include <string.h>

#define TABLE_ENTRIES 1024U
#define MAX_BINDINGS 8U
#define HANDLE_PREFIX 0xcca1000000000000UL
#define HANDLE_PREFIX_MASK 0xffff000000000000UL
#define PA_LIMIT (1UL << 40U)
#define IOVA_LIMIT (1UL << 32U)
#define PTE_VALID 1U
#define DOMAIN_READY 1U
#define DOMAIN_QUIESCED 2U
#define DOMAIN_QUARANTINED 3U

struct iommu_domain {
	const void *owner;
	unsigned long handle;
	unsigned long devices[MAX_BINDINGS];
	unsigned long grants[MAX_BINDINGS];
	unsigned int root;
	unsigned int mapped;
	unsigned int generation;
	unsigned int state;
};

/* Real hardware-format DT/PT pages, not a Host shadow or permission ledger.
 * The platform maps RMM RW memory identically. Page zero is permanently an
 * empty root used to park detached devices without enabling bypass.
 */
static uint32_t tables[OPENCCA_IOMMU_TABLE_PAGES][TABLE_ENTRIES]
	__attribute__((aligned(4096)));
static unsigned long table_owner[OPENCCA_IOMMU_TABLE_PAGES];
/* Guest IPA + valid bit. Retained after a failed invalidation, including
 * when the hardware PTE has already been cleared. Host entries use zero.
 */
static unsigned long source_ipas[OPENCCA_IOMMU_TABLE_PAGES][TABLE_ENTRIES];
static struct iommu_domain domains[OPENCCA_IOMMU_DOMAINS];

bool opencca_iommu_secure_handle(unsigned long handle)
{
	return (handle & HANDLE_PREFIX_MASK) == HANDLE_PREFIX;
}

static bool range_valid(unsigned long base, unsigned long size,
			unsigned long limit)
{
	return size != 0UL && ((base | size) & 4095UL) == 0UL &&
	       base < limit && size <= limit - base;
}

static uint32_t encode_pa(unsigned long pa)
{
	return (uint32_t)((pa & 0xfffff000UL) |
			 ((pa >> 24U) & 0xf00UL) |
			 ((pa >> 32U) & 0xf0UL)) | PTE_VALID;
}

static unsigned long decode_pa(uint32_t entry)
{
	return ((unsigned long)entry & 0xfffff000UL) |
	       (((unsigned long)entry & 0xf00UL) << 24U) |
	       (((unsigned long)entry & 0xf0UL) << 32U);
}

static struct iommu_domain *lookup_handle(unsigned long handle)
{
	unsigned long slot = handle & 0xffffUL;
	struct iommu_domain *domain;

	if (!opencca_iommu_secure_handle(handle) || slot == 0UL ||
	    slot > OPENCCA_IOMMU_DOMAINS)
		return NULL;
	domain = &domains[slot - 1UL];
	if (domain->state == 0U || domain->handle != handle)
		return NULL;
	return domain;
}

static struct iommu_domain *lookup(const void *owner, unsigned long handle)
{
	struct iommu_domain *domain = lookup_handle(handle);

	return domain != NULL && domain->owner == owner ? domain : NULL;
}

static bool has_grants(const struct iommu_domain *domain)
{
	for (unsigned int slot = 0U; slot < MAX_BINDINGS; slot++) {
		if (domain->grants[slot] != 0UL)
			return true;
	}
	return false;
}

static struct iommu_domain *grantor(unsigned long handle, unsigned long device)
{
	for (unsigned int domain = 0U; domain < OPENCCA_IOMMU_DOMAINS; domain++) {
		if (domains[domain].state == 0U || domains[domain].owner != NULL)
			continue;
		for (unsigned int slot = 0U; slot < MAX_BINDINGS; slot++) {
			if (domains[domain].grants[slot] == handle &&
			    (device == 0UL || domains[domain].devices[slot] == device))
				return &domains[domain];
		}
	}
	return NULL;
}

static void device_grant(const struct opencca_iommu_ops *ops,
		unsigned long operation, unsigned long device, unsigned long handle,
		struct opencca_iommu_result *result)
{
	struct iommu_domain *host = NULL, *guest;
	unsigned int slot = 0U;

	if (!ops->device_valid(device))
		return;
	for (unsigned int domain = 0U; domain < OPENCCA_IOMMU_DOMAINS; domain++) {
		if (domains[domain].state == 0U || domains[domain].owner != NULL)
			continue;
		for (slot = 0U; slot < MAX_BINDINGS; slot++) {
			if (domains[domain].devices[slot] == device) {
				host = &domains[domain];
				break;
			}
		}
		if (host != NULL)
			break;
	}
	result->status = OPENCCA_IOMMU_STATE;
	if (host == NULL)
		return;
	if (operation == OPENCCA_IOMMU_GRANT) {
		guest = lookup_handle(handle);
		if (guest == NULL || guest->owner == NULL ||
		    guest->state == DOMAIN_QUARANTINED ||
		    host->state != DOMAIN_READY || host->mapped != 0U ||
		    host->grants[slot] != 0UL)
			return;
	} else {
		guest = lookup_handle(host->grants[slot]);
		if (guest == NULL || handle != 0UL)
			return;
	}
	ops->clean(tables[0], sizeof(tables[0]));
	if (!ops->device(device, ops->table_pa(tables[0]), OPENCCA_IOMMU_DEVICE_PARK)) {
		host->state = DOMAIN_QUARANTINED;
		if (operation == OPENCCA_IOMMU_REVOKE)
			guest->state = DOMAIN_QUARANTINED;
		return;
	}
	if (operation == OPENCCA_IOMMU_GRANT) {
		host->grants[slot] = handle;
	} else {
		for (unsigned int binding = 0U; binding < MAX_BINDINGS; binding++) {
			if (guest->devices[binding] == device)
				guest->devices[binding] = 0UL;
		}
		if (!ops->device(device, ops->table_pa(tables[host->root]),
				 OPENCCA_IOMMU_DEVICE_BIND)) {
			host->state = DOMAIN_QUARANTINED;
			return;
		}
		host->grants[slot] = 0UL;
		host->state = DOMAIN_READY;
	}
	result->status = OPENCCA_IOMMU_SUCCESS;
	result->value[0] = host->handle;
}

static unsigned int alloc_table(const struct opencca_iommu_ops *ops,
			       unsigned long handle)
{
	for (unsigned int i = 1U; i < OPENCCA_IOMMU_TABLE_PAGES; i++) {
		unsigned long pa;

		if (table_owner[i] != 0UL)
			continue;
		pa = ops->table_pa(tables[i]);
		if (!range_valid(pa, OPENCCA_IOMMU_PAGE_SIZE, PA_LIMIT))
			return 0U;
		table_owner[i] = handle;
		memset(tables[i], 0, sizeof(tables[i]));
		memset(source_ipas[i], 0, sizeof(source_ipas[i]));
		ops->clean(tables[i], sizeof(tables[i]));
		return i;
	}
	return 0U;
}

static unsigned int leaf_table(const struct opencca_iommu_ops *ops,
		struct iommu_domain *domain, unsigned long iova, bool allocate)
{
	unsigned int index = (unsigned int)(iova >> 22U);
	uint32_t entry = tables[domain->root][index];
	unsigned int page;

	if ((entry & PTE_VALID) == 0U) {
		if (!allocate)
			return 0U;
		page = alloc_table(ops, domain->handle);
		if (page != 0U)
			tables[domain->root][index] = encode_pa(ops->table_pa(tables[page]));
		return page;
	}
	/* The fixed pool is physically contiguous. Resolve only its own pages;
	 * no external pointer or Host table can enter this walk.
	 */
	if (decode_pa(entry) >= ops->table_pa(tables[0])) {
		unsigned long offset = decode_pa(entry) - ops->table_pa(tables[0]);

		page = (unsigned int)(offset / 4096UL);
		if ((offset & 4095UL) == 0UL && page > 0U &&
		    page < OPENCCA_IOMMU_TABLE_PAGES && table_owner[page] == domain->handle)
			return page;
	}
	return 0U;
}

static bool devices_command(const struct opencca_iommu_ops *ops,
		struct iommu_domain *domain, enum opencca_iommu_device_command command)
{
	unsigned long root = ops->table_pa(tables[domain->root]);

	for (unsigned int i = 0U; i < MAX_BINDINGS; i++) {
		if (domain->devices[i] != 0UL &&
		    !ops->device(domain->devices[i], root, command)) {
			domain->state = DOMAIN_QUARANTINED;
			return false;
		}
	}
	return true;
}

static void clean_range(const struct opencca_iommu_ops *ops,
		struct iommu_domain *domain, unsigned long iova, size_t count)
{
	unsigned int previous = 0U;

	for (size_t i = 0U; i < count; i++) {
		unsigned int page = leaf_table(ops, domain, iova + i * 4096UL, false);

		if (page != 0U && page != previous)
			ops->clean(tables[page], sizeof(tables[page]));
		previous = page;
	}
	/* Publish initialized leaves before their new directory entries. */
	ops->clean(tables[domain->root], sizeof(tables[domain->root]));
}

static size_t run_length(const unsigned long *pages, size_t first, size_t count)
{
	size_t end = first + 1U;

	while (end < count && pages[end] == pages[end - 1U] + 4096UL)
		end++;
	return end - first;
}

void opencca_iommu_map(const struct opencca_iommu_ops *ops, const void *owner,
		unsigned long handle, unsigned long iova,
		const unsigned long *pages, size_t count, unsigned long prot,
		unsigned long source_ipa, struct opencca_iommu_result *result)
{
	struct iommu_domain *domain = lookup(owner, handle);
	size_t reserved = 0U;
	bool was_quiesced;

	memset(result, 0, sizeof(*result));
	result->status = OPENCCA_IOMMU_INPUT;
	if (domain == NULL || pages == NULL || count == 0U ||
	    count > OPENCCA_IOMMU_BATCH_PAGES || prot == 0UL || (prot & ~3UL) != 0UL ||
	    !range_valid(iova, count * 4096UL, IOVA_LIMIT) ||
	    (owner != NULL && !range_valid(source_ipa, count * 4096UL, ULONG_MAX)))
		return;
	if (domain->state == DOMAIN_QUARANTINED || has_grants(domain)) {
		result->status = OPENCCA_IOMMU_STATE;
		return;
	}
	was_quiesced = domain->state == DOMAIN_QUIESCED;
	for (size_t i = 0U; i < count; i++) {
		unsigned long address = iova + i * 4096UL;
		unsigned int page = leaf_table(ops, domain, address, false);

		if (!range_valid(pages[i], 4096UL, PA_LIMIT) ||
		    (page != 0U && (tables[page][(address >> 12U) & 1023UL] & PTE_VALID)))
			return;
	}
	/* Allocate before taking physical reservations. Empty leaves are retained
	 * until domain destruction, avoiding stale DTE pointers to reused pages.
	 */
	for (size_t i = 0U; i < count; i++) {
		if (leaf_table(ops, domain, iova + i * 4096UL, true) == 0U) {
			result->status = OPENCCA_IOMMU_FULL;
			return;
		}
	}
	while (reserved < count) {
		size_t run = run_length(pages, reserved, count);

		if (!ops->reserve(handle, iova + reserved * 4096UL,
				  pages[reserved], run * 4096UL))
			goto rollback;
		reserved += run;
	}
	if (!devices_command(ops, domain, OPENCCA_IOMMU_DEVICE_STALL)) {
		result->status = OPENCCA_IOMMU_STATE;
		goto rollback;
	}
	for (size_t i = 0U; i < count; i++) {
		unsigned long address = iova + i * 4096UL;
		unsigned int page = leaf_table(ops, domain, address, false);
		unsigned int entry = (unsigned int)((address >> 12U) & 1023UL);

		tables[page][entry] = encode_pa(pages[i]) | (uint32_t)(prot << 1U);
		source_ipas[page][entry] = owner == NULL ? 0UL : (source_ipa + i * 4096UL) | 1UL;
	}
	domain->mapped += (unsigned int)count;
	clean_range(ops, domain, iova, count);
	if (!devices_command(ops, domain, OPENCCA_IOMMU_DEVICE_INVALIDATE) ||
	    (!was_quiesced && !devices_command(ops, domain, OPENCCA_IOMMU_DEVICE_RESUME))) {
		/* Hardware may have observed the new tables: retain every lease and
		 * table, and quarantine the domain rather than trusting Host cleanup.
		 */
		result->status = OPENCCA_IOMMU_STATE;
		return;
	}
	result->status = OPENCCA_IOMMU_SUCCESS;
	result->value[0] = count * 4096UL;
	return;
rollback:
	if (reserved != 0U && !ops->retire(handle, iova, reserved * 4096UL)) {
		domain->state = DOMAIN_QUARANTINED;
		result->status = OPENCCA_IOMMU_STATE;
	}
}

static void unmap(const struct opencca_iommu_ops *ops, struct iommu_domain *domain,
		unsigned long iova, unsigned long size, struct opencca_iommu_result *result)
{
	size_t count = 0U;
	bool was_quiesced = domain->state == DOMAIN_QUIESCED;

	if (!range_valid(iova, size, IOVA_LIMIT))
		return;
	/* Match iommu_unmap(): stop at the first hole and report actual bytes. */
	for (; count < size / 4096UL; count++) {
		unsigned long address = iova + count * 4096UL;
		unsigned int page = leaf_table(ops, domain, address, false);

		if (page == 0U || !(tables[page][(address >> 12U) & 1023UL] & PTE_VALID))
			break;
	}
	if (count == 0U) {
		result->status = OPENCCA_IOMMU_SUCCESS;
		return;
	}
	if (!devices_command(ops, domain, OPENCCA_IOMMU_DEVICE_STALL)) {
		result->status = OPENCCA_IOMMU_STATE;
		return;
	}
	for (size_t i = 0U; i < count; i++) {
		unsigned long address = iova + i * 4096UL;
		unsigned int page = leaf_table(ops, domain, address, false);

		tables[page][(address >> 12U) & 1023UL] = 0U;
	}
	clean_range(ops, domain, iova, count);
	if (!devices_command(ops, domain, OPENCCA_IOMMU_DEVICE_INVALIDATE) ||
	    !ops->retire(domain->handle, iova, count * 4096UL)) {
		domain->state = DOMAIN_QUARANTINED;
		result->status = OPENCCA_IOMMU_STATE;
		return;
	}
	for (size_t i = 0U; i < count; i++) {
		unsigned long address = iova + i * 4096UL;
		unsigned int page = leaf_table(ops, domain, address, false);

		source_ipas[page][(address >> 12U) & 1023UL] = 0UL;
	}
	domain->mapped -= (unsigned int)count;
	/* A resume failure cannot reinstate the cleared translations. Report
	 * the completed unmap, but quarantine all subsequent modifications.
	 */
	if (!was_quiesced)
		(void)devices_command(ops, domain, OPENCCA_IOMMU_DEVICE_RESUME);
	result->status = OPENCCA_IOMMU_SUCCESS;
	result->value[0] = count * 4096UL;
}

void opencca_iommu_call(const struct opencca_iommu_ops *ops, const void *owner,
		unsigned long operation, unsigned long handle,
		unsigned long arg1, unsigned long arg2, unsigned long arg3,
		struct opencca_iommu_result *result)
{
	struct iommu_domain *domain;

	memset(result, 0, sizeof(*result));
	result->status = OPENCCA_IOMMU_INPUT;
	if (operation == OPENCCA_IOMMU_GRANT || operation == OPENCCA_IOMMU_REVOKE) {
		if (owner == NULL && handle == 0UL && arg3 == 0UL)
			device_grant(ops, operation, arg1, arg2, result);
		return;
	}
	if (operation == OPENCCA_IOMMU_VERSION && (handle | arg1 | arg2 | arg3) == 0UL) {
		result->status = OPENCCA_IOMMU_SUCCESS;
		result->value[0] = OPENCCA_IOMMU_ABI;
		result->value[1] = OPENCCA_IOMMU_SIMULATED_PROTECTION;
		result->value[2] = OPENCCA_IOMMU_DOMAINS;
		result->value[3] = OPENCCA_IOMMU_TABLE_PAGES;
		return;
	}
	if (operation == OPENCCA_IOMMU_CREATE && (handle | arg1 | arg2 | arg3) == 0UL) {
		result->status = OPENCCA_IOMMU_FULL;
		for (unsigned int i = 0U; i < OPENCCA_IOMMU_DOMAINS; i++) {
			unsigned int root;

			domain = &domains[i];
			if (domain->state != 0U || domain->generation == UINT_MAX)
				continue;
			domain->generation++;
			handle = HANDLE_PREFIX | ((unsigned long)domain->generation << 16U) | (i + 1UL);
			root = alloc_table(ops, handle);
			if (root == 0U)
				return;
			domain->owner = owner;
			domain->handle = handle;
			domain->root = root;
			domain->mapped = 0U;
			domain->state = DOMAIN_READY;
			memset(domain->devices, 0, sizeof(domain->devices));
			memset(domain->grants, 0, sizeof(domain->grants));
			result->status = OPENCCA_IOMMU_SUCCESS;
			result->value[0] = handle;
			result->value[1] = ops->table_pa(tables[root]);
			return;
		}
		return;
	}
	domain = lookup(owner, handle);
	if (domain == NULL || arg2 != 0UL ||
	    (operation != OPENCCA_IOMMU_UNMAP && arg3 != 0UL))
		return;
	if (operation == OPENCCA_IOMMU_QUERY) {
		unsigned int page;
		uint32_t pte = 0U;

		if (arg1 >= IOVA_LIMIT)
			return;
		page = leaf_table(ops, domain, arg1, false);
		if (page != 0U)
			pte = tables[page][(arg1 >> 12U) & 1023UL];
		result->status = OPENCCA_IOMMU_SUCCESS;
		if (pte & PTE_VALID) {
			result->value[0] = decode_pa(pte) | (arg1 & 4095UL);
			result->value[1] = (pte >> 1U) & 3U;
		}
		result->value[2] = ops->table_pa(tables[domain->root]);
		result->value[3] = domain->mapped;
		return;
	}
	if (operation == OPENCCA_IOMMU_FAULT) {
		struct iommu_domain *effective = domain;
		struct iommu_domain *host = owner == NULL ? domain : grantor(handle, arg1);
		unsigned int slot;
		unsigned long root = ops->table_pa(tables[domain->root]);
		bool guest = owner != NULL;

		if (ops->fault == NULL || arg1 == 0UL || !ops->device_valid(arg1))
			return;
		for (slot = 0U; slot < MAX_BINDINGS; slot++) {
			if (domain->devices[slot] == arg1)
				break;
		}
		if (slot == MAX_BINDINGS)
			return;
		if (domain->grants[slot] != 0UL) {
			effective = lookup_handle(domain->grants[slot]);
			if (effective == NULL)
				return;
			guest = true;
			root = ops->table_pa(tables[0]);
			for (unsigned int binding = 0U; binding < MAX_BINDINGS; binding++) {
				if (effective->devices[binding] == arg1) {
					root = ops->table_pa(tables[effective->root]);
					break;
				}
			}
		}
		if (host == NULL) {
			result->status = OPENCCA_IOMMU_STATE;
			return;
		}
		if (host->state == DOMAIN_QUARANTINED || effective->state == DOMAIN_QUARANTINED ||
		    !ops->fault(arg1, root, result)) {
			host->state = DOMAIN_QUARANTINED;
			effective->state = DOMAIN_QUARANTINED;
			result->status = OPENCCA_IOMMU_STATE;
			return;
		}
		if (guest)
			result->value[0] |= OPENCCA_IOMMU_FAULT_GUEST;
		result->value[3] = effective->handle;
		result->status = OPENCCA_IOMMU_SUCCESS;
		return;
	}
	if (domain->state == DOMAIN_QUARANTINED || has_grants(domain)) {
		result->status = OPENCCA_IOMMU_STATE;
		return;
	}
	if (operation == OPENCCA_IOMMU_UNMAP) {
		unmap(ops, domain, arg1, arg3, result);
		return;
	}
	if (operation == OPENCCA_IOMMU_BIND) {
		unsigned int free_slot = MAX_BINDINGS;
		bool was_quiesced = domain->state == DOMAIN_QUIESCED;
		struct iommu_domain *host = owner == NULL ? NULL : grantor(handle, arg1);

		if (!ops->device_valid(arg1))
			return;
		if (owner != NULL && (host == NULL || host->state == DOMAIN_QUARANTINED)) {
			result->status = OPENCCA_IOMMU_STATE;
			return;
		}
		for (unsigned int d = 0U; d < OPENCCA_IOMMU_DOMAINS; d++) {
			for (unsigned int i = 0U; i < MAX_BINDINGS; i++) {
				if (domains[d].devices[i] == arg1 && &domains[d] != domain &&
				    (&domains[d] != host || domains[d].grants[i] != handle)) {
					result->status = OPENCCA_IOMMU_STATE;
					return;
				}
			}
		}
		for (unsigned int i = 0U; i < MAX_BINDINGS; i++) {
			if (domain->devices[i] == arg1) {
				free_slot = i;
				break;
			}
			if (domain->devices[i] == 0UL)
				free_slot = i;
		}
		if (free_slot == MAX_BINDINGS) {
			result->status = OPENCCA_IOMMU_FULL;
			return;
		}
		/* Retain ownership even if hardware programming partially fails. */
		domain->devices[free_slot] = arg1;
		if (!ops->device(arg1, ops->table_pa(tables[domain->root]),
				 OPENCCA_IOMMU_DEVICE_BIND)) {
			domain->state = DOMAIN_QUARANTINED;
			result->status = OPENCCA_IOMMU_STATE;
			return;
		}
		/* BIND is also the powered-on reactivation operation. A previously
		 * quiesced domain may contain other banks; resume them together.
		 */
		if (was_quiesced && !devices_command(ops, domain, OPENCCA_IOMMU_DEVICE_RESUME)) {
			result->status = OPENCCA_IOMMU_STATE;
			return;
		}
		domain->state = DOMAIN_READY;
		result->status = OPENCCA_IOMMU_SUCCESS;
		return;
	}
	if (operation == OPENCCA_IOMMU_UNBIND) {
		for (unsigned int i = 0U; i < MAX_BINDINGS; i++) {
			if (domain->devices[i] != arg1 || arg1 == 0UL)
				continue;
			ops->clean(tables[0], sizeof(tables[0]));
			if (!ops->device(arg1, ops->table_pa(tables[0]), OPENCCA_IOMMU_DEVICE_PARK)) {
				domain->state = DOMAIN_QUARANTINED;
				result->status = OPENCCA_IOMMU_STATE;
				return;
			}
			domain->devices[i] = 0UL;
			result->status = OPENCCA_IOMMU_SUCCESS;
			return;
		}
		return;
	}
	if (arg1 != 0UL)
		return;
	if (operation == OPENCCA_IOMMU_QUIESCE) {
		if (devices_command(ops, domain, OPENCCA_IOMMU_DEVICE_STALL)) {
			domain->state = DOMAIN_QUIESCED;
			result->status = OPENCCA_IOMMU_SUCCESS;
		} else {
			result->status = OPENCCA_IOMMU_STATE;
		}
		return;
	}
	if (operation == OPENCCA_IOMMU_DESTROY) {
		result->status = OPENCCA_IOMMU_STATE;
		if (domain->mapped != 0U || grantor(handle, 0UL) != NULL)
			return;
		for (unsigned int i = 0U; i < MAX_BINDINGS; i++) {
			if (domain->devices[i] != 0UL)
				return;
		}
		for (unsigned int i = 1U; i < OPENCCA_IOMMU_TABLE_PAGES; i++) {
			if (table_owner[i] == handle) {
				memset(tables[i], 0, sizeof(tables[i]));
				memset(source_ipas[i], 0, sizeof(source_ipas[i]));
				ops->clean(tables[i], sizeof(tables[i]));
				table_owner[i] = 0UL;
			}
		}
		domain->state = 0U;
		domain->owner = NULL;
		domain->handle = 0UL;
		result->status = OPENCCA_IOMMU_SUCCESS;
	}
}

bool opencca_iommu_owner_busy(const void *owner)
{
	if (owner == NULL)
		return false;
	for (unsigned int i = 0U; i < OPENCCA_IOMMU_DOMAINS; i++) {
		if (domains[i].state != 0U && domains[i].owner == owner)
			return true;
	}
	return false;
}

bool opencca_iommu_range_busy(const void *owner, unsigned long ipa, unsigned long size)
{
	if (owner == NULL || size == 0UL)
		return false;
	if (size > ULONG_MAX - ipa)
		return true;
	for (unsigned int d = 0U; d < OPENCCA_IOMMU_DOMAINS; d++) {
		if (domains[d].state == 0U || domains[d].owner != owner)
			continue;
		for (unsigned int p = 1U; p < OPENCCA_IOMMU_TABLE_PAGES; p++) {
			if (table_owner[p] != domains[d].handle)
				continue;
			for (unsigned int e = 0U; e < TABLE_ENTRIES; e++) {
				unsigned long source = source_ipas[p][e];

				if ((source & 1UL) != 0UL && (source & ~4095UL) < ipa + size &&
				    ipa < (source & ~4095UL) + 4096UL)
					return true;
			}
		}
	}
	return false;
}
