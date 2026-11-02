/* SPDX-License-Identifier: BSD-3-Clause */
/* Execute the production RMI table, outer dispatcher and policy together.
 * Leaf handlers, granules, busy predicates and SIMD are test doubles. The
 * production policy lock wrappers use a checked pthread mutex, not Arm locks.
 * This tests gate placement/interleavings, not actual Realm creation or GPC.
 */
#include <assert.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <smc-rmi.h>
#include <smc-handler.h>
#include <status.h>
#include <xshm_runtime.h>
#include <granule.h>
#include <spinlock.h>

#define RD_PA 0x100000UL
#define IPA 0x400000UL
#define SENTINEL 0xbadbadbadUL
static struct granule owners[2];
static atomic_uint busy[2], leaf_calls, acquisitions, releases;
static _Thread_local bool held, saved, hint;
static _Thread_local unsigned int role, slot_checks;
static _Thread_local unsigned int saves, restores;
static _Thread_local unsigned int gate_epoch, authorization_epoch;
static _Thread_local unsigned int seen_fid;
static _Thread_local unsigned long seen_args[5];
static _Thread_local unsigned int leaf_status;
static unsigned int checks;
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t rendezvous = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static bool racing, first_inside, contender_waiting;
static unsigned int race_busy;

static void expect(bool value, const char *why)
{
	if (!value) {
		fprintf(stderr, "GPU_RMI_DISPATCH_REJECT %s\n", why);
		abort();
	}
}

void test_spinlock_acquire(spinlock_t *lock)
{
	(void)lock;
	expect(!held, "policy gate must not recurse");
	int rc = pthread_mutex_trylock(&gate);
	if (rc == EBUSY) {
		assert(pthread_mutex_lock(&rendezvous) == 0);
		if (racing && role == 2U) {
			contender_waiting = true;
			assert(pthread_cond_broadcast(&changed) == 0);
		}
		assert(pthread_mutex_unlock(&rendezvous) == 0);
		assert(pthread_mutex_lock(&gate) == 0);
	} else {
		assert(rc == 0);
	}
	held = true;
	gate_epoch++;
	atomic_fetch_add(&acquisitions, 1U);
}

void test_spinlock_release(spinlock_t *lock)
{
	(void)lock;
	expect(held, "unlock must match a held policy gate");
	held = false;
	atomic_fetch_add(&releases, 1U);
	assert(pthread_mutex_unlock(&gate) == 0);
}

struct granule *find_granule(unsigned long pa)
{
	expect(held, "authorization lookup executes under policy gate");
	authorization_epoch = gate_epoch;
	if (pa == RD_PA) return &owners[0];
	if (pa == RD_PA + 4096UL) return &owners[1];
	return NULL;
}

static bool owner_busy(const void *owner, unsigned int mask)
{
	expect(held, "busy predicate executes under policy gate");
	assert(owner == &owners[0] || owner == &owners[1]);
	return (atomic_load(&busy[owner == &owners[1]]) & mask) != 0U;
}
static bool range_busy(const void *owner, unsigned long base,
		       unsigned long size, unsigned int mask)
{
	return owner_busy(owner, mask) && base <= IPA && size > IPA - base;
}
bool xshm_memory_owner_busy(const void *o) { return owner_busy(o, 1U); }
bool gpu_private_owner_busy(const void *o) { return owner_busy(o, 2U); }
bool opencca_iommu_owner_busy(const void *o) { return owner_busy(o, 4U); }
bool xshm_memory_range_busy(const void *o, unsigned long b, unsigned long s)
{ return range_busy(o, b, s, 1U); }
bool gpu_private_range_busy(const void *o, unsigned long b, unsigned long s)
{ return range_busy(o, b, s, 2U); }
bool opencca_iommu_range_busy(const void *o, unsigned long b, unsigned long s)
{ return range_busy(o, b, s, 4U); }

struct simd_context { unsigned int unused; };
static _Thread_local struct simd_context simd;
static bool check_cpu_slots_empty(void) { slot_checks++; return true; }
static bool simd_is_state_saved(void) { return saved; }
static struct simd_context *get_cpu_ns_simd_context(void) { return &simd; }
static void simd_update_smc_sve_hint(struct simd_context *s, bool value)
{ assert(s == &simd); hint = value; }
static __unused void simd_context_save(struct simd_context *s)
{ assert(s == &simd && !saved); saved = true; saves++; }
static __unused void simd_context_restore(struct simd_context *s)
{ assert(s == &simd && saved); saved = false; restores++; }
static void test_log(const char *format, ...) __printflike(1, 2);
static void test_log(const char *format, ...) { (void)format; }
#define INFO(...) test_log(__VA_ARGS__)
#define VERBOSE(...) test_log(__VA_ARGS__)

static unsigned long result_word(unsigned int fid, const unsigned long a[5], unsigned int i)
{
	unsigned long value = fid + i;
	for (unsigned int j = 0; j < 5U; j++) value = value * 33UL + a[j];
	return value;
}

static unsigned long leaf(unsigned int fid, const unsigned long a[5],
			 struct smc_result *res, unsigned int outputs)
{
	expect(held == (fid != SMC_RMI_REC_ENTER), "handler executes inside its required gate");
	if (fid != SMC_RMI_REC_ENTER)
		expect(authorization_epoch == gate_epoch, "authorization and execution share one uninterrupted gate");
	seen_fid = fid;
	memcpy(seen_args, a, sizeof(seen_args));
	atomic_fetch_add(&leaf_calls, 1U);
	if (fid == SMC_RMI_REC_ENTER) {
		/* Realm-side RSI may take the policy gate during REC_ENTER. */
		xshm_policy_lock(); xshm_policy_unlock();
	}
	if (racing && role == 1U) {
		assert(pthread_mutex_lock(&rendezvous) == 0);
		first_inside = true;
		assert(pthread_cond_broadcast(&changed) == 0);
		while (!contender_waiting)
			assert(pthread_cond_wait(&changed, &rendezvous) == 0);
		expect(atomic_load(&leaf_calls) == 1U, "contender cannot dispatch during authorized mutation");
		/* Model a registration/release at the end of a leaf transaction. */
		atomic_store(&busy[0], race_busy);
		assert(pthread_mutex_unlock(&rendezvous) == 0);
	}
	if (res != NULL) {
		res->x[0] = leaf_status;
		for (unsigned int i = 1U; i <= outputs; i++) res->x[i] = result_word(fid, a, i);
	}
	return leaf_status;
}

/* Generated solely from the production HANDLER entries. Leaves intentionally
 * remain doubles, with their prototypes checked against smc-handler.h. */
#include "rmi-leaves.inc"
/* Unchanged production table, FID handling, logging and handle_ns_smc body. */
#include "rmi-dispatch.inc"
#include "rmi-cases.inc"

static void inputs(unsigned int fid, unsigned long a[5])
{
	unsigned long values[] = { RD_PA, IPA, 3UL, IPA + 4096UL, 0xabcUL };
	memcpy(a, values, sizeof(values));
	if (fid == SMC_RMI_DATA_CREATE || fid == SMC_RMI_DATA_CREATE_UNKNOWN ||
	    fid == SMC_RMI_RTT_SET_RIPAS) a[2] = IPA;
	if (fid == SMC_RMI_RTT_INIT_RIPAS) a[2] = IPA + 4096UL;
}
static struct smc_result invoke(unsigned int fid, const unsigned long a[5])
{
	struct smc_result res;
	for (unsigned int i = 0; i < SMC_RESULT_REGS; i++) res.x[i] = SENTINEL;
	unsigned int old_slots = slot_checks, old_saves = saves;
	seen_fid = 0U;
	handle_ns_smc(fid, a[0], a[1], a[2], a[3], a[4], 0xdeadUL, &res);
	expect(!held && !saved && saves == restores, "return balances policy gate and SIMD state");
	unsigned int clean_fid = fid & ~SMC_SVE_HINT;
	bool known = false;
	for (size_t i = 0; i < ARRAY_SIZE(cases); i++) known |= clean_fid == cases[i].fid;
	expect(slot_checks - old_slots == (known ? 2U : 0U), "known dispatch checks CPU slots before and after");
	unsigned int expected_saves = 0U;
#ifdef RMM_FPU_USE_AT_REL2
	if (known && (clean_fid == SMC_RMI_REALM_CREATE || clean_fid == SMC_RMI_DATA_CREATE ||
	    clean_fid == SMC_RMI_REC_CREATE || clean_fid == SMC_RMI_RTT_INIT_RIPAS)) expected_saves = 1U;
#endif
	expect(saves - old_saves == expected_saves, "SIMD save and restore follow production FID policy");
	return res;
}

static void test_routing(void)
{
	for (size_t c = 0; c < ARRAY_SIZE(cases); c++) {
		for (unsigned int sve = 0; sve < 2U; sve++) {
			unsigned long a[5]; inputs(cases[c].fid, a);
			unsigned int before = atomic_load(&leaf_calls);
			struct smc_result res = invoke(cases[c].fid | (sve ? SMC_SVE_HINT : 0U), a);
			expect(res.x[0] == RMI_SUCCESS && seen_fid == cases[c].fid &&
			       atomic_load(&leaf_calls) == before + 1U, "valid FID selects exactly its production leaf");
			expect(hint == (sve != 0U), "SVE hint is stripped from dispatch and delivered to SIMD");
			unsigned long expected[5] = {0};
			memcpy(expected, a, cases[c].inputs * sizeof(unsigned long));
			expect(memcmp(expected, seen_args, sizeof(expected)) == 0, "all argument positions retain their ABI order");
			for (unsigned int i = 1U; i < SMC_RESULT_REGS; i++)
				expect(res.x[i] == (i <= cases[c].outputs ? result_word(cases[c].fid, expected, i) : SENTINEL),
				       "successful result registers follow the production handler ABI");
			checks++;
		}
	}
}

static void test_denials(void)
{
	const unsigned int protected[] = { SMC_RMI_REALM_DESTROY, SMC_RMI_DATA_CREATE,
		SMC_RMI_DATA_CREATE_UNKNOWN, SMC_RMI_DATA_DESTROY, SMC_RMI_RTT_FOLD,
		SMC_RMI_RTT_DESTROY, SMC_RMI_RTT_INIT_RIPAS, SMC_RMI_RTT_SET_RIPAS };
	for (size_t c = 0; c < ARRAY_SIZE(protected); c++) {
		for (unsigned int mask = 1U; mask <= 4U; mask <<= 1U) {
			for (unsigned int sve = 0; sve < 2U; sve++) {
				unsigned long a[5]; inputs(protected[c], a);
				atomic_store(&busy[0], mask);
				unsigned int before = atomic_load(&leaf_calls);
				struct smc_result res = invoke(protected[c] | (sve ? SMC_SVE_HINT : 0U), a);
				expect(res.x[0] == RMI_ERROR_INPUT && seen_fid == 0U &&
				       atomic_load(&leaf_calls) == before, "busy policy rejection never calls a leaf");
				for (unsigned int i = 1U; i < SMC_RESULT_REGS; i++)
					expect(res.x[i] == 0UL, "policy rejection clears every result register");
				/* The same IPA in another Realm must remain usable. */
				a[0] += 4096UL;
				res = invoke(protected[c], a);
				expect(res.x[0] == RMI_SUCCESS && seen_fid == protected[c], "busy Client does not block unrelated Client");
				atomic_store(&busy[0], 0U);
				checks += 2U;
			}
		}
	}
	for (unsigned int mask = 1U; mask <= 4U; mask <<= 1U) {
		atomic_store(&busy[0], mask);
		for (unsigned int side = 0U; side < 2U; side++) {
			unsigned long a[5]; inputs(SMC_RMI_DATA_DESTROY, a);
			a[1] = side ? IPA + 4096UL : IPA - 4096UL;
			struct smc_result res = invoke(SMC_RMI_DATA_DESTROY, a);
			expect(res.x[0] == RMI_SUCCESS && seen_fid == SMC_RMI_DATA_DESTROY,
			       "busy range does not block disjoint pages of the same Client"); checks++;
		}
	}
	atomic_store(&busy[0], 0U);
}

static void *race_first(void *unused)
{
	(void)unused; role = 1U;
	unsigned long a[5]; inputs(SMC_RMI_OPENCCA_GPU_PM, a);
	struct smc_result res = invoke(SMC_RMI_OPENCCA_GPU_PM, a);
	expect(res.x[0] == RMI_SUCCESS, "first authorized mutation finishes");
	return NULL;
}
static void *race_second(void *unused)
{
	(void)unused; role = 2U;
	unsigned long a[5]; inputs(SMC_RMI_DATA_DESTROY, a);
	struct smc_result res = invoke(SMC_RMI_DATA_DESTROY, a);
	expect(res.x[0] == (race_busy ? RMI_ERROR_INPUT : RMI_SUCCESS),
	       "contender authorizes against the committed state after the first leaf");
	return NULL;
}
static void test_interleavings(void)
{
	for (unsigned int mask = 0U; mask <= 4U; mask = mask == 0U ? 1U : mask * 2U) {
		for (unsigned int repeat = 0; repeat < 8U; repeat++) {
			atomic_store(&busy[0], mask ? 0U : 2U);
			atomic_store(&leaf_calls, 0U);
			first_inside = contender_waiting = false;
			race_busy = mask; racing = true;
			pthread_t first, second;
			assert(pthread_create(&first, NULL, race_first, NULL) == 0);
			assert(pthread_mutex_lock(&rendezvous) == 0);
			while (!first_inside) assert(pthread_cond_wait(&changed, &rendezvous) == 0);
			assert(pthread_mutex_unlock(&rendezvous) == 0);
			assert(pthread_create(&second, NULL, race_second, NULL) == 0);
			assert(pthread_join(first, NULL) == 0);
			assert(pthread_join(second, NULL) == 0);
			expect(atomic_load(&leaf_calls) == (mask ? 1U : 2U), "serialized transaction has exact dispatch count");
			racing = false; checks++;
		}
	}
	atomic_store(&busy[0], 0U);
}

int main(void)
{
	test_routing();
	test_denials();
	/* Real table holes as well as FIDs outside the RMI range. */
	for (unsigned int offset = 0; offset <= SMC64_NUM_FIDS_IN_RANGE(RMI) + 1U; offset++) {
		unsigned int fid = SMC64_RMI_FID(offset); bool known = false;
		for (size_t i = 0; i < ARRAY_SIZE(cases); i++) known |= cases[i].fid == fid;
		if (known) continue;
		unsigned long a[5]; inputs(fid, a);
		unsigned int before = atomic_load(&acquisitions);
		struct smc_result res = invoke(fid, a);
		expect(res.x[0] == SMC_UNKNOWN && seen_fid == 0U && before == atomic_load(&acquisitions),
		       "unknown FID has no dispatch or lock side effect"); checks++;
	}
	/* A genuine handler error must also release the gate and retain outputs. */
	unsigned long a[5]; inputs(SMC_RMI_DATA_DESTROY, a);
	leaf_status = RMI_ERROR_RTT;
	struct smc_result res = invoke(SMC_RMI_DATA_DESTROY, a);
	expect(res.x[0] == RMI_ERROR_RTT && seen_fid == SMC_RMI_DATA_DESTROY,
	       "leaf error preserves its actual status");
	a[2] = a[3] = a[4] = 0UL;
	for (unsigned int i = 1U; i <= 2U; i++)
		expect(res.x[i] == result_word(SMC_RMI_DATA_DESTROY, a, i),
		       "leaf error retains actual output values after unlocking");
	leaf_status = RMI_SUCCESS; checks++;
	test_interleavings();
	expect(atomic_load(&acquisitions) == atomic_load(&releases), "all acquired gates released");
	printf("GPU_RMI_DISPATCH=PASS checks=%u handlers=%zu interleavings=32 fpu=%u\n",
	       checks, ARRAY_SIZE(cases),
#ifdef RMM_FPU_USE_AT_REL2
	       1U
#else
	       0U
#endif
	);
	return 0;
}
