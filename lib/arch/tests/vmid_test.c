#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vmid.h>

#define THREAD_COUNT 16U

bool test_vmid16;
static pthread_barrier_t reserve_barrier;
static unsigned int race_vmid;
static bool race_reserved[THREAD_COUNT];

static void expect(bool condition, const char *name)
{
	if (!condition) {
		fprintf(stderr, "FAIL: %s\n", name);
		exit(EXIT_FAILURE);
	}
}

static void *reserve_worker(void *argument)
{
	bool *reserved = argument;
	int result = pthread_barrier_wait(&reserve_barrier);

	expect(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD,
	       "worker barrier");
	*reserved = vmid_reserve(race_vmid);
	return NULL;
}

int main(int argc, char **argv)
{
	pthread_t threads[THREAD_COUNT];
	unsigned int limit, first, vmid, worker, winners = 0U;

	expect(argc == 2 && (!strcmp(argv[1], "8") || !strcmp(argv[1], "16")),
	       "VMID width argument");
	test_vmid16 = !strcmp(argv[1], "16");
	limit = test_vmid16 ? 65536U : 256U;
	first = ENABLE_OPENCCA ? (test_vmid16 ? 32768U : 128U) : 0U;

	for (vmid = 0U; vmid < first; vmid++) {
		expect(!vmid_reserve(vmid), "reject Host/ordinary VM namespace");
	}
	expect(!vmid_reserve(limit), "reject first out-of-range VMID");
	expect(!vmid_reserve(UINT_MAX), "reject unsigned maximum");

	for (vmid = first; vmid < limit; vmid++) {
		expect(vmid_reserve(vmid), "allocate every allowed VMID");
		expect(!vmid_reserve(vmid), "reject every duplicate VMID");
	}
	for (vmid = first; vmid < limit; vmid++) {
		expect(!vmid_reserve(vmid), "exhaustion preserves reservations");
	}
	for (vmid = first; vmid < limit; vmid += 2U) {
		vmid_free(vmid);
	}
	for (vmid = first; vmid < limit; vmid++) {
		expect(vmid_reserve(vmid) == ((vmid % 2U) == 0U),
		       "reuse holes without disturbing retained VMIDs");
		vmid_free(vmid);
	}

	race_vmid = first + 63U;
	expect(pthread_barrier_init(&reserve_barrier, NULL, THREAD_COUNT) == 0,
	       "initialize concurrent reservation barrier");
	for (worker = 0U; worker < THREAD_COUNT; worker++) {
		expect(pthread_create(&threads[worker], NULL, reserve_worker,
				      &race_reserved[worker]) == 0,
		       "create reservation worker");
	}
	for (worker = 0U; worker < THREAD_COUNT; worker++) {
		expect(pthread_join(threads[worker], NULL) == 0, "join worker");
		winners += race_reserved[worker] ? 1U : 0U;
	}
	expect(winners == 1U, "only one concurrent owner");
	expect(pthread_barrier_destroy(&reserve_barrier) == 0, "destroy barrier");
	vmid_free(race_vmid);
	expect(vmid_reserve(race_vmid), "reuse concurrent reservation");
	vmid_free(race_vmid);
	printf("PASS: opencca=%u bits=%s allowed=%u..%u concurrent_owners=%u\n",
	       ENABLE_OPENCCA, argv[1], first, limit - 1U, winners);
	return EXIT_SUCCESS;
}
