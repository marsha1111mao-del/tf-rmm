/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef GPU_TEST_MEMORY_FALLBACK_H
#define GPU_TEST_MEMORY_FALLBACK_H
#include <assert.h>
/* These old RTT/cache fixtures have NULL pin/unpin callbacks, so exercise
 * the original temporary-map path. Persistent mapping/cache/TLB/RO-table
 * behavior is covered by dedicated actual-source suites, not this fallback.
 */
static void *control_view_address(unsigned long pa) { (void)pa; return NULL; }
static void gpu_test_unexpected_persistent_isb(void)
{ assert(!"persistent path used by temporary-mapping-only fixture"); }
#ifndef isb
#define isb() gpu_test_unexpected_persistent_isb()
#endif
#endif
