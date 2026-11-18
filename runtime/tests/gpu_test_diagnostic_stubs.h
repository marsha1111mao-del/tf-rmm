/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef GPU_TEST_DIAGNOSTIC_STUBS_H
#define GPU_TEST_DIAGNOSTIC_STUBS_H
#include <assert.h>
#include <stdbool.h>
/* Legacy task/RTT fixtures never request optional diagnostic selectors.
 * Any unexpected invocation is a test failure. The separate actual-routing
 * suite covers those selectors, real auth and mapping-lock forwarding.
 */
void control_view_statistics(unsigned long values[4])
{ (void)values; assert(!"unexpected diagnostic in legacy task fixture"); }
bool opencca_gpu_root_statistics(unsigned int selector, unsigned long values[4])
{ (void)selector; (void)values; assert(!"unexpected root diagnostic"); return false; }
#endif
