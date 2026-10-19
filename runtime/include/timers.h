/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */

#ifndef TIMERS_H
#define TIMERS_H

#include <stdbool.h>

struct rec;
struct rmi_rec_exit;

bool check_pending_timers(struct rec *rec);
void report_timer_state_to_ns(struct rmi_rec_exit *rec_exit);
bool opencca_check_pending_timers(struct rec *rec);
void plat_opencca_timers_save(void);
void plat_opencca_timers_mask(bool virtual_masked, bool physical_masked);
void plat_opencca_timers_restore(void);

#endif /* TIMERS_H */
