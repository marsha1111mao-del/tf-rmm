/* SPDX-License-Identifier: BSD-3-Clause */
typedef unsigned int spinlock_t;
static inline void spinlock_acquire(spinlock_t *lock) { (void)lock; }
static inline void spinlock_release(spinlock_t *lock) { (void)lock; }
