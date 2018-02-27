/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

#include <uzfs_task.h>
#include <sys/spa_impl.h>

#ifndef	_UZFS_H

#define	_UZFS_H

typedef int (*const uzfs_pool_task_func_t)(void *spa);

typedef struct uzfs_pool_task_funcs {
	uzfs_pool_task_func_t open_func;
	uzfs_pool_task_func_t close_func;
} uzfs_pool_task_funcs_t;

#define	UZFS_POOL_MAX_TASKS	3

typedef struct uzfs_spa {
	boolean_t	tasks_initialized[UZFS_POOL_MAX_TASKS];
	boolean_t	close_pool;
	kmutex_t	mtx;
	kcondvar_t	cv;
	kthread_t	*update_txg_tid;
} uzfs_spa_t;

extern uzfs_pool_task_funcs_t uzfs_pool_tasks[UZFS_POOL_MAX_TASKS];

#define	uzfs_spa(s)	((uzfs_spa_t *)(s->spa_us))

#endif
