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

#include <uzfs.h>
#include <uzfs_zap.h>
#include <sys/dmu_objset.h>
#include <sys/zap.h>
#include <sys/uzfs_zvol.h>
#include <sys/stat.h>

int
dummy_pool_task(void *s)
{
	return (0);
}

int
post_open_pool(void *s)
{
	spa_t *spa = (spa_t *)s;

	spa->spa_us = (uzfs_spa_t *)kmem_zalloc(sizeof (uzfs_spa_t), KM_SLEEP);
	mutex_init(&(uzfs_spa(spa)->mtx), NULL, MUTEX_DEFAULT, NULL);
	cv_init(&(uzfs_spa(spa)->cv), NULL, CV_DEFAULT, NULL);
	return (0);
}

int
pre_close_pool(void *s)
{
	spa_t *spa = (spa_t *)s;
	mutex_enter(&(uzfs_spa(spa)->mtx));
	uzfs_spa(spa)->close_pool = 1;
	mutex_exit(&(uzfs_spa(spa)->mtx));
	return (0);
}

int
post_close_pool(void *s)
{
	spa_t *spa = (spa_t *)s;
	uzfs_spa_t *us = spa->spa_us;
	mutex_destroy(&(uzfs_spa(spa)->mtx));
	cv_destroy(&(uzfs_spa(spa)->cv));
	spa->spa_us = NULL;
	kmem_free(us, sizeof (uzfs_spa_t));
	return (0);
}

int
create_txg_update_thread(void *s)
{
	spa_t *spa = (spa_t *)s;

	uzfs_spa(spa)->update_txg_tid = zk_thread_create(NULL, 0,
	    (thread_func_t)uzfs_update_txg_zap_thread, spa, 0, NULL, TS_RUN, 0,
	    PTHREAD_CREATE_DETACHED);
	return (0);
}

int
close_txg_update_thread(void *s)
{
	spa_t *spa = (spa_t *)s;
	struct timespec ts;

	mutex_enter(&(uzfs_spa(spa)->mtx));
	cv_signal(&(uzfs_spa(spa)->cv));
	mutex_exit(&(uzfs_spa(spa)->mtx));

	ts.tv_sec = 0;
	ts.tv_nsec = 100000000;

	while (uzfs_spa(spa)->update_txg_tid != NULL)
		nanosleep(&ts, NULL);

	return (0);
}
