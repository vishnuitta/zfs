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

/*
 * Copyright (c) 2018 CloudByte, Inc. All rights reserved.
 */

#include <gtest/gtest.h>
#include <unistd.h>

/* Avoid including conflicting C++ declarations for LE-BE conversions */
#define _SYS_BYTEORDER_H
#include <sys/spa.h>
#include <libuzfs.h>
#include <mgmt_conn.h>
#include <uzfs_mgmt.h>

char *ds_name;
char *pool;
spa_t *spa;
zvol_state_t *zv;
zvol_info_t *zinfo;

extern void (*zinfo_create_hook)(zvol_info_t *, nvlist_t *);
extern void (*zinfo_destroy_hook)(zvol_info_t *);

void
make_vdev(const char *path)
{
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
	if (fd == -1) {
		printf("can't open %s", path);
		exit(1);
	}
	if (ftruncate(fd, 1024*1024*1024) != 0) {
		printf("can't ftruncate %s", path);
		exit(1);
	}
	(void) close(fd);
}

void
setup_unit_test(char *path)
{
	make_vdev(path);
}

/* This will be called once for uZFS tests */
TEST(uZFS, Setup) {
	char *path;
	int ret;
	char *pool_ds;
	ds_name = (char *)malloc(MAXNAMELEN);
	pool_ds = (char *)malloc(MAXNAMELEN);
	path = (char *)malloc(MAXNAMELEN);
	pool = (char *)malloc(MAXNAMELEN);

	strncpy(path, "/tmp/uztest.1a", MAXNAMELEN);
	strncpy(pool, "pool1", MAXNAMELEN);
	strncpy(ds_name, "vol1", MAXNAMELEN);
	strncpy(pool_ds, "pool1/vol1", MAXNAMELEN);

	uzfs_init();
	setup_unit_test(path);
	ret = uzfs_create_pool(pool, path, &spa);
	EXPECT_EQ(0, ret);

	uzfs_create_dataset(spa, ds_name, 1024*1024*1024, 512, &zv);

	mutex_init(&conn_list_mtx, NULL, MUTEX_DEFAULT, NULL);
	SLIST_INIT(&uzfs_mgmt_conns);
	mgmt_eventfd = -1;

	zinfo_create_hook = &zinfo_create_cb;
	zinfo_destroy_hook = &zinfo_destroy_cb;

	uzfs_zinfo_init(zv, pool_ds, NULL);
	zinfo = uzfs_zinfo_lookup(ds_name);
	EXPECT_EQ(0, !zinfo);

	EXPECT_GT(kthread_nr, 0);
}

int
slist_count(struct uzfs_mgmt_conn_list *list)
{
	int count = 0;
	uzfs_mgmt_conn_t *mgmt_conn;

	SLIST_FOREACH(mgmt_conn, list, conn_next)
		count++;

	return count;
}

TEST(uZFS, EmptyCreateProps) {
	uzfs_mgmt_conn_t *conn;

	EXPECT_EQ(1, slist_count(&uzfs_mgmt_conns));
	conn = SLIST_FIRST(&uzfs_mgmt_conns);
	EXPECT_EQ(1, conn->conn_refcount);

	zinfo_create_cb(zinfo, NULL);
	EXPECT_EQ(1, slist_count(&uzfs_mgmt_conns));
	conn = SLIST_FIRST(&uzfs_mgmt_conns);
	EXPECT_EQ(2, conn->conn_refcount);
}

TEST(uZFS, TestZInfoRefcnt) {
	int ret;
	zvol_info_t *zinfo1;
 	char *ds1 = (char *)malloc(MAXNAMELEN);

	EXPECT_EQ(2, zinfo->refcnt);

	uzfs_zinfo_drop_refcnt(zinfo, B_FALSE);
	EXPECT_EQ(1, zinfo->refcnt);

	strncpy(ds1, "vol1 ", MAXNAMELEN);
	zinfo1 = uzfs_zinfo_lookup(ds1);
	EXPECT_EQ(NULL, zinfo1);

	strncpy(ds1, "vol2", MAXNAMELEN);
	zinfo1 = uzfs_zinfo_lookup(ds1);
	EXPECT_EQ(NULL, zinfo1);

	strncpy(ds1, "vol", MAXNAMELEN);
	zinfo1 = uzfs_zinfo_lookup(ds1);
	EXPECT_EQ(NULL, zinfo1);

	strncpy(ds1, "pool1/vol", MAXNAMELEN);
	zinfo1 = uzfs_zinfo_lookup(ds1);
	EXPECT_EQ(NULL, zinfo1);

	strncpy(ds1, "pool1/vol1 ", MAXNAMELEN);
	zinfo1 = uzfs_zinfo_lookup(ds1);
	EXPECT_EQ(NULL, zinfo1);

	strncpy(ds1, "pool1/vol1/", MAXNAMELEN);
	zinfo1 = uzfs_zinfo_lookup(ds1);
	EXPECT_EQ(NULL, zinfo1);

	strncpy(ds1, "pool1/vol1", MAXNAMELEN);
	zinfo1 = uzfs_zinfo_lookup(ds1);
	EXPECT_EQ(NULL, zinfo1);

	zinfo1 = uzfs_zinfo_lookup(NULL);
	EXPECT_EQ(NULL, zinfo1);

	strncpy(ds1, "vol1", MAXNAMELEN);
	zinfo1 = uzfs_zinfo_lookup(ds1);
	EXPECT_EQ(NULL, !zinfo1);
	EXPECT_EQ(2, zinfo->refcnt);
}

void
set_start_rebuild_mgmt_ack(mgmt_ack_t *mack, const char *dw_name, const char *volname)
{
	strncpy(mack->dw_volname, dw_name, MAXNAMELEN);
	if (volname != NULL)
		strncpy(mack->volname, volname, MAXNAMELEN);
}

void
set_zvol_io_hdr(zvol_io_hdr_t *hdrp, zvol_op_status_t status,
    zvol_op_code_t opcode, int len)
{
	hdrp->version = REPLICA_VERSION;
	hdrp->status = status;
	hdrp->opcode = opcode;
	hdrp->len = len;
}

TEST(uZFS, TestStartRebuild) {
	int i;
	uzfs_mgmt_conn_t *conn;
	mgmt_ack_t *mack;

	zvol_rebuild_status_t rebuild_status[5];
	rebuild_status[0] = ZVOL_REBUILDING_INIT;
	rebuild_status[1] = ZVOL_REBUILDING_IN_PROGRESS;
	rebuild_status[2] = ZVOL_REBUILDING_DONE;
	rebuild_status[3] = ZVOL_REBUILDING_ERRORED;
	rebuild_status[4] = ZVOL_REBUILDING_FAILED;

	EXPECT_EQ(1, slist_count(&uzfs_mgmt_conns));
	EXPECT_EQ(2, zinfo->refcnt);
	conn = SLIST_FIRST(&uzfs_mgmt_conns);

	zvol_io_hdr_t *hdrp = (zvol_io_hdr_t *)kmem_zalloc(sizeof (*hdrp), KM_SLEEP);
	void *payload = kmem_zalloc(sizeof (mgmt_ack_t) * 5, KM_SLEEP);
	mack = (mgmt_ack_t *)payload;

	/* payload is 0 */
	set_zvol_io_hdr(hdrp, ZVOL_OP_STATUS_OK, ZVOL_OPCODE_PREPARE_FOR_REBUILD, 0);
	handle_start_rebuild_req(conn, hdrp, NULL, 0);
	EXPECT_EQ(ZVOL_OP_STATUS_FAILED, ((zvol_io_hdr_t *)conn->conn_buf)->status);
	EXPECT_EQ(2, zinfo->refcnt);

	/* NULL name in payload */
	set_zvol_io_hdr(hdrp, ZVOL_OP_STATUS_OK, ZVOL_OPCODE_PREPARE_FOR_REBUILD, sizeof (mgmt_ack_t));
	handle_start_rebuild_req(conn, hdrp, payload, sizeof (mgmt_ack_t));
	EXPECT_EQ(ZVOL_OP_STATUS_FAILED, ((zvol_io_hdr_t *)conn->conn_buf)->status);
	EXPECT_EQ(2, zinfo->refcnt);

	/* invalid name in payload */
	set_start_rebuild_mgmt_ack(mack, "vol2", NULL);
	handle_start_rebuild_req(conn, hdrp, payload, sizeof (mgmt_ack_t));
	EXPECT_EQ(ZVOL_OP_STATUS_FAILED, ((zvol_io_hdr_t *)conn->conn_buf)->status);
	EXPECT_EQ(2, zinfo->refcnt);

	/* invalid rebuild state */
	for (i = 1; i < 5; i++) {
		uzfs_zvol_set_rebuild_status(zinfo->zv,
		    rebuild_status[i]);
		set_start_rebuild_mgmt_ack(mack, "vol1", NULL);
		handle_start_rebuild_req(conn, hdrp, payload, sizeof (mgmt_ack_t));
		EXPECT_EQ(ZVOL_OP_STATUS_FAILED, ((zvol_io_hdr_t *)conn->conn_buf)->status);
		EXPECT_EQ(2, zinfo->refcnt);
	}

	/* rebuild for single replica case */
	uzfs_zvol_set_rebuild_status(zinfo->zv,
	    ZVOL_REBUILDING_INIT);
	set_start_rebuild_mgmt_ack(mack, "vol1", NULL);
	handle_start_rebuild_req(conn, hdrp, payload, sizeof (mgmt_ack_t));
	EXPECT_EQ(ZVOL_OP_STATUS_OK, ((zvol_io_hdr_t *)conn->conn_buf)->status);
	EXPECT_EQ(ZVOL_REBUILDING_DONE, uzfs_zvol_get_rebuild_status(zinfo->zv));
	EXPECT_EQ(ZVOL_STATUS_HEALTHY, uzfs_zvol_get_status(zinfo->zv));
	EXPECT_EQ(2, zinfo->refcnt);

	/* rebuild in two replicas case with 'connect' failure */
	uzfs_zvol_set_rebuild_status(zinfo->zv,
	    ZVOL_REBUILDING_INIT);
	set_start_rebuild_mgmt_ack(mack, "vol1", "vol2");
	handle_start_rebuild_req(conn, hdrp, payload, sizeof (mgmt_ack_t));
	EXPECT_EQ(ZVOL_OP_STATUS_OK, ((zvol_io_hdr_t *)conn->conn_buf)->status);
	while (1) {
		if (uzfs_zvol_get_rebuild_status(zinfo->zv) != ZVOL_REBUILDING_FAILED)
			sleep(1);
		else
			break;
	}
	EXPECT_EQ(2, zinfo->refcnt);

	/* rebuild in three replicas case with invalid volname to rebuild */
	uzfs_zvol_set_rebuild_status(zinfo->zv,
	    ZVOL_REBUILDING_INIT);
	set_start_rebuild_mgmt_ack(mack, "vol1", "vol3");
	set_start_rebuild_mgmt_ack(mack + 1, "vol2", "vol3");
	handle_start_rebuild_req(conn, hdrp, payload, sizeof (mgmt_ack_t)*2);
	EXPECT_EQ(ZVOL_OP_STATUS_FAILED, ((zvol_io_hdr_t *)conn->conn_buf)->status);
	while (1) {
		if (uzfs_zvol_get_rebuild_status(zinfo->zv) != ZVOL_REBUILDING_FAILED)
			sleep(1);
		else
			break;
	}
	EXPECT_EQ(2, zinfo->refcnt);

	/* rebuild in three replicas case with 'connect' failing */
	uzfs_zvol_set_rebuild_status(zinfo->zv,
	    ZVOL_REBUILDING_INIT);
	set_start_rebuild_mgmt_ack(mack, "vol1", "vol3");
	set_start_rebuild_mgmt_ack(mack + 1, "vol1", "vol3");
	handle_start_rebuild_req(conn, hdrp, payload, sizeof (mgmt_ack_t)*2);
	EXPECT_EQ(ZVOL_OP_STATUS_OK, ((zvol_io_hdr_t *)conn->conn_buf)->status);
	while (1) {
		if (uzfs_zvol_get_rebuild_status(zinfo->zv) != ZVOL_REBUILDING_FAILED)
			sleep(1);
		else
			break;
	}
	EXPECT_EQ(2, zinfo->refcnt);
}
