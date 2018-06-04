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
#include <libuzfs.h>
#include <mgmt_conn.h>

TEST(uZFSServer, Setup) {
	kernel_init(FREAD);
	EXPECT_GT(kthread_nr, 0);
}

TEST(uZFSServer, ClientConnectNoServer) {
	EXPECT_NE(0, libuzfs_client_init(NULL));
}

TEST(uZFSServer, InitServer) {
	EXPECT_EQ(0, libuzfs_ioctl_init());
}

TEST(uZFSServer, ClientConnectServer) {
	EXPECT_EQ(0, libuzfs_client_init(NULL));
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

TEST(uZFSServer, EmptyCreateProps) {
	zvol_info_t *zinfo = (zvol_info_t *)malloc(sizeof (zvol_info_t));
	zvol_state_t *zv = (zvol_state_t *)malloc(sizeof (zvol_state_t));
	uzfs_mgmt_conn_t *conn;

	memset(zinfo, 0, sizeof (zvol_info_t));
	memset(zv, 0, sizeof (zvol_state_t));

	zinfo->zv = zv;

	mutex_init(&conn_list_mtx, NULL, MUTEX_DEFAULT, NULL);
	SLIST_INIT(&uzfs_mgmt_conns);
	mgmt_eventfd = -1;

	zinfo_create_cb(zinfo, NULL);
	EXPECT_EQ(1, slist_count(&uzfs_mgmt_conns));
	conn = SLIST_FIRST(&uzfs_mgmt_conns);
	EXPECT_EQ(1, conn->conn_refcount);

	zinfo_create_cb(zinfo, NULL);
	EXPECT_EQ(1, slist_count(&uzfs_mgmt_conns));
	conn = SLIST_FIRST(&uzfs_mgmt_conns);
	EXPECT_EQ(2, conn->conn_refcount);
}
