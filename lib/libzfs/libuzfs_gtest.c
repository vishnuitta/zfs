/* ****************************************************************************
 *  (C) Copyright 2017 CloudByte, Inc.
 *  All Rights Reserved.
 *
 *  This program is an unpublished copyrighted work which is proprietary
 *  to CloudByte, Inc. and contains confidential information that is not
 *  to be reproduced or disclosed to any other person or entity without
 *  prior written consent from CloudByte, Inc. in each and every instance.
 *
 *  WARNING:  Unauthorized reproduction of this program as well as
 *  unauthorized preparation of derivative works based upon the
 *  program or distribution of copies by sale, rental, lease or
 *  lending are violations of federal copyright laws and state trade
 *  secret laws, punishable by civil and criminal penalties.
 *
 ****************************************************************************/

/*
 * ALL the function here should have follwing prototype
 * boolean_t function(void);
 * these are the helper functions for gtest.
 */

#include <sys/file.h>
#include <libuzfs.h>
#include <gtest_helper.h>

boolean_t
gtest_kernel_init(void)
{
	kernel_init(FREAD);
	return (kthread_nr > 0);
}

boolean_t
gtest_libuzfs_ioctl_init(void)
{
	return (0 == libuzfs_ioctl_init());
}

boolean_t
gtest_libuzfs_client_init(void)
{
	return (0 == libuzfs_client_init(NULL));
}
