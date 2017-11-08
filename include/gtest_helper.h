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

#ifndef _TEST_UZFS_
#define _TEST_UZFS_

#ifdef __cplusplus
extern "C" {
#endif

extern boolean_t gtest_kernel_init(void);
extern boolean_t gtest_libuzfs_ioctl_init(void);
extern boolean_t gtest_libuzfs_client_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _TEST_UZFS_ */
