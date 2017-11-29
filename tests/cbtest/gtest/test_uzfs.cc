#include <gtest/gtest.h>
#include <gtest_helper.h>

TEST(uZFSServer, Setup) {
	EXPECT_EQ(true, gtest_kernel_init());
}

TEST(uZFSServer, ClientConnectNoServer) {
	EXPECT_EQ(false, gtest_libuzfs_client_init());
}

TEST(uZFSServer, InitServer) {
	EXPECT_EQ(true, gtest_libuzfs_ioctl_init());
}

TEST(uZFSServer, ClientConnectServer) {
	EXPECT_EQ(true, gtest_libuzfs_client_init());
}
