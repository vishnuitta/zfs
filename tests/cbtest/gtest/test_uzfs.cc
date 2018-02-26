
#include <gtest/gtest.h>
#include <libuzfs.h>

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
