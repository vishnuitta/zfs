#ifndef _LIBUZFS_H_
#define _LIBUZFS_H_

#include <sys/zfs_ioctl.h>
#include <libzfs.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UZFS_PORT 8971
#define UZFS_IP "127.0.0.1"

#define SET_ERR(err) (errno = err, -1)

typedef struct uzfs_ioctl {
	uint64_t packet_size;
	uint64_t ioc_num;
	int his_len;
	int ioc_ret;
} uzfs_ioctl_t;

/* _UZFS_IOC(ioctl_number, is_config_command, description) */
#define UZFS_IOCTL_LIST                                                       \
	_UZFS_IOC(ZFS_IOC_OBJSET_STATS, 0, "")                                \
	_UZFS_IOC(ZFS_IOC_POOL_CREATE, 1, "")                                 \
	_UZFS_IOC(ZFS_IOC_POOL_IMPORT, 1, "")                                 \
	_UZFS_IOC(ZFS_IOC_POOL_STATS, 0, "")                                  \
	_UZFS_IOC(ZFS_IOC_POOL_TRYIMPORT, 0, "")                              \
	_UZFS_IOC(ZFS_IOC_CREATE, 1, "")                                      \
	_UZFS_IOC(ZFS_IOC_POOL_CONFIGS, 0, "")                                \
	_UZFS_IOC(ZFS_IOC_DATASET_LIST_NEXT, 0, "")                           \
	_UZFS_IOC(ZFS_IOC_GET_BOOKMARKS, 0, "")                               \
	_UZFS_IOC(ZFS_IOC_POOL_GET_PROPS, 0, "")                              \
	_UZFS_IOC(ZFS_IOC_POOL_EXPORT, 1, "")                                 \
	_UZFS_IOC(ZFS_IOC_POOL_GET_HISTORY, 0, "")                            \
	_UZFS_IOC(ZFS_IOC_LOG_HISTORY, 0, "")                                 \
	_UZFS_IOC(ZFS_IOC_SNAPSHOT, 1, "")                                    \
	_UZFS_IOC(ZFS_IOC_SNAPSHOT_LIST_NEXT, 0, "")                          \
	_UZFS_IOC(ZFS_IOC_POOL_DESTROY, 1, "")                                \
	_UZFS_IOC(ZFS_IOC_DESTROY_SNAPS, 1, "")                               \
	_UZFS_IOC(ZFS_IOC_DESTROY, 1, "")                                     \
	_UZFS_IOC(ZFS_IOC_POOL_SET_PROPS, 1, "")                              \
	_UZFS_IOC(ZFS_IOC_SET_PROP, 1, "")

#define MAX_NVLIST_SRC_SIZE 128 * 1024 * 1024

extern int uzfs_ioctl(int fd, unsigned long request, zfs_cmd_t *zc);
extern int uzfs_handle_ioctl(const char *pool, uint64_t request,
                             zfs_cmd_t *zc);
extern int uzfs_recv_ioctl(int fd, zfs_cmd_t *zc, uint64_t *ioc_num);
extern int uzfs_send_response(int fd, zfs_cmd_t *zc, int err);
extern int uzfs_send_ioctl(int fd, unsigned long request, zfs_cmd_t *zc);
extern int libuzfs_ioctl_init(void);
extern int libuzfs_client_init(libzfs_handle_t *g_zfs);
extern int uzfs_recv_response(int fd, zfs_cmd_t *zc);

boolean_t zfs_is_bootfs(const char *name);
boolean_t zpl_earlier_version(const char *name, int version);
int zfs_set_prop_nvlist(const char *dsname, zprop_source_t source,
                        nvlist_t *nvl, nvlist_t *errlist);

static inline int
is_config_command(unsigned long ioc_num)
{
	switch (ioc_num) {

#define _UZFS_IOC(ioc, config, desc)                                          \
	case ioc:                                                             \
		return config;                                                \
		break;

		UZFS_IOCTL_LIST

#undef _UZFS_IOC
	}
	return 0;
}
#ifdef __cplusplus
}
#endif

#endif /* _LIBUZFS_H */
