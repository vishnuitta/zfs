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

#include <errno.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <libuzfs.h>
#include "libzfs_impl.h"

extern int g_fd;

static void inline uzfs_ioctl_done(uzfs_ioctl_t *cmd, zfs_cmd_t *zc)
{
	free((void *) zc->zc_nvlist_src);
	free((void *) zc->zc_nvlist_dst);
	free((void *) zc->zc_nvlist_conf);
	free((void *) zc->zc_history);
}

static int inline uzfs_ioctl_init(uzfs_ioctl_t *cmd, zfs_cmd_t *zc)
{
	void *ptr;

	zc->zc_nvlist_src = zc->zc_nvlist_dst = zc->zc_nvlist_conf =
	    zc->zc_history = (uint64_t)NULL;

	if (zc->zc_nvlist_src_size) {
		ptr = malloc(zc->zc_nvlist_src_size);
		if (ptr == NULL)
			goto err;
		zc->zc_nvlist_src = (uint64_t) ptr;
	}
	if (zc->zc_nvlist_dst_size) {
		ptr = malloc(zc->zc_nvlist_dst_size);
		if (ptr == NULL)
			goto err;
		zc->zc_nvlist_dst = (uint64_t) ptr;
	}
	if (zc->zc_nvlist_conf_size) {
		ptr = malloc(zc->zc_nvlist_conf_size);
		if (ptr == NULL)
			goto err;
		zc->zc_nvlist_conf = (uint64_t) ptr;
	}
	size_t his_size = (cmd->his_len ? cmd->his_len : zc->zc_history_len);
	if (his_size) {
		ptr = malloc(his_size);
		if (ptr == NULL)
			goto err;
		zc->zc_history = (uint64_t) ptr;
	}

	return (0);
err:
	uzfs_ioctl_done(cmd, zc);
	return (-1);
}

static int
uzfs_client_init(const char *ip, uint16_t port)
{
	int sock;
	struct sockaddr_in server_addr;
	struct hostent *host;

	if ((host = gethostbyname(ip)) == NULL)
		return (-1);

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		return (-1);
	}
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr = *((struct in_addr *) host->h_addr);
	memset(&(server_addr.sin_zero), '\0', sizeof(server_addr.sin_zero));

	if (connect(sock, (struct sockaddr *) &server_addr,
	            sizeof(server_addr)) < 0) {
		close(sock);
		return (-1);
	}
	return (sock);
}

int
libuzfs_client_init(libzfs_handle_t *g_zfs)
{
	g_fd = uzfs_client_init(UZFS_IP, UZFS_PORT);
	if (g_fd < 0)
		return (-1);
	g_zfs->libzfs_fd = g_fd;
	return (0);
}

static int
uzfs_read_packet(int fd, void *ptr, uint64_t size)
{
	uint64_t buf_len = 0, len;
	char *buf = ptr;

	if (0 == size)
		return (1);

	do {
		if ((len = read(fd, buf + buf_len, size - buf_len)) < 0) {
			return (-1);
		}
		buf_len += len;
	} while (len && buf_len < size);

	return (buf_len == size);
}

static int
uzfs_write_packet(int fd, void *ptr, uint64_t size)
{
	uint64_t buf_len = 0, len;
	char *buf = ptr;

	if (0 == size)
		return (1);

	do {
		if ((len = write(fd, buf + buf_len, size - buf_len)) < 0) {
			return (-1);
		}
		buf_len += len;
	} while (buf_len < size);

	return (buf_len == size);
}

int
uzfs_recv_response(int fd, zfs_cmd_t *zc)
{
	uzfs_ioctl_t uzfs_cmd = {0};

	if (uzfs_read_packet(fd, &uzfs_cmd, sizeof(uzfs_ioctl_t)) <= 0)
		return (EPIPE);

	zfs_cmd_t *uzc = (zfs_cmd_t *) malloc(sizeof(zfs_cmd_t));

	if (uzc == NULL)
		return (-1);

	if (uzfs_read_packet(fd, uzc, sizeof(zfs_cmd_t)) <= 0)
		return (EPIPE);

	/*
	 * Ideal way to do this is reorganise zfs_cmd_t
	 * structure and copy from the memory offset.
	 * Doing it the dirty way so that the binary is
	 * backward compatibale.
	 */
	/* backup the  pointers */
	uint64_t src = zc->zc_nvlist_src;
	uint64_t dst = zc->zc_nvlist_dst;
	uint64_t conf = zc->zc_nvlist_conf;
	uint64_t his = zc->zc_history;

	*zc = *uzc;

	/* restore the pointers */
	zc->zc_nvlist_src = src;
	zc->zc_nvlist_dst = dst;
	zc->zc_nvlist_conf = conf;
	zc->zc_history = his;

	if (zc->zc_history && zc->zc_history_len &&
	    uzfs_read_packet(fd, (void *) zc->zc_history,
	                     zc->zc_history_len) <= 0)
		return (EPIPE);

	if (!uzc->zc_nvlist_dst_filled)
		return (uzfs_cmd.ioc_ret);

	if (uzfs_read_packet(fd, (void *) zc->zc_nvlist_dst,
	                     zc->zc_nvlist_dst_size) <= 0)
		return (EPIPE);

	return (uzfs_cmd.ioc_ret);
}

int
uzfs_send_ioctl(int fd, unsigned long request, zfs_cmd_t *zc)
{
	uzfs_ioctl_t uzfs_cmd = {0};

	uzfs_cmd.ioc_num = request;

	if (!zc->zc_history_len && zc->zc_history)
		uzfs_cmd.his_len = strlen((char *) zc->zc_history);

	char *src = (char *) zc->zc_nvlist_src;
	char *conf = (char *) zc->zc_nvlist_conf;
	char *his = (char *) zc->zc_history;

	uzfs_cmd.packet_size = (sizeof(uzfs_ioctl_t) + sizeof(zfs_cmd_t) +
	                        zc->zc_nvlist_src_size +
	                        zc->zc_nvlist_conf_size + uzfs_cmd.his_len);

	if (uzfs_write_packet(fd, &uzfs_cmd, sizeof(uzfs_ioctl_t)) <= 0)
		return (-1);

	if (uzfs_write_packet(fd, zc, sizeof(zfs_cmd_t)) <= 0)
		return (-1);

	if (uzfs_write_packet(fd, src, zc->zc_nvlist_src_size) <= 0)
		return (-1);

	if (uzfs_write_packet(fd, conf, zc->zc_nvlist_conf_size) <= 0)
		return (-1);

	if (uzfs_write_packet(fd, his, uzfs_cmd.his_len) <= 0)
		return (-1);

	return (0);
}

int
uzfs_recv_ioctl(int fd, zfs_cmd_t *zc, uint64_t *ioc_num)
{
	uzfs_ioctl_t cmd = {0};

	if (uzfs_read_packet(fd, &cmd, sizeof(uzfs_ioctl_t)) <= 0)
		return (-1);

	if (uzfs_read_packet(fd, zc, sizeof(zfs_cmd_t)) <= 0)
		return (-1);

	if (uzfs_ioctl_init(&cmd, zc) < 0)
		return (-1);

	if (uzfs_read_packet(fd, (void *) zc->zc_nvlist_src,
	                     zc->zc_nvlist_src_size) <= 0)
		goto err;

	if (uzfs_read_packet(fd, (void *) zc->zc_nvlist_conf,
	                     zc->zc_nvlist_conf_size) <= 0)
		goto err;

	if (uzfs_read_packet(fd, (void *) zc->zc_history, cmd.his_len) <= 0)
		goto err;

	*ioc_num = cmd.ioc_num;

	return (0);
err:
	uzfs_ioctl_done(&cmd, zc);
	return (-1);
}

int
uzfs_send_response(int fd, zfs_cmd_t *zc, int ret)
{
	int err = -1;

	uzfs_ioctl_t uzfs_cmd = {0};

	uzfs_cmd.ioc_ret = ret;

	if (uzfs_write_packet(fd, &uzfs_cmd, sizeof(uzfs_ioctl_t)) <= 0) {
		goto out;
	}

	if (uzfs_write_packet(fd, zc, sizeof(zfs_cmd_t)) <= 0) {
		goto out;
	}

	if (uzfs_write_packet(fd, (void *) zc->zc_history,
	                      zc->zc_history_len) <= 0) {
		goto out;
	}

	char *buf = (char *) zc->zc_nvlist_dst;

	if (zc->zc_nvlist_dst_filled &&
	    uzfs_write_packet(fd, buf, zc->zc_nvlist_dst_size) <= 0) {
		goto out;
	}
	err = 0;
out:
	uzfs_ioctl_done(&uzfs_cmd, zc);
	return (err);
}
