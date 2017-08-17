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

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <libuzfs.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define PEND_CONNECTIONS 10

static int
uzfs_server_init(void)
{
	sigset_t set;
	if (sigemptyset(&set) < 0)
		return (-1);
	if (sigaddset(&set, SIGPIPE) < 0)
		return (-1);
	if (pthread_sigmask(SIG_BLOCK, &set, NULL))
		return (-1);
	return (0);
}

static void *
uzfs_process_ioctl(void *arg)
{
	int cfd;
	uint64_t ioc_num = 0;
	zfs_cmd_t zc;
	int count = 0;
	char *pool = NULL;

	cfd = *(int *) arg;

	// printf("started the ioctl processing fd(%d)\n", cfd);
	while (1) {
		if (uzfs_recv_ioctl(cfd, &zc, &ioc_num) < 0)
			goto out;

		/* legacy ioctls can modify zc_name */
		if (zc.zc_name[0] && is_config_command(ioc_num)) {
			if (pool)
				strfree(pool);
			pool = strdup(zc.zc_name);
			if (pool) {
				pool[strcspn(pool, "/@#")] = '\0';
			}
		}
		int ret = uzfs_handle_ioctl(pool, ioc_num, &zc);

		int err = (ret < 0 ? errno : ret);

		if (uzfs_send_response(cfd, &zc, err) < 0)
			goto out;

		count++;
	}
out:
	// printf("ioctl processing done count = %d fd(%d)\n", cfd, count);
	if (pool)
		strfree(pool);
	close(cfd);
	free(arg);
	thread_exit();
	return NULL;
}

static void *
uzfs_accept(void *arg)
{
	struct sockaddr_in client_addr;
	unsigned int addr_len;
	int sfd = *(int *) arg;

	while (1) {
		addr_len = sizeof(client_addr);
		int *cfd = (int *) malloc(sizeof(int));
		if (cfd == NULL ||
		    (*cfd = accept(sfd, (struct sockaddr *) &client_addr,
		                   &addr_len)) < 0) {
			perror("accept");
			continue;
		}
		/* TODO(pawan) make it event-driven */
		VERIFY3P(zk_thread_create(NULL, 0,
		                          (thread_func_t) uzfs_process_ioctl,
		                          cfd, 0, NULL, TS_RUN, 0,
		                          PTHREAD_CREATE_DETACHED),
		         !=, NULL);
	}

	close(sfd);
	free(arg);
	thread_exit();
	return NULL;
}

int
libuzfs_ioctl_init(void)
{
	unsigned int server_s;
	struct sockaddr_in server_addr;

	if ((server_s = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return (-1);

	int x = 1;
	if (setsockopt(server_s, SOL_SOCKET, SO_REUSEADDR, &x, sizeof(x)) < 0) {
		goto err;
	}

	x = 1;
	if (setsockopt(server_s, IPPROTO_TCP, TCP_NODELAY, &x, sizeof(x)) < 0) {
		goto err;
	}

	struct linger so_linger;
	so_linger.l_onoff = 1;
	so_linger.l_linger = 30;
	if (setsockopt(server_s, SOL_SOCKET, SO_LINGER, &so_linger,
	               sizeof so_linger)) {
		goto err;
	}

	if (uzfs_server_init() < 0)
		goto err;

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(UZFS_PORT);
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(server_s, (struct sockaddr *) &server_addr,
	         sizeof(server_addr)) < 0) {
		goto err;
	}

	if (listen(server_s, PEND_CONNECTIONS) < 0) {
		goto err;
	}

	int *sfd = (int *) malloc(sizeof(int));
	if (sfd == NULL) {
		goto err;
	}
	*sfd = server_s;

	VERIFY3P(zk_thread_create(NULL, 0, (thread_func_t) uzfs_accept, sfd, 0,
	                          NULL, TS_RUN, 0, PTHREAD_CREATE_DETACHED),
	         !=, NULL);
	return (0);
err:
	close(server_s);
	return (-1);
}
