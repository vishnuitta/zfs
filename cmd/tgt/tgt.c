/*
 * ***************************************************************************
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
 * ***************************************************************************
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libuzfs.h>
#include <sys/zil.h>
#include <sys/zvol.h>

#define	MB (1024 * 1024)
#define	DSIZE (40 * MB)

char *conf_vol = NULL;

void *
uzfs_write(void *arg)
{
	static int count;
	objset_t *os;

	if (conf_vol == NULL) {
		printf("no volume specified\n");
		goto out;
	}

	int error = dmu_objset_own(conf_vol, DMU_OST_ZVOL, B_TRUE, FTAG, &os);
	if (error) {
		printf("error opening volume(%d)\n", error);
		goto out;
	}
	int offset = 0, buf_len;
	char data[4096];
	while (offset < DSIZE) {
		buf_len = 0;
		if (offset == 0) {
			buf_len =
			    sprintf(data, "%d. uZFS Signature Data!", count++);
		}
		while (buf_len < sizeof (data) - 1) {
			data[buf_len++] = 'a' + rand() % 26;
		}
		data[buf_len++] = '\n';
		dmu_tx_t *tx = dmu_tx_create(os);
		dmu_tx_hold_write(tx, ZVOL_OBJ, offset, buf_len);
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error) {
			dmu_tx_abort(tx);
			dmu_objset_disown(os, FTAG);
			goto out;
		}
		dmu_write(os, ZVOL_OBJ, offset, buf_len, data, tx);
		dmu_tx_commit(tx);
		offset += buf_len;
	}
	dmu_objset_disown(os, FTAG);
out:
	thread_exit();
	return (NULL);
}

void *
uzfs_read(void *arg)
{
	objset_t *os;
	char vol[MAXPATHLEN];
	char *zvol = arg;

	if (conf_vol == NULL && zvol == NULL) {
		printf("no volume specified\n");
		goto out;
	}

	if (zvol) {
		sprintf(vol, "%s", zvol);
	} else {
		sprintf(vol, "%s@snap1", conf_vol);
	}

	int error = dmu_objset_own(vol, DMU_OST_ZVOL, B_TRUE, FTAG, &os);
	if (error) {
		printf("error opening volume(%d)\n", error);
		goto out;
	}
	int fd = open("out.txt", O_RDWR | O_CREAT | O_TRUNC, 0666);
	if (fd < 0) {
		perror("open");
		dmu_objset_disown(os, FTAG);
		goto out;
	}
	int offset = 0, buf_len;
	char data[4096];
	while (offset < DSIZE) {
		buf_len = sizeof (data);
		dmu_read(os, ZVOL_OBJ, offset, buf_len, data, 0);
		if (write(fd, data, buf_len) < 0) {
			perror("write");
			break;
		}
		offset += buf_len;
	}
	dmu_objset_disown(os, FTAG);
out:
	thread_exit();
	return (NULL);
}

static void
reload_config(int signo)
{
	/* start the IO processing */
	if (signo == SIGHUP) {
		VERIFY3P((zk_thread_create(NULL, 0, (thread_func_t)uzfs_write,
		    conf_vol, 0, NULL, TS_RUN, 0, PTHREAD_CREATE_DETACHED)),
		    !=, NULL);
	}

	if (signo == SIGUSR1) {
		VERIFY3P((zk_thread_create(NULL, 0, (thread_func_t)uzfs_read,
		    conf_vol, 0, NULL, TS_RUN, 0, PTHREAD_CREATE_DETACHED)),
		    !=, NULL);
	}
	if (signo == SIGUSR2) {
		VERIFY3P((zk_thread_create(NULL, 0, (thread_func_t)uzfs_read,
		    NULL, 0, NULL, TS_RUN, 0, PTHREAD_CREATE_DETACHED)),
		    !=, NULL);
	}
}

/*
 * This is a test program to show how istgt can
 * use the libuzfs to act like a kernel to the
 * zpool and zfs commands.
 * All it has to do is call libuzfs_ioctl_init(),
 * which will take care of everything.
 * Make sure you have done kernel_init before calling this.
 */
int
main(int argc, char *argv[])
{
	int c;
	while ((c = getopt(argc, argv, ":v:")) != EOF) {
		switch (c) {
		case 'v':
			conf_vol = optarg;
			break;
		case ':':
			fprintf(stderr, "argument required for option %c\n"
			    "usage : tgt [-v volume]\n", optopt);
			exit(1);
		default:
			fprintf(stderr, "invalid option %c\n"
			    "usage : tgt [-v volume]\n", optopt);
			exit(1);
		}
	}

	kernel_init(FREAD | FWRITE);
	signal(SIGHUP, reload_config);
	signal(SIGUSR1, reload_config);
	signal(SIGUSR2, reload_config);

	if (libuzfs_ioctl_init() < 0) {
		(void) fprintf(stderr, "%s",
		    "failed to initialize libuzfs ioctl\n");
		goto err;
	}

	while (1) {
		sleep(5);
		/* other stuffs */
	}

err:
	kernel_fini();
	return (0);
}
