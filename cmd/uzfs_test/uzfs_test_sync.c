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
#include <sys/zfs_context.h>
#include <uzfs_mgmt.h>
#include <uzfs_io.h>
#include <math.h>

int total_time_in_sec = 60;
uint64_t io_block_size = 4096;
uint64_t block_size = 4096;
uint64_t active_size = 0;
uint64_t vol_size = 0;
int write_op = 0;
int verify = 0;
int verify_err = 0;
int silent = 0;
int sync_data = 0;
extern int zfs_txg_timeout;

typedef struct worker_args {
	void *zv;
	kmutex_t *mtx;
	kcondvar_t *cv;
	int *threads_done;
	uint64_t io_block_size;
	uint64_t active_size;
} worker_args_t;

int
verify_fn(void *zv, char *buf, int block_size)
{
	int err;

	err = uzfs_read_data(zv, buf, 0, block_size);
	if (err != 0)
		printf("read error..\n");
	if (silent == 0)
		printf("%d %d\n", buf[0], verify);
	if ((buf[0] == verify) && (err == 0))
		return (0);
	else
		return (1);
}

void
write_fn(void *zv, char *buf, int block_size)
{
	int err;
	uint64_t txg1, txg2;

	buf[0] = uzfs_random(100);
	if (buf[0] == 0)
		buf[0] = 1;

	txg1 = uzfs_syncing_txg(zv);

	err = uzfs_write_data(zv, buf, 0, block_size);
	if (err != 0)
		printf("IO error\n");

	if (sync_data == 0)
		uzfs_flush_data(zv);

	txg2 = uzfs_syncing_txg(zv);

	if (txg1 == txg2) {
		printf("%d\n", buf[0]);
		exit(0);
	}
}

void
thread_fn(void *arg)
{
	worker_args_t *warg = (worker_args_t *)arg;
	char *buf;
	hrtime_t end, now;
	void *zv = warg->zv;
	kmutex_t *mtx = warg->mtx;
	kcondvar_t *cv = warg->cv;
	int *threads_done = warg->threads_done;
	uint64_t block_size = warg->io_block_size;

	buf = (char *)umem_alloc(sizeof (char)*block_size, UMEM_NOFAIL);

	now = gethrtime();
	end = now + (hrtime_t)(total_time_in_sec * (hrtime_t)(NANOSEC));

	if (silent == 0)
		printf("Starting %s..\n", write_op ? "write" : "verify");

	while (1) {
		if (write_op == 1)
			write_fn(zv, buf, block_size);
		else {
			verify_err = verify_fn(zv, buf, block_size);
			goto done;
		}

		now = gethrtime();

		if (now > end) {
			printf("unable to write..\n");
			break;
		}
	}
done:
	umem_free(buf, sizeof (char)*block_size);
	if (silent == 0)
		printf("Stoping %s..\n", write_op ? "write" : "verify");
	if (write_op == 1)
		exit(1);

	mutex_enter(mtx);
	*threads_done = *threads_done + 1;
	cv_signal(cv);
	mutex_exit(mtx);
	zk_thread_exit();
}

void
make_vdev(char *path)
{
	int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
	if (fd == -1) {
		printf("can't open %s", path);
		exit(1);
	}
	if (ftruncate(fd, vol_size) != 0) {
		printf("can't ftruncate %s", path);
		exit(1);
	}
	(void) close(fd);
}

void
setup_unit_test(void)
{
	make_vdev("/tmp/uztest_sync.1a");
	make_vdev("/tmp/uztest_sync.log");
}

void
open_pool_ds(void **s, void **z)
{
	int err;
	void *spa, *zv;

	spa = zv = NULL;

	*s = spa;
	*z = zv;

	err = uzfs_open_pool("testp_sync", &spa);
	if (err != 0) {
		printf("pool open errored.. %d\n", err);
		exit(1);
	}
	err = uzfs_open_dataset(spa, "ds0", sync_data, &zv);
	if (err != 0) {
		printf("ds open errored.. %d\n", err);
		exit(1);
	}

	*s = spa;
	*z = zv;
}

void
create_pool_ds(void **s, void **z)
{
	int err;
	void *spa, *zv;

	spa = zv = NULL;

	*s = spa;
	*z = zv;

	err = uzfs_create_pool("testp_sync", "/tmp/uztest_sync.1a", &spa);
	if (err != 0 || spa == NULL) {
		printf("creating pool errored %d..\n", err);
		exit(1);
	}

	err = uzfs_create_dataset(spa, "ds0", vol_size, block_size, sync_data,
	    &zv);
	if (zv == NULL || err != 0) {
		printf("creating ds errored %d..\n", err);
		exit(1);
	}

	err = uzfs_vdev_add(spa, "/tmp/uztest_sync.log", 12, 1);
	if (err != 0) {
		printf("vdev add errored %d..\n", err);
		exit(1);
	}

	*s = spa;
	*z = zv;
}

static void usage(int num)
{
	printf("uzfs_test_sync -s -S -w | -v <verify data>\n");
	if (num == 0)
		exit(1);
}

static int
str2shift(const char *buf)
{
	const char *ends = "BKMGTPEZ";
	int i;

	if (buf[0] == '\0')
		return (0);
	for (i = 0; i < strlen(ends); i++) {
		if (toupper(buf[0]) == ends[i])
			break;
	}
	if (i == strlen(ends)) {
		printf("uztest: invalid bytes suffix: %s\n", buf);
		usage(B_FALSE);
	}
	if (buf[1] == '\0' || (toupper(buf[1]) == 'B' && buf[2] == '\0')) {
		return (10*i);
	}
	printf("uztest: invalid bytes suffix: %s\n", buf);
	usage(B_FALSE);
	return (-1);
}


static uint64_t
nicenumtoull(const char *buf)
{
	char *end;
	uint64_t val;

	val = strtoull(buf, &end, 0);
	if (end == buf) {
		printf("uztest: bad numeric value: %s\n", buf);
		usage(B_FALSE);
	} else if (end[0] == '.') {
		double fval = strtod(buf, &end);
		fval *= pow(2, str2shift(end));
		if (fval > UINT64_MAX) {
			printf("uztest: value too large: %s\n", buf);
			usage(B_FALSE);
		}
		val = (uint64_t)fval;
	} else {
		int shift = str2shift(end);
		if (shift >= 64 || (val << shift) >> shift != val) {
			printf("uztest: value too large: %s\n", buf);
			usage(B_FALSE);
		}
		val <<= shift;
	}
	return (val);
}

/*
 * option 'w' writes a block at offset 0 and crashes before sync
 * option 's' opens the dataset in sync mode
 * option 'S' disables verbose print
 * option 'v' verifies the first byte of block at offset 0 with given byte
 */

static void process_options(int argc, char **argv)
{
	int opt;
	uint64_t val = 0;
	while ((opt = getopt(argc, argv, "wsSv:")) != EOF) {
		switch (opt) {
			case 'w':
				write_op = 1;
				break;
			case 'v':
				if (optarg != NULL)
					val = nicenumtoull(optarg);
				verify = val;
				break;
			case 's':
				sync_data = 1;
				break;
			case 'S':
				silent = 1;
				break;
			default:
				usage(0);
		}
	}

	vol_size = active_size = 1024*1024*1024;
	block_size = io_block_size = 4*1024;

	if (silent == 0) {
		printf("vol size: %lu active size: %lu\n", vol_size,
		    active_size);
		printf("block size: %lu io blksize: %lu\n", block_size,
		    io_block_size);
		printf("write_op: %d verify: %d sync: %d\n", write_op,
		    verify, sync_data);
	}
}

int
main(int argc, char **argv)
{
	void *spa, *zv;
	kthread_t *thread1;
	int err;
	kmutex_t mtx;
	kcondvar_t cv;
	int threads_done = 0;
	int num_threads = 0;
	worker_args_t args;

	mutex_init(&mtx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&cv, NULL, CV_DEFAULT, NULL);

	process_options(argc, argv);
	zfs_txg_timeout = 30;

	err = uzfs_init();
	if (err != 0) {
		printf("initialization errored.. %d\n", err);
		exit(1);
	}

	zfs_txg_timeout = 30;

	if (write_op == 1) {
		setup_unit_test();
		create_pool_ds(&spa, &zv);
	} else if (verify != 0) {
		open_pool_ds(&spa, &zv);
	} else {
		printf("exiting program..\n");
		uzfs_fini();
		exit(1);
	}

	args.zv = zv;
	args.threads_done = &threads_done;
	args.mtx = &mtx;
	args.cv = &cv;
	args.io_block_size = io_block_size;
	args.active_size = active_size;

	thread1 = zk_thread_create(NULL, 0, (thread_func_t)thread_fn,
	    &args, 0, NULL, TS_RUN, 0, PTHREAD_CREATE_DETACHED);
	num_threads++;

	mutex_enter(&mtx);
	while (threads_done != num_threads)
		cv_wait(&cv, &mtx);
	mutex_exit(&mtx);

	cv_destroy(&cv);
	mutex_destroy(&mtx);

	if (verify != 0)
		if (silent == 0)
			printf("verify error: %d\n", verify_err);
	uzfs_close_dataset(zv);
	uzfs_close_pool(spa);
	uzfs_fini();
	exit(verify_err);
}
