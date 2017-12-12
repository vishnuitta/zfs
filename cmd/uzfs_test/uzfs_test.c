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
uint64_t io_block_size = 1024;
uint64_t block_size = 4096;
uint64_t active_size = 0;
uint64_t vol_size = 0;

typedef struct worker_args {
	void *zv;
	kmutex_t *mtx;
	kcondvar_t *cv;
	int *threads_done;
	uint64_t io_block_size;
	uint64_t active_size;
} worker_args_t;

void reader_thread(void *zv);

extern unsigned long zfs_arc_max;
extern unsigned long zfs_arc_min;

void
verify_data(char *buf, uint64_t offset, int idx, uint64_t block_size)
{
	int i;
	int err = 0;
	if ((buf[0] != ((offset / 256) % 128)) && (buf[0] != 0)) {
		printf("error0 in data..\n");
		err = 1;
	}

	for (i = 0; i < idx; i++) {
		if ((buf[((i + 1) * block_size) - 1] !=
		    (((offset + (i * block_size)) / 4096) % 128)) &&
		    (buf[((i + 1) * block_size) - 1] != 0)) {
			printf("error0 %d in data..\n", i);
			err = 1;
		}
		if ((buf[((i + 1) * block_size)] !=
		    (((offset + ((i + 1) * block_size)) / 256) % 128)) &&
		    (buf[((i + 1) * block_size)] != 0)) {
			printf("error1 %d in data..\n", i);
			err = 1;
		}
	}
	if ((buf[((i + 1) * block_size) - 1] !=
	    (((offset + (i * block_size)) / 4096) % 128)) &&
	    (buf[((i + 1) * block_size) - 1] != 0)) {
		printf("error1 %lu %d in data..\n", offset+i*block_size,
		    buf[((i+1)*block_size)-1]);
		err = 1;
	}
	if (err == 1)
		exit(1);
}

void
reader_thread(void *arg)
{
	worker_args_t *warg = (worker_args_t *)arg;
	char *buf[15];
	int idx, j, err;
	uint64_t blk_offset, offset, vol_blocks, iops = 0, data_iops = 0;
	hrtime_t end, now;
	void *zv = warg->zv;
	kmutex_t *mtx = warg->mtx;
	kcondvar_t *cv = warg->cv;
	int *threads_done = warg->threads_done;
	uint64_t vol_size = warg->active_size;
	uint64_t block_size = warg->io_block_size;

	for (j = 0; j < 15; j++)
		buf[j] = (char *)umem_alloc(sizeof (char)*(j+1)* block_size,
		    UMEM_NOFAIL);

	now = gethrtime();
	end = now + (hrtime_t)(total_time_in_sec * (hrtime_t)(NANOSEC));

	vol_blocks = (vol_size) / block_size;

	printf("Starting read..\n");

	while (1) {
		blk_offset = uzfs_random(vol_blocks - 16);
		offset = blk_offset * block_size;

		idx = uzfs_random(15);
		err = uzfs_read_data(zv, buf[idx], offset,
		    (idx + 1) * block_size);

		if (err != 0)
			printf("IO error at offset: %lu len: %lu\n", offset,
			    (idx + 1) * block_size);
		verify_data(buf[idx], offset, idx, block_size);

		if (buf[idx][0] != 0)
			data_iops += (idx + 1);

		iops += (idx + 1);

		now = gethrtime();
		if (now > end)
			break;
	}
	for (j = 0; j < 15; j++)
		umem_free(buf[j], sizeof (char) * (j + 1) * block_size);
	printf("Stopping read.. ios done: %lu data iops: %lu\n", iops,
	    data_iops);

	mutex_enter(mtx);
	*threads_done = *threads_done + 1;
	cv_signal(cv);
	mutex_exit(mtx);
	zk_thread_exit();
}

void
populate_data(char *buf, uint64_t offset, int idx, uint64_t block_size)
{
	int i;
	buf[0] = (offset / 256) % 128;

	for (i = 0; i < idx; i++) {
		buf[((i + 1) * block_size) - 1] =
		    ((offset + (i * block_size)) / 4096) % 128;
		buf[((i + 1) * block_size)] =
		    ((offset + ((i + 1) * block_size)) / 256) % 128;
	}
	buf[((i + 1) * block_size) - 1] =
	    ((offset + (i * block_size)) / 4096) % 128;
}

void
writer_thread(void *arg)
{
	worker_args_t *warg = (worker_args_t *)arg;
	char *buf[15];
	int idx, j, err;
	uint64_t blk_offset, offset, vol_blocks, iops = 0;
	hrtime_t end, now;
	void *zv = warg->zv;
	kmutex_t *mtx = warg->mtx;
	kcondvar_t *cv = warg->cv;
	int *threads_done = warg->threads_done;
	uint64_t vol_size = warg->active_size;
	uint64_t block_size = warg->io_block_size;

	for (j = 0; j < 15; j++)
		buf[j] = (char *)umem_alloc(sizeof (char)*(j+1)*block_size,
		    UMEM_NOFAIL);

	now = gethrtime();
	end = now + (hrtime_t)(total_time_in_sec * (hrtime_t)(NANOSEC));

	vol_blocks = (vol_size) / block_size;

	printf("Starting write..\n");

	while (1) {
		blk_offset = uzfs_random(vol_blocks - 16);
		offset = blk_offset * block_size;

		idx = uzfs_random(15);

		populate_data(buf[idx], offset, idx, block_size);

		err = uzfs_write_data(zv, buf[idx], offset,
		    (idx + 1) * block_size);
		if (err != 0)
			printf("IO error at offset: %lu len: %lu\n", offset,
			    (idx + 1) * block_size);
		iops += (idx + 1);
		now = gethrtime();

		if (now > end)
			break;
	}
	for (j = 0; j < 15; j++)
		umem_free(buf[j], sizeof (char) * (j + 1) * block_size);
	printf("Stopping write.. ios done: %lu\n", iops);

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
	make_vdev("/tmp/uztest.1a");
	make_vdev("/tmp/uztest.2a");
	make_vdev("/tmp/uztest.log");
	unlink("/tmp/uztest.xyz");
}

void
unit_test_create_pool_ds(void)
{
	void *spa1, *spa2, *spa3, *spa4, *spa;
	void *zv1, *zv2, *zv3, *zv4, *zv5, *zv;
	int err, err1, err2, err3, err4, err5;

	err1 = uzfs_create_pool("testp", "/tmp/uztest.xyz", &spa1);
	if (spa1 != NULL) {
		printf("shouldn't create pool with non existing disk..\n");
		exit(1);
	}

	err = uzfs_create_pool("testp", "/tmp/uztest.1a", &spa);
	if (err != 0 || spa == NULL) {
		printf("creating pool errored %d..\n", err);
		exit(1);
	}

	err1 = uzfs_create_pool("testp", "/tmp/uztest.1a", &spa1);
	err2 = uzfs_create_pool("testp1", "/tmp/uztest.xyz", &spa2);
	err3 = uzfs_open_pool("testp", &spa3);
	err4 = uzfs_open_pool("testp1", &spa4);
	if (spa1 != NULL || spa2 != NULL || spa4 != NULL ||
	    err1 == 0 || err2 == 0 || err4 == 0) {
		printf("shouldn't create/open, but succeeded..\n");
		exit(1);
	}

	if (err3 != 0 || spa3 == NULL) {
		printf("opening pool errored %d..\n", err3);
		exit(1);
	}

	err = uzfs_create_dataset(spa, "ds0", vol_size, block_size, 0, &zv);
	if (zv == NULL || err != 0) {
		printf("creating ds errored %d..\n", err);
		exit(1);
	}

	err1 = uzfs_create_dataset(spa, "ds0", vol_size, block_size, 0, &zv1);
	err2 = uzfs_open_dataset(spa, "ds0", 0, &zv2);
	err3 = uzfs_open_dataset(spa, "ds1", 0, &zv3);
	err4 = uzfs_open_dataset(NULL, "ds1", 0, &zv4);
	err5 = uzfs_create_dataset(NULL, "ds0", vol_size, block_size, 0, &zv5);
	if (zv1 != NULL || zv2 != NULL || zv3 != NULL || zv4 != NULL ||
	    zv5 != NULL || err1 == 0 || err2 == 0 || err3 == 0 || err4 == 0 ||
	    err5 == 0) {
		printf("shouldn't create/open, but succeeded..\n");
		exit(1);
	}

	err1 = uzfs_vdev_add(spa, "/tmp/uztest.xyz", 12, 0);
	err2 = uzfs_vdev_add(spa, "/tmp/uztest.1a", 12, 0);
	err3 = uzfs_vdev_add(spa, "/tmp/uztest.2a", 12, 0);
	err4 = uzfs_vdev_add(spa, "/tmp/uztest.log", 12, 1);
	if (err1 == 0 || err2 == 0) {
		printf("shouldn't add vdev, but succeeded..\n");
		exit(1);
	}

	if (err3 != 0 || err4 != 0) {
		printf("vdev add errored %d %d..\n", err3, err4);
		exit(1);
	}

	uzfs_close_pool(spa, zv);
}

static void usage(int num)
{
	printf("uzfs_test -t <total_time_in_sec> -a <active data size>"
	    " -b <block_size> -i <io size> -v <vol size>\n");
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


static void process_options(int argc, char **argv)
{
	int opt;
	uint64_t val = 0;
	while ((opt = getopt(argc, argv, "a:b:i:v:t:")) != EOF) {
		if (optarg != NULL)
			val = nicenumtoull(optarg);
		switch (opt) {
			case 'a':
				active_size = val;
				if (vol_size == 0)
					vol_size = active_size;
				else
					active_size = (active_size < vol_size)
					    ? (active_size) : (vol_size);
				break;
			case 'b':
				block_size = val;
				break;
			case 'i':
				io_block_size = val;
				break;
			case 'v':
				vol_size = val;
				if (active_size == 0)
					active_size = vol_size;
				else
					active_size = (active_size < vol_size)
					    ? (active_size) : (vol_size);
				break;
			case 't':
				total_time_in_sec = val;
				break;
			default:
				usage(0);
		}
	}
	if (active_size == 0 || vol_size == 0)
		active_size = vol_size = 1024*1024*1024ULL;

	printf("vol size: %lu active size: %lu\n", vol_size, active_size);
	printf("block size: %lu io blksize: %lu\n", block_size, io_block_size);
	printf("total run time in seconds: %d\n", total_time_in_sec);
}

int
main(int argc, char **argv)
{
	void *spa, *zv;
	kthread_t *reader1;
	kthread_t *writer[3];
	int i, err;
	kmutex_t mtx;
	kcondvar_t cv;
	int threads_done = 0;
	int num_threads = 0;
	worker_args_t reader1_args, writer_args[3];

	mutex_init(&mtx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&cv, NULL, CV_DEFAULT, NULL);

	process_options(argc, argv);

	zfs_arc_max = (512 << 20);
	zfs_arc_min = (256 << 20);

	err = uzfs_init();
	if (err != 0) {
		printf("initialization errored.. %d\n", err);
		exit(1);
	}
	printf("zarcmax: %lu zarcmin:%lu\n", zfs_arc_max, zfs_arc_min);

	setup_unit_test();

	unit_test_create_pool_ds();

	err = uzfs_open_pool("testp", &spa);
	if (err != 0) {
		printf("pool open errored.. %d\n", err);
		exit(1);
	}
	err = uzfs_open_dataset(spa, "ds0", 0, &zv);
	if (err != 0) {
		printf("ds open errored.. %d\n", err);
		exit(1);
	}

	reader1_args.zv = zv;
	reader1_args.threads_done = &threads_done;
	reader1_args.mtx = &mtx;
	reader1_args.cv = &cv;
	reader1_args.io_block_size = io_block_size;
	reader1_args.active_size = active_size;

	reader1 = zk_thread_create(NULL, 0, (thread_func_t)reader_thread,
	    &reader1_args, 0, NULL, TS_RUN, 0, PTHREAD_CREATE_DETACHED);
	num_threads++;

	for (i = 0; i < 3; i++) {
		writer_args[i].zv = zv;
		writer_args[i].threads_done = &threads_done;
		writer_args[i].mtx = &mtx;
		writer_args[i].cv = &cv;
		writer_args[i].io_block_size = io_block_size;
		writer_args[i].active_size = active_size;

		writer[i] = zk_thread_create(NULL, 0,
		    (thread_func_t)writer_thread, &writer_args[i], 0, NULL,
		    TS_RUN, 0, PTHREAD_CREATE_DETACHED);
		num_threads++;
	}

	mutex_enter(&mtx);
	while (threads_done != num_threads)
		cv_wait(&cv, &mtx);
	mutex_exit(&mtx);

	cv_destroy(&cv);
	mutex_destroy(&mtx);

	uzfs_close_pool(spa, zv);
	uzfs_fini();
}
