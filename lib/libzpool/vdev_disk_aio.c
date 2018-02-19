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
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/vdev_impl.h>
#include <sys/zio.h>
#include <sys/abd.h>
#include <sys/kstat.h>

#include <libaio.h>
#include <linux/fs.h>
#include <rte_ring.h>

/*
 * The value is taken from SPDK. It does not scale (and perhaps should) with
 * number of vdevs in the system, we have one queue for all vdevs.
 */
#define	AIO_QUEUE_DEPTH	128

/* XXX Must be kept in sync with zfs_vdev_max_active in vdev_queue.c */
#define	MAX_ZIOS	1000

/*
 * The smaller the more CPU we use, the higher the bigger latency of IOs
 * eventually leading to timeout errors. Empirically was found out that
 * 10ms seems to perform well.
 */
#define	POLL_SLEEP	10000000

/*
 * Virtual device vector for disks accessed from userland using linux aio(7) API
 */

typedef struct vdev_disk_aio {
	int vda_fd;
	/* AIO context used for submitting AIOs and polling */
	io_context_t vda_io_ctx;
	boolean_t vda_stop_polling;
	uintptr_t vda_poller_tid;
	/* Support for submitting multiple IOs in one syscall */
	/* list of zios to enqueue/dequeue from ring buffer */
	zio_t *vda_zio_queue[MAX_ZIOS];
	uint32_t vda_zio_next;	/* next zio to be submitted to kernel */
				/* read & written only from poller thread */
	uint32_t vda_zio_top;	/* latest incoming zio from uzfs */
	/* Preallocated array of iocbs for use in poller to run faster */
	struct iocb *vda_iocbs[MAX_ZIOS];
	struct rte_ring *vda_ring;	/* ring buffer to enqueue/dequeue zio */
} vdev_disk_aio_t;

typedef struct aio_task {
	zio_t *zio;
	void *buf;
	struct iocb iocb;
} aio_task_t;

/*
 * AIO kstats help analysing performance of aio vdev backend.
 */
typedef struct vda_stats {
	kstat_named_t vda_stat_userspace_polls;
	kstat_named_t vda_stat_kernel_polls;
} vda_stats_t;

static vda_stats_t vda_stats = {
	{ "userspace_polls",	KSTAT_DATA_UINT64 },
	{ "kernel_polls",	KSTAT_DATA_UINT64 },
};

#define	VDA_STAT_BUMP(stat)	atomic_inc_64(&vda_stats.stat.value.ui64)

kstat_t *vda_ksp = NULL;

/*
 * Process a single result from asynchronous IO.
 */
static void
vdev_disk_aio_done(aio_task_t *task, int64_t res)
{
	zio_t *zio = task->zio;

	if (zio->io_type == ZIO_TYPE_IOCTL) {
		if (res != 0) {
			zio->io_error = (SET_ERROR(-res));
		}
	} else {
		if (zio->io_type == ZIO_TYPE_READ)
			abd_return_buf_copy(zio->io_abd, task->buf,
			    zio->io_size);
		else if (zio->io_type == ZIO_TYPE_WRITE)
			abd_return_buf(zio->io_abd, task->buf, zio->io_size);
		else
			ASSERT(0);

		if (res < 0) {
			zio->io_error = (SET_ERROR(-res));
		} else if (res != zio->io_size) {
			zio->io_error = (SET_ERROR(ENOSPC));
		}

	}

	/*
	 * Perf optimisation: For reads there is checksum verify pipeline
	 * stage which is CPU intensive and could delay next poll considerably
	 * hence it is executed asynchronously, however for other operations
	 * (write and ioctl) it is faster to finish zio directly (synchronously)
	 * than to dispatch the work to a separate thread.
	 */
	if (zio->io_type == ZIO_TYPE_READ)
		zio_interrupt(zio);
	else
		zio_execute(zio);

	kmem_free(task, sizeof (aio_task_t));
}

/*
 * A copy of aio ring structure to be able to access aio events from userland.
 */
struct aio_ring {
	unsigned id;	/* kernel internal index number */
	unsigned nr;	/* number of io_events */
	unsigned head;
	unsigned tail;

	unsigned magic;
	unsigned compat_features;
	unsigned incompat_features;
	unsigned header_length;  /* size of aio_ring */

	struct io_event events[0];
};

#define	AIO_RING_MAGIC	0xa10a10a1

static int
user_io_getevents(io_context_t io_ctx, struct io_event *events)
{
	long i = 0;
	unsigned head;
	struct aio_ring *ring = (struct aio_ring *)io_ctx;

	while (i < AIO_QUEUE_DEPTH) {
		head = ring->head;

		if (head == ring->tail) {
			/* There are no more completions */
			break;
		} else {
			/* There is another completion to reap */
			events[i] = ring->events[head];
			/* read barrier */
			asm volatile("": : :"memory");
			ring->head = (head + 1) % ring->nr;
			i++;
		}
	}

	return (i);
}

/*
 * Submit all queued ZIOs to kernel and reset length of ZIO queue.
 */
static void
vdev_disk_aio_submit(vdev_disk_aio_t *vda)
{
	struct iocb **iocbs = vda->vda_iocbs;
	int n = 0;
	int nr = 0;

	/*
	 * Dequeue ZIOs from ring buffer as many as possible.
	 * We have used single consumer dequeue operation since polling
	 * thread is only dequeuing from aio_submit ring buffer.
	 */
	nr = rte_ring_sc_dequeue_burst(vda->vda_ring,
	    (void **) &vda->vda_zio_queue, MAX_ZIOS, NULL);

	if (nr > 0) {
		for (n = 0; n < nr; n++) {
			aio_task_t *task;
			zio_t *zio = vda->vda_zio_queue[n];
			ASSERT3P(zio->io_vd->vdev_tsd, ==, vda);
			ASSERT3P(n, <, MAX_ZIOS);

			/*
			 * Prepare AIO command control block.
			 */
			task = kmem_alloc(sizeof (aio_task_t), KM_SLEEP);
			task->zio = zio;
			task->buf = NULL;
			iocbs[n] = &task->iocb;

			switch (zio->io_type) {
			case ZIO_TYPE_WRITE:
				task->buf = abd_borrow_buf_copy(zio->io_abd,
				    zio->io_size);
				io_prep_pwrite(iocbs[n], vda->vda_fd, task->buf,
				    zio->io_size, zio->io_offset);
				break;
			case ZIO_TYPE_READ:
				task->buf = abd_borrow_buf(zio->io_abd,
				    zio->io_size);
				io_prep_pread(iocbs[n], vda->vda_fd, task->buf,
				    zio->io_size, zio->io_offset);
				break;
			default:
				ASSERT(0);
			}

			/*
			 * prep functions above reset data pointer
			 * set it again
			 */
			iocbs[n]->data = task;
		}
	} else {
		return;
	}

	/*
	 * Submit async IO.
	 * XXX What happens if AIO_QUEUE_DEPTH is exceeded?
	 */
	nr = io_submit(vda->vda_io_ctx, n, iocbs);
	if (nr < n) {
		int neg_error;

		if (nr < 0) {
			neg_error = nr;
			nr = 0;
		} else {
			/* No error but the control block was not submitted */
			neg_error = -EAGAIN;
		}

		for (int i = nr; i < n; i++) {
			aio_task_t *task = (aio_task_t *)iocbs[i]->data;
			vdev_disk_aio_done(task, neg_error);
		}
	}
}

/*
 * Poll for asynchronous IO done events and submit incoming IOs from a queue.
 */
static void
vdev_disk_aio_poll(void *arg)
{
	vdev_disk_aio_t *vda = arg;
	struct io_event *events;
	struct timespec timeout;
	int nr;

	/* allocated on heap not to exceed recommended frame size */
	events = kmem_alloc(sizeof (struct io_event) * AIO_QUEUE_DEPTH,
	    KM_SLEEP);

	while (!vda->vda_stop_polling) {
		timeout.tv_sec = 0;
		timeout.tv_nsec = POLL_SLEEP;
		nr = 0;

		/* First we try non-blocking userspace poll which is fast */
		if (((struct aio_ring *)(vda->vda_io_ctx))->magic ==
		    AIO_RING_MAGIC) {
			nr = user_io_getevents(vda->vda_io_ctx, events);
		}
		if (nr <= 0) {
			/* Do blocking kernel poll */
			nr = io_getevents(vda->vda_io_ctx, 1, AIO_QUEUE_DEPTH,
			    events, &timeout);
		} else {
			VDA_STAT_BUMP(vda_stat_userspace_polls);
		}

		if (nr < 0) {
			int error = -nr;

			/* all errors except EINTR are unrecoverable */
			if (error == EINTR) {
				continue;
			} else {
				fprintf(stderr,
				    "Failed when polling for AIO events: %d\n",
				    error);
				break;
			}
		}
		ASSERT3P(nr, <=, AIO_QUEUE_DEPTH);

		for (int i = 0; i < nr; i++) {
			vdev_disk_aio_done(events[i].data, events[i].res);
		}

		/*
		 * Submit IOs which arrived while waiting for and processing
		 * done events.
		 */
		if (!vda->vda_stop_polling)
			vdev_disk_aio_submit(vda);
	}

	kmem_free(events, sizeof (struct io_event) * AIO_QUEUE_DEPTH);
	vda->vda_poller_tid = 0;
	thread_exit();
}

/*
 * We probably can't do anything better from userland than opening the device
 * to prevent it from going away. So hold and rele are noops.
 */
static void
vdev_disk_aio_hold(vdev_t *vd)
{
	ASSERT(vd->vdev_path != NULL);
}

static void
vdev_disk_aio_rele(vdev_t *vd)
{
	ASSERT(vd->vdev_path != NULL);
}

/*
 * Opens dev file, creates AIO context and poller thread.
 */
static int
vdev_disk_aio_open(vdev_t *vd, uint64_t *psize, uint64_t *max_psize,
    uint64_t *ashift)
{
	vdev_disk_aio_t *vda;
	unsigned short isrot = 0;
	int err;

	/*
	 * We must have a pathname, and it must be absolute.
	 */
	if (vd->vdev_path == NULL || vd->vdev_path[0] != '/') {
		vd->vdev_stat.vs_aux = VDEV_AUX_BAD_LABEL;
		return (SET_ERROR(EINVAL));
	}

	/*
	 * Reopen the device if it's not currently open.  Otherwise,
	 * just update the physical size of the device.
	 */
	if (vd->vdev_tsd != NULL) {
		ASSERT(vd->vdev_reopening);
		vda = vd->vdev_tsd;
		goto skip_open;
	}

	vda = kmem_zalloc(sizeof (vdev_disk_aio_t), KM_SLEEP);

	ASSERT(vd->vdev_path != NULL && vd->vdev_path[0] == '/');
	vda->vda_fd = open(vd->vdev_path,
	    ((spa_mode(vd->vdev_spa) & FWRITE) != 0) ? O_RDWR|O_DIRECT :
	    O_RDONLY|O_DIRECT);

	if (vda->vda_fd < 0) {
		kmem_free(vda, sizeof (vdev_disk_aio_t));
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		return (SET_ERROR(errno));
	}

	/*
	 * TODO: code in fio aio plugin suggests that for new kernels we can
	 * pass INTMAX as limit here and use max limit allowed by the kernel.
	 * However for userspace polling we need some kind of limit.
	 */
	err = io_setup(AIO_QUEUE_DEPTH, &vda->vda_io_ctx);
	if (err != 0) {
		fprintf(stderr, "Failed to initialize AIO context: %d\n", -err);
		close(vda->vda_fd);
		kmem_free(vda, sizeof (vdev_disk_aio_t));
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		return (SET_ERROR(-err));
	}

	/* Create RTE RING to enqueue/dequeue ZIOs */
	vda->vda_ring = rte_ring_create("aio_submit_ring", MAX_ZIOS,
	    -1, RING_F_EXACT_SZ);
	if (!vda->vda_ring) {
		fprintf(stderr, "Failed to create aio_submit ring\n");
		(void) io_destroy(vda->vda_io_ctx);
		vda->vda_io_ctx = NULL;
		return (SET_ERROR(ENOMEM));
	}

	vda->vda_stop_polling = B_FALSE;
	vda->vda_poller_tid = (uintptr_t)thread_create(NULL, 0,
	    vdev_disk_aio_poll, vda, 0, &p0, TS_RUN, 0);

	vd->vdev_tsd = vda;

skip_open:
	if (ioctl(vda->vda_fd, BLKSSZGET, ashift) != 0) {
		(void) close(vda->vda_fd);
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		return (SET_ERROR(errno));
	}
	if (ioctl(vda->vda_fd, BLKGETSIZE64, psize) != 0) {
		(void) close(vda->vda_fd);
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		return (SET_ERROR(errno));
	}
	if (ioctl(vda->vda_fd, BLKROTATIONAL, &isrot) != 0) {
		(void) close(vda->vda_fd);
		vd->vdev_stat.vs_aux = VDEV_AUX_OPEN_FAILED;
		return (SET_ERROR(errno));
	}

	*ashift = highbit64(MAX(*ashift, SPA_MINBLOCKSIZE)) - 1;
	*max_psize = *psize;
	vd->vdev_nonrot = !isrot;

	return (0);
}

/*
 * Waits for poller thread to exit and destroys AIO context.
 *
 * TODO: The current algorithm for poller thread exit is rough and full of
 * sleeps.
 */
static void
vdev_disk_aio_close(vdev_t *vd)
{
	vdev_disk_aio_t *vda = vd->vdev_tsd;
	struct timespec ts;

	if (vd->vdev_reopening || vda == NULL)
		return;

	ASSERT3P(vda->vda_zio_next, ==, vda->vda_zio_top);
	ts.tv_sec = 0;
	ts.tv_nsec = 100000000;  // 100ms

	vda->vda_stop_polling = B_TRUE;
	while (vda->vda_poller_tid != 0) {
		nanosleep(&ts, NULL);
	}

	if (vda->vda_io_ctx) {
		(void) io_destroy(vda->vda_io_ctx);
		vda->vda_io_ctx = NULL;
	}

	(void) close(vda->vda_fd);

	vd->vdev_delayed_close = B_FALSE;

	if (vda->vda_ring) {
		rte_ring_free(vda->vda_ring);
		vda->vda_ring = NULL;
	}
	kmem_free(vda, sizeof (vdev_disk_aio_t));
	vd->vdev_tsd = NULL;
}

/*
 * Check and put valid IOs to submit queue.
 */
static void
vdev_disk_aio_start(zio_t *zio)
{
	vdev_t *vd = zio->io_vd;
	vdev_disk_aio_t *vda = vd->vdev_tsd;

	/*
	 * Check operation type.
	 */
	switch (zio->io_type) {
	case ZIO_TYPE_IOCTL:
		if (!vdev_readable(vd)) {
			zio->io_error = (SET_ERROR(ENXIO));
			zio_interrupt(zio);
			return;
		}
		if (zio->io_cmd != DKIOCFLUSHWRITECACHE) {
			zio->io_error = (SET_ERROR(ENOTSUP));
			zio_execute(zio);
			return;
		}
		/*
		 * fsync for device files should not be needed.
		 * XXX Disk cache flush is needed but how to do that?
		 */
		zio_execute(zio);
		return;

	case ZIO_TYPE_WRITE:
		break;
	case ZIO_TYPE_READ:
		break;
	default:
		zio->io_error = (SET_ERROR(ENOTSUP));
		zio_interrupt(zio);
		break;
	}

	/*
	 * Enqueue zio and poller thread will take care of it.
	 */

	if (rte_ring_mp_enqueue(vda->vda_ring, (void **) &zio)) {
		fprintf(stderr, "Failed to enqueue zio in ring\n");
		zio->io_error = (SET_ERROR(EBUSY));
		zio_interrupt(zio);
	}
}

/* ARGSUSED */
static void
vdev_disk_zio_done(zio_t *zio)
{
	/*
	 * This callback is used to trigger device removal or do another
	 * smart things in case that zio ends up with EIO error.
	 * As of now nothing implemented here.
	 */
}

void
vdev_disk_aio_init(void)
{
	vda_ksp = kstat_create("zfs", 0, "vdev_aio_stats", "misc",
	    KSTAT_TYPE_NAMED, sizeof (vda_stats_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);

	if (vda_ksp != NULL) {
		vda_ksp->ks_data = &vda_stats;
		kstat_install(vda_ksp);
	}
}

void
vdev_disk_aio_fini(void)
{
	if (vda_ksp != NULL) {
		kstat_delete(vda_ksp);
		vda_ksp = NULL;
	}
}

vdev_ops_t vdev_disk_ops = {
	vdev_disk_aio_open,
	vdev_disk_aio_close,
	vdev_default_asize,
	vdev_disk_aio_start,
	vdev_disk_zio_done,
	NULL,
	NULL,
	vdev_disk_aio_hold,
	vdev_disk_aio_rele,
	VDEV_TYPE_DISK,		/* name of this vdev type */
	B_TRUE			/* leaf vdev */
};
