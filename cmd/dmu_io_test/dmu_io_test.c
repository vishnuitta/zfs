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

#include <string.h>
#include <stdlib.h>
#include <sys/dmu_objset.h>
#include <sys/zap.h>
#include <sys/stat.h>

#define	DEFAULT_NBLOCKS	1000
#define	HOLD_TAG	"TEST_IO_HOLD"
#define	BLKSIZE		(1 << 12)
#define	VOLSIZE		(1ULL << 25)
#define	ZVOL_OBJ	1ULL
#define	ZVOL_ZAP_OBJ	2ULL

static nvlist_t *
make_root(char *path, int ashift)
{
	nvlist_t *root, *child;
	struct stat64 statbuf;
	const char *vdev_type;

	if (stat64(path, &statbuf) != 0)
		return (NULL);

	if (S_ISBLK(statbuf.st_mode)) {
		vdev_type = VDEV_TYPE_DISK;
	} else {
		vdev_type = VDEV_TYPE_FILE;
	}
	printf("vdev type: %s\n", vdev_type);

	VERIFY(nvlist_alloc(&child, NV_UNIQUE_NAME, 0) == 0);
	VERIFY(nvlist_add_string(child, ZPOOL_CONFIG_TYPE, vdev_type) == 0);
	VERIFY(nvlist_add_string(child, ZPOOL_CONFIG_PATH, path) == 0);
	VERIFY(nvlist_add_uint64(child, ZPOOL_CONFIG_ASHIFT, ashift) == 0);
	VERIFY(nvlist_add_uint64(child, ZPOOL_CONFIG_IS_LOG, 0) == 0);

	nvlist_alloc(&root, NV_UNIQUE_NAME, 0);
	nvlist_add_string(root, ZPOOL_CONFIG_TYPE, VDEV_TYPE_ROOT);
	nvlist_add_nvlist_array(root, ZPOOL_CONFIG_CHILDREN, &child, 1);

	nvlist_free(child);
	return (root);
}


/* Opens the pool if any with 'name' */
spa_t *
uzfs_open_pool(char *name)
{
	spa_t *spa = NULL;

	int err = spa_open(name, &spa, HOLD_TAG);
	if (err != 0) {
		fprintf(stderr, "Error opening pool %s: %d\n", name, err);
		return (NULL);
	}
	printf("opened pool %s\n", name);
	return (spa);
}

/* creates the pool 'name' with a disk at 'path' */
int
uzfs_create_pool(char *name, char *path)
{
	nvlist_t *nvroot;
	int err;

	(void) spa_destroy(name);

	nvroot = make_root(path, 12);
	if (nvroot == NULL) {
		fprintf(stderr, "error creating pool nvlist\n");
		return (-1);
	}

	err = spa_create(name, nvroot, NULL, NULL);
	nvlist_free(nvroot);

	if (err != 0) {
		fprintf(stderr, "error creating pool %s: %d\n", name, err);
		return (-1);
	}

	printf("Created pool %s\n", name);
	return (0);
}

/*
 * callback when a zvol objset is created
 * Create the objects common to all uzfs datasets.
 */
void
uzfs_objset_create_cb(objset_t *new_os, void *arg, cred_t *cr, dmu_tx_t *tx)
{
	uint64_t error;
	uint64_t volsize = VOLSIZE;

	error = dmu_object_claim(new_os, ZVOL_OBJ, DMU_OT_ZVOL,
	    BLKSIZE, DMU_OT_NONE, 0, tx);
	VERIFY(error == 0);

	error = zap_create_claim(new_os, ZVOL_ZAP_OBJ, DMU_OT_ZVOL_PROP,
	    DMU_OT_NONE, 0, tx);
	VERIFY(error == 0);

	error = zap_update(new_os, ZVOL_ZAP_OBJ, "size", 8, 1, &volsize, tx);
	VERIFY(error == 0);
}

/* owns objset with name 'ds_name' in pool 'spa'. Sets 'sync' property */
objset_t *
uzfs_open_dataset(spa_t *spa, const char *ds_name)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	int error;
	objset_t *os;

	(void) snprintf(name, sizeof (name), "%s/%s", spa_name(spa), ds_name);

	error = dmu_objset_own(name, DMU_OST_ZVOL, B_FALSE, HOLD_TAG, &os);
	if (error) {
		fprintf(stderr, "error owning objset %s: %d\n", name, error);
		return (NULL);
	}
	printf("Owning dataset %s\n", name);
	return (os);
}

/*
 * Creates dataset 'ds_name' in pool 'spa' with volume size 'vol_size',
 * block size as 'block_size' and with 'sync' property
 */
int
uzfs_create_dataset(spa_t *spa, char *ds_name)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];

	(void) snprintf(name, sizeof (name), "%s/%s", spa_name(spa), ds_name);

	int err = dmu_objset_create(name, DMU_OST_ZVOL, 0,
	    uzfs_objset_create_cb, NULL);
	if (err) {
		fprintf(stderr, "error creating %s: %d\n", name, err);
		return (-1);
	}
	printf("Created dataset %s\n", name);
	return (0);
}

/* disowns, closes dataset and pool */
void
uzfs_close_all(spa_t *spa, objset_t *os)
{
	dmu_objset_disown(os, HOLD_TAG);
	spa_close(spa, HOLD_TAG);
}

/*
 * Allocate N * 4k block, write all blocks, read them and verify.
 */
int
test_io(objset_t *os)
{
	uint64_t offset;
	uint64_t bsize = (1 << 12);
	uint64_t size = DEFAULT_NBLOCKS * bsize;
	char *writebufs = kmem_alloc(size, KM_SLEEP);
	char *readbufs = kmem_alloc(size, KM_SLEEP);
	int error;
	int rc = 0;
	hrtime_t start, end;

	printf("Writing blocks ");
	offset = 0;
	start = gethrtime();
	while (offset < size) {
		dmu_tx_t *tx = dmu_tx_create(os);
		dmu_tx_hold_write(tx, ZVOL_OBJ, offset, bsize);
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error != 0) {
			fprintf(stderr, "tx assign failed: %d\n", error);
			dmu_tx_abort(tx);
			rc = -1;
			goto end;
		}
		dmu_write(os, ZVOL_OBJ, offset, bsize, writebufs + offset, tx);
		dmu_tx_commit(tx);
		printf(".");
		offset += bsize;
	}
	end = gethrtime();
	printf("\nDone in %lld ms\n", (end - start) / 1000000);

	printf("Reading blocks ");
	offset = 0;
	start = gethrtime();
	while (offset < size) {
		error = dmu_read(os, ZVOL_OBJ, offset, bsize, readbufs + offset,
		    0);
		if (error != 0) {
			fprintf(stderr, "read failed: %d\n", error);
			rc = -1;
			goto end;
		}
		printf(".");
		offset += bsize;
	}
	end = gethrtime();
	printf("\nDone in %lld ms\n", (end - start) / 1000000);

	printf("Verifying blocks\n");
	if (memcmp(writebufs, readbufs, size) != 0) {
		fprintf(stderr, "data corruption detected\n");
		rc = -1;
	}

end:
	kmem_free(writebufs, size);
	kmem_free(readbufs, size);
	return (rc);
}

/*
 * Create a pool on given device and write & read data from it.
 */
int
main(int argc, char **argv)
{
	char *pool;
	char *vol;
	char *c;
	objset_t *os;
	spa_t *spa;

	kernel_init(FREAD | FWRITE);

	if (argc != 3) {
		fprintf(stderr, "Usage: dmu_io_test <dataset> <dev>\n");
		exit(1);
	}

	c = strchr(argv[1], '/');
	if (c == NULL) {
		fprintf(stderr, "Usage: dmu_io_test <dataset> <dev>\n");
		exit(1);
	}
	*c = '\0';
	pool = argv[1];
	vol = c + 1;

	if (uzfs_create_pool(pool, argv[2]) != 0)
		return (1);

	spa = uzfs_open_pool(pool);
	if (spa == NULL) {
		(void) spa_destroy(pool);
		return (1);
	}

	if (uzfs_create_dataset(spa, vol) != 0) {
		(void) spa_destroy(pool);
		return (1);
	}

	os = uzfs_open_dataset(spa, vol);
	if (os == NULL) {
		(void) spa_destroy(pool);
		return (1);
	}

	/*
	 * Finally test write and read.
	 */
	test_io(os);

	uzfs_close_all(spa, os);
	kernel_fini();
	return (0);
}
