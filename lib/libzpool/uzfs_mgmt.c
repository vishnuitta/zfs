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

#include <sys/dmu_objset.h>
#include <sys/zap.h>
#include <sys/uzfs_zvol.h>

static int uzfs_fd_rand = -1;

static nvlist_t *
make_root(char *path, int ashift, int log)
{
	nvlist_t *root = NULL, *child;

	if (nvlist_alloc(&child, NV_UNIQUE_NAME, 0) != 0)
		goto ret;
	if (nvlist_add_string(child, ZPOOL_CONFIG_TYPE,
	    VDEV_TYPE_DISK) != 0)
		goto free_ret;
	if (nvlist_add_string(child, ZPOOL_CONFIG_PATH, path) != 0)
		goto free_ret;
	if (nvlist_add_uint64(child, ZPOOL_CONFIG_ASHIFT, ashift) != 0)
		goto free_ret;
	if (nvlist_add_uint64(child, ZPOOL_CONFIG_IS_LOG, log) != 0)
		goto free_ret;

	if (nvlist_alloc(&root, NV_UNIQUE_NAME, 0) != 0) {
		root = NULL;
		goto free_ret;
	}
	if (nvlist_add_string(root, ZPOOL_CONFIG_TYPE, VDEV_TYPE_ROOT) != 0)
		goto free_root_ret;
	if (nvlist_add_nvlist_array(root, ZPOOL_CONFIG_CHILDREN, &child, 1)
	    != 0) {
free_root_ret:
		nvlist_free(root);
		root = NULL;
		goto free_ret;
	}
free_ret:
	nvlist_free(child);
ret:
	return (root);
}

/* Generates random number in the [0-range] */
uint64_t
uzfs_random(uint64_t range)
{

	uint64_t r;

	ASSERT3S(uzfs_fd_rand, >=, 0);

	if (range == 0)
		return (0);

	while (read(uzfs_fd_rand, &r, sizeof (r)) != sizeof (r))
		;

	return (r % range);
}

int
uzfs_init(void)
{
	int err = 0;
	kernel_init(FREAD | FWRITE);
	uzfs_fd_rand = open("/dev/urandom", O_RDONLY);
	if (uzfs_fd_rand == -1)
		err = errno;
	return (err);
}

/* Opens the pool if any with 'name' */
int
uzfs_open_pool(char *name, spa_t **s)
{
	spa_t *spa = NULL;
	int err = spa_open(name, &spa, FTAG);
	if (err != 0) {
		spa = NULL;
		goto ret;
	}
ret:
	*s = spa;
	return (err);
}

/* creates the pool 'name' with a disk at 'path' */
int
uzfs_create_pool(char *name, char *path, spa_t **s)
{
	nvlist_t *nvroot;
	spa_t *spa = NULL;
	int err = -1;
	/*
	 * Create the storage pool.
	 */

	(void) spa_destroy(name);

	nvroot = make_root(path, 12, 0);
	if (nvroot == NULL)
		goto ret;

	err = spa_create(name, nvroot, NULL, NULL);
	nvlist_free(nvroot);

	if (err != 0)
		goto ret;

	err = uzfs_open_pool(name, &spa);
	if (err != 0) {
		(void) spa_destroy(name);
		spa = NULL;
		goto ret;
	}
ret:
	*s = spa;
	return (err);
}

/* Adds vdev at 'path' to pool 'spa' as either log or data device */
int
uzfs_vdev_add(spa_t *spa, char *path, int ashift, int log)
{
	nvlist_t *nvroot;
	int error = -1;

	nvroot = make_root(path, ashift, log);
	if (nvroot == NULL)
		goto ret;

	error = spa_vdev_add(spa, nvroot);

	nvlist_free(nvroot);
ret:
	return (error);
}

/*
 * callback when a zvol objset is created
 * Any error here will bring down the process
 */
void
uzfs_objset_create_cb(objset_t *new_os, void *arg, cred_t *cr, dmu_tx_t *tx)
{
	/*
	 * Create the objects common to all uzfs datasets.
	 */
	uint64_t error;

	zvol_properties_t *properties = (zvol_properties_t *)arg;

	error = dmu_object_claim(new_os, ZVOL_OBJ, DMU_OT_ZVOL,
	    properties->block_size, DMU_OT_NONE, 0, tx);
	VERIFY(error == 0);

	error = zap_create_claim(new_os, ZVOL_ZAP_OBJ, DMU_OT_ZVOL_PROP,
	    DMU_OT_NONE, 0, tx);
	VERIFY(error == 0);

	error = zap_update(new_os, ZVOL_ZAP_OBJ, "size", 8, 1,
	    &properties->vol_size, tx);
	VERIFY(error == 0);
}

/* owns objset with name 'ds_name' in pool 'spa'. Sets 'sync' property */
int
uzfs_open_dataset(spa_t *spa, const char *ds_name, int sync, zvol_state_t **z)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	zvol_state_t *zv = NULL;
	int error = -1;
	objset_t *os;
	dmu_object_info_t doi;
	uint64_t block_size, vol_size;

	if (spa == NULL)
		goto ret;
	(void) snprintf(name, sizeof (name), "%s/%s", spa_name(spa), ds_name);

	zv = kmem_zalloc(sizeof (zvol_state_t), KM_SLEEP);
	if (zv == NULL)
		goto ret;
	zv->zv_spa = spa;
	zfs_rlock_init(&zv->zv_range_lock);

	strlcpy(zv->zv_name, name, MAXNAMELEN);

	error = dmu_objset_own(name, DMU_OST_ZVOL, 1, zv, &os);
	if (error)
		goto free_ret;
	zv->zv_objset = os;

	error = dmu_object_info(os, ZVOL_OBJ, &doi);
	if (error)
		goto disown_free;
	block_size = doi.doi_data_block_size;

	error = zap_lookup(os, ZVOL_ZAP_OBJ, "size", 8, 1, &vol_size);
	if (error)
		goto disown_free;

	error = dnode_hold(os, ZVOL_OBJ, zv, &zv->zv_dn);
	if (error) {
disown_free:
		dmu_objset_disown(zv->zv_objset, zv);
free_ret:
		kmem_free(zv, sizeof (zvol_state_t));
		zv = NULL;
		goto ret;
	}

	zv->zv_zilog = zil_open(os, zvol_get_data);
	zv->zv_sync = sync;
	zv->zv_volblocksize = block_size;
	zv->zv_volsize = vol_size;
ret:
	*z = zv;
	return (error);
}

/*
 * Creates dataset 'ds_name' in pool 'spa' with volume size 'vol_size',
 * block size as 'block_size' and with 'sync' property
 */
int
uzfs_create_dataset(spa_t *spa, char *ds_name, uint64_t vol_size,
    uint64_t block_size, int sync, zvol_state_t **z)
{
	char name[ZFS_MAX_DATASET_NAME_LEN];
	zvol_state_t *zv = NULL;
	zvol_properties_t properties;
	int error = -1;

	if (spa == NULL)
		goto ret;
	(void) snprintf(name, sizeof (name), "%s/%s", spa_name(spa), ds_name);

	properties.vol_size = vol_size;
	properties.block_size = block_size;

	error = dmu_objset_create(name, DMU_OST_ZVOL, 0,
	    uzfs_objset_create_cb, &properties);

	if (error)
		goto ret;

	error = uzfs_open_dataset(spa, ds_name, sync, &zv);
	if (error != 0) {
		zv = NULL;
		goto ret;
	}
ret:
	*z = zv;
	return (error);
}

/* disowns, closes dataset and pool */
void
uzfs_close_pool(spa_t *spa, zvol_state_t *zv)
{
	dmu_objset_disown(zv->zv_objset, zv);
	zil_close(zv->zv_zilog);
	dnode_rele(zv->zv_dn, zv);
	kmem_free(zv, sizeof (zvol_state_t));
	spa_close(spa, FTAG);
}

void
uzfs_fini(void)
{
	kernel_fini();
	if (uzfs_fd_rand != -1)
		close(uzfs_fd_rand);
}
