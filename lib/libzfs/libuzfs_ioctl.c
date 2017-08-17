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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libuzfs.h>
#include <sys/dsl_prop.h>
#include <sys/zil.h>
#include <sys/zvol.h>
#include <sys/zap.h>
#include <assert.h>
#include <sys/spa_impl.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_bookmark.h>
#include <sys/types.h>
#include <sys/dmu_objset.h>
#include <sys/dsl_dir.h>
#include <sys/dmu_send.h>
#include <sys/dsl_destroy.h>
#include <sys/zfs_acl.h>
#include <sys/zio_checksum.h>
#include <sys/zfs_znode.h>

#include "zfs_fletcher.h"
#include "zfs_namecheck.h"
#include "zfs_comutil.h"
#include "zfs_prop.h"
#include "zfeature_common.h"

static int
get_nvlist(uint64_t nvl, uint64_t size, int iflag, nvlist_t **nvp)
{
	char *packed;
	int error;
	nvlist_t *list = NULL;

	/*
	 * Read in and unpack the user-supplied nvlist.
	 */
	if (size == 0)
		return EINVAL;

	packed = (void *) (uintptr_t) nvl;

	if ((error = nvlist_unpack(packed, size, &list, 0)) != 0)
		return (error);

	*nvp = list;
	return (0);
}

static int
put_nvlist(zfs_cmd_t *zc, nvlist_t *nvl)
{
	char *packed = NULL;
	int error = 0;
	size_t size;

	size = fnvlist_size(nvl);

	if (size > zc->zc_nvlist_dst_size) {
		error = SET_ERROR(ENOMEM);
	} else {
		packed = fnvlist_pack(nvl, &size);
		memcpy((void *) (uintptr_t) zc->zc_nvlist_dst, packed, size);
		fnvlist_pack_free(packed, size);
	}

	zc->zc_nvlist_dst_size = size;
	zc->zc_nvlist_dst_filled = B_TRUE;
	return (error);
}

/*
 * Return non-zero if the spa version is less than requested version.
 */
static int
zfs_earlier_version(const char *name, int version)
{
	spa_t *spa;

	if (spa_open(name, &spa, FTAG) == 0) {
		if (spa_version(spa) < version) {
			spa_close(spa, FTAG);
			return (1);
		}
		spa_close(spa, FTAG);
	}
	return (0);
}

static int
zfs_dozonecheck_impl(const char *dataset, uint64_t zoned, cred_t *cr)
{
	int writable = 1;

	/*
	 * The dataset must be visible by this zone -- check this first
	 * so they don't see EPERM on something they shouldn't know about.
	 */
	if (!INGLOBALZONE(curproc) &&
	    !zone_dataset_visible(dataset, &writable))
		return (SET_ERROR(ENOENT));

	if (INGLOBALZONE(curproc)) {
		/*
		 * If the fs is zoned, only root can access it from the
		 * global zone.
		 */
		if (secpolicy_zfs(cr) && zoned)
			return (SET_ERROR(EPERM));
	} else {
		/*
		 * If we are in a local zone, the 'zoned' property must be set.
		 */
		if (!zoned)
			return (SET_ERROR(EPERM));

		/* must be writable by this zone */
		if (!writable)
			return (SET_ERROR(EPERM));
	}
	return (0);
}

static int
zfs_dozonecheck_ds(const char *dataset, dsl_dataset_t *ds, cred_t *cr)
{
	uint64_t zoned;

	if (dsl_prop_get_int_ds(ds, "zoned", &zoned))
		return (SET_ERROR(ENOENT));

	return (zfs_dozonecheck_impl(dataset, zoned, cr));
}

static int
zfs_secpolicy_write_perms_ds(const char *name, dsl_dataset_t *ds,
                             const char *perm, cred_t *cr)
{
	int error;

	error = zfs_dozonecheck_ds(name, ds, cr);
	if (error == 0) {
		error = secpolicy_zfs(cr);
		if (error != 0)
			error = dsl_deleg_access_impl(ds, perm, cr);
	}
	return (error);
}

static int
zfs_secpolicy_write_perms(const char *name, const char *perm, cred_t *cr)
{
	int error;
	dsl_dataset_t *ds;
	dsl_pool_t *dp;

	/*
	 * First do a quick check for root in the global zone, which
	 * is allowed to do all write_perms.  This ensures that zfs_ioc_*
	 * will get to handle nonexistent datasets.
	 */
	if (INGLOBALZONE(curproc) && secpolicy_zfs(cr) == 0)
		return (0);

	error = dsl_pool_hold(name, FTAG, &dp);
	if (error != 0)
		return (error);

	error = dsl_dataset_hold(dp, name, FTAG, &ds);
	if (error != 0) {
		dsl_pool_rele(dp, FTAG);
		return (error);
	}

	error = zfs_secpolicy_write_perms_ds(name, ds, perm, cr);

	dsl_dataset_rele(ds, FTAG);
	dsl_pool_rele(dp, FTAG);
	return (error);
}

/*
 * Check that all the properties are valid user properties.
 */
static int
zfs_check_userprops(const char *fsname, nvlist_t *nvl)
{
	nvpair_t *pair = NULL;
	int error = 0;

	while ((pair = nvlist_next_nvpair(nvl, pair)) != NULL) {
		const char *propname = nvpair_name(pair);

		if (!zfs_prop_user(propname) ||
		    nvpair_type(pair) != DATA_TYPE_STRING)
			return (SET_ERROR(EINVAL));

		if ((error = zfs_secpolicy_write_perms(fsname,
		                                       ZFS_DELEG_PERM_USERPROP,
		                                       CRED())))
			return (error);

		if (strlen(propname) >= ZAP_MAXNAMELEN)
			return (SET_ERROR(ENAMETOOLONG));

		if (strlen(fnvpair_value_string(pair)) >= ZAP_MAXVALUELEN)
			return (SET_ERROR(E2BIG));
	}
	return (0);
}

static boolean_t
dataset_name_hidden(const char *name)
{
	/*
	 * Skip over datasets that are not visible in this zone,
	 * internal datasets (which have a $ in their name), and
	 * temporary datasets (which have a % in their name).
	 */
	if (strchr(name, '$') != NULL)
		return (B_TRUE);
	if (strchr(name, '%') != NULL)
		return (B_TRUE);
	if (!INGLOBALZONE(curproc) && !zone_dataset_visible(name, NULL))
		return (B_TRUE);
	return (B_FALSE);
}

void
zvol_create_cb(objset_t *os, void *arg, cred_t *cr, dmu_tx_t *tx)
{
	zfs_creat_t *zct = arg;
	nvlist_t *nvprops = zct->zct_props;
	int error;
	uint64_t volblocksize, volsize;

	VERIFY(nvlist_lookup_uint64(nvprops,
	                            zfs_prop_to_name(ZFS_PROP_VOLSIZE),
	                            &volsize) == 0);
	if (nvlist_lookup_uint64(nvprops,
	                         zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE),
	                         &volblocksize) != 0)
		volblocksize = zfs_prop_default_numeric(ZFS_PROP_VOLBLOCKSIZE);

	/*
	 * These properties must be removed from the list so the generic
	 * property setting step won't apply to them.
	 */
	VERIFY(nvlist_remove_all(nvprops,
	                         zfs_prop_to_name(ZFS_PROP_VOLSIZE)) == 0);
	(void) nvlist_remove_all(nvprops,
	                         zfs_prop_to_name(ZFS_PROP_VOLBLOCKSIZE));

	error = dmu_object_claim(os, ZVOL_OBJ, DMU_OT_ZVOL, volblocksize,
	                         DMU_OT_NONE, 0, tx);
	ASSERT(error == 0);

	error = zap_create_claim(os, ZVOL_ZAP_OBJ, DMU_OT_ZVOL_PROP,
	                         DMU_OT_NONE, 0, tx);
	ASSERT(error == 0);

	error = zap_update(os, ZVOL_ZAP_OBJ, "size", 8, 1, &volsize, tx);
	ASSERT(error == 0);
}

#define ZFS_PROP_UNDEFINED      ((uint64_t)-1)

int
zfs_get_zplprop(objset_t *os, zfs_prop_t prop, uint64_t *value)
{
	const char *pname;
	int error = SET_ERROR(ENOENT);

	/*
	 * Look up the file system's value for the property.  For the
	 * version property, we look up a slightly different string.
	 */
	if (prop == ZFS_PROP_VERSION)
		pname = ZPL_VERSION_STR;
	else
		pname = zfs_prop_to_name(prop);

	if (os != NULL) {
		ASSERT3U(os->os_phys->os_type, ==, DMU_OST_ZFS);
		error = zap_lookup(os, MASTER_NODE_OBJ, pname, 8, 1, value);
	}

	if (error == ENOENT) {
		/* No value set, use the default value */
		switch (prop) {
		case ZFS_PROP_VERSION:
			*value = ZPL_VERSION;
			break;
		case ZFS_PROP_NORMALIZE:
		case ZFS_PROP_UTF8ONLY:
			*value = 0;
			break;
		case ZFS_PROP_CASE:
			*value = ZFS_CASE_SENSITIVE;
			break;
		case ZFS_PROP_ACLTYPE:
			*value = ZFS_ACLTYPE_OFF;
			break;
		default:
			return (error);
		}
		error = 0;
	}
	return (error);
}

static int
zfs_fill_zplprops_impl(objset_t *os, uint64_t zplver,
    boolean_t fuids_ok, boolean_t sa_ok, nvlist_t *createprops,
    nvlist_t *zplprops, boolean_t *is_ci)
{
	uint64_t sense = ZFS_PROP_UNDEFINED;
	uint64_t norm = ZFS_PROP_UNDEFINED;
	uint64_t u8 = ZFS_PROP_UNDEFINED;
	int error;

	ASSERT(zplprops != NULL);

	if (os != NULL && os->os_phys->os_type != DMU_OST_ZFS)
		return (SET_ERROR(EINVAL));

	/*
	 * Pull out creator prop choices, if any.
	 */
	if (createprops) {
		(void) nvlist_lookup_uint64(createprops,
		    zfs_prop_to_name(ZFS_PROP_VERSION), &zplver);
		(void) nvlist_lookup_uint64(createprops,
		    zfs_prop_to_name(ZFS_PROP_NORMALIZE), &norm);
		(void) nvlist_remove_all(createprops,
		    zfs_prop_to_name(ZFS_PROP_NORMALIZE));
		(void) nvlist_lookup_uint64(createprops,
		    zfs_prop_to_name(ZFS_PROP_UTF8ONLY), &u8);
		(void) nvlist_remove_all(createprops,
		    zfs_prop_to_name(ZFS_PROP_UTF8ONLY));
		(void) nvlist_lookup_uint64(createprops,
		    zfs_prop_to_name(ZFS_PROP_CASE), &sense);
		(void) nvlist_remove_all(createprops,
		    zfs_prop_to_name(ZFS_PROP_CASE));
	}

	/*
	 * If the zpl version requested is whacky or the file system
	 * or pool is version is too "young" to support normalization
	 * and the creator tried to set a value for one of the props,
	 * error out.
	 */
	if ((zplver < ZPL_VERSION_INITIAL || zplver > ZPL_VERSION) ||
	    (zplver >= ZPL_VERSION_FUID && !fuids_ok) ||
	    (zplver >= ZPL_VERSION_SA && !sa_ok) ||
	    (zplver < ZPL_VERSION_NORMALIZATION &&
	    (norm != ZFS_PROP_UNDEFINED || u8 != ZFS_PROP_UNDEFINED ||
	    sense != ZFS_PROP_UNDEFINED)))
		return (SET_ERROR(ENOTSUP));

	/*
	 * Put the version in the zplprops
	 */
	VERIFY(nvlist_add_uint64(zplprops,
	    zfs_prop_to_name(ZFS_PROP_VERSION), zplver) == 0);

	if (norm == ZFS_PROP_UNDEFINED &&
	    (error = zfs_get_zplprop(os, ZFS_PROP_NORMALIZE, &norm)) != 0)
		return (error);
	VERIFY(nvlist_add_uint64(zplprops,
	    zfs_prop_to_name(ZFS_PROP_NORMALIZE), norm) == 0);

	/*
	 * If we're normalizing, names must always be valid UTF-8 strings.
	 */
	if (norm)
		u8 = 1;
	if (u8 == ZFS_PROP_UNDEFINED &&
	    (error = zfs_get_zplprop(os, ZFS_PROP_UTF8ONLY, &u8)) != 0)
		return (error);
	VERIFY(nvlist_add_uint64(zplprops,
	    zfs_prop_to_name(ZFS_PROP_UTF8ONLY), u8) == 0);

	if (sense == ZFS_PROP_UNDEFINED &&
	    (error = zfs_get_zplprop(os, ZFS_PROP_CASE, &sense)) != 0)
		return (error);
	VERIFY(nvlist_add_uint64(zplprops,
	    zfs_prop_to_name(ZFS_PROP_CASE), sense) == 0);

	if (is_ci)
		*is_ci = (sense == ZFS_CASE_INSENSITIVE);

	return (0);
}

static int
zfs_fill_zplprops_root(uint64_t spa_vers, nvlist_t *createprops,
    nvlist_t *zplprops, boolean_t *is_ci)
{
	boolean_t fuids_ok;
	boolean_t sa_ok;
	uint64_t zplver = ZPL_VERSION;
	int error;

	zplver = zfs_zpl_version_map(spa_vers);
	fuids_ok = (zplver >= ZPL_VERSION_FUID);
	sa_ok = (zplver >= ZPL_VERSION_SA);

	error = zfs_fill_zplprops_impl(NULL, zplver, fuids_ok, sa_ok,
	    createprops, zplprops, is_ci);
	return (error);
}

static int
uzfs_ioc_pool_create(zfs_cmd_t *zc)
{
	int error;
	nvlist_t *config, *props = NULL;
	nvlist_t *rootprops = NULL;
	nvlist_t *zplprops = NULL;

	if ((error = get_nvlist(zc->zc_nvlist_conf, zc->zc_nvlist_conf_size,
	                        zc->zc_iflags, &config)))
		return (error);

	if (zc->zc_nvlist_src_size != 0 &&
	    (error = get_nvlist(zc->zc_nvlist_src, zc->zc_nvlist_src_size,
	                        zc->zc_iflags, &props))) {
		nvlist_free(config);
		return (error);
	}

	if (props) {
		nvlist_t *nvl = NULL;
		uint64_t version = SPA_VERSION;

		(void) nvlist_lookup_uint64(props, zpool_prop_to_name(
		                                       ZPOOL_PROP_VERSION),
		                            &version);
		if (!SPA_VERSION_IS_SUPPORTED(version)) {
			error = SET_ERROR(EINVAL);
			goto pool_props_bad;
		}
		(void) nvlist_lookup_nvlist(props, ZPOOL_ROOTFS_PROPS, &nvl);
		if (nvl) {
			error = nvlist_dup(nvl, &rootprops, KM_SLEEP);
			if (error != 0) {
				nvlist_free(config);
				nvlist_free(props);
				return (error);
			}
			(void) nvlist_remove_all(props, ZPOOL_ROOTFS_PROPS);
		}
		VERIFY(nvlist_alloc(&zplprops, NV_UNIQUE_NAME, KM_SLEEP) == 0);
		error =
		    zfs_fill_zplprops_root(version, rootprops, zplprops, NULL);
		if (error != 0)
			goto pool_props_bad;
	}

	error = spa_create(zc->zc_name, config, props, NULL);

	/*
	 * Set the remaining root properties
	 */
	if (!error &&
	    (error = zfs_set_prop_nvlist(zc->zc_name, ZPROP_SRC_LOCAL,
	                                 rootprops, NULL)) != 0)
		(void) spa_destroy(zc->zc_name);

pool_props_bad:
	nvlist_free(rootprops);
	nvlist_free(zplprops);
	nvlist_free(config);
	nvlist_free(props);

	return (error);
}

static int
uzfs_ioc_pool_import(zfs_cmd_t *zc)
{
	nvlist_t *config, *props = NULL;
	uint64_t guid;
	int error;

	if ((error = get_nvlist(zc->zc_nvlist_conf, zc->zc_nvlist_conf_size,
	                        zc->zc_iflags, &config)) != 0)
		return (error);

	if (zc->zc_nvlist_src_size != 0 &&
	    (error = get_nvlist(zc->zc_nvlist_src, zc->zc_nvlist_src_size,
	                        zc->zc_iflags, &props))) {
		nvlist_free(config);
		return (error);
	}

	if (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID, &guid) != 0 ||
	    guid != zc->zc_guid)
		error = SET_ERROR(EINVAL);
	else
		error = spa_import(zc->zc_name, config, props, zc->zc_cookie);

	if (zc->zc_nvlist_dst != 0) {
		int err;

		if ((err = put_nvlist(zc, config)) != 0)
			error = err;
	}

	nvlist_free(config);
	nvlist_free(props);

	return (error);
}

static int
uzfs_ioc_snapshot(const char *poolname, nvlist_t *innvl, nvlist_t *outnvl)
{
	nvlist_t *snaps;
	nvlist_t *props = NULL;
	int error, poollen;
	nvpair_t *pair, *pair2;

	(void) nvlist_lookup_nvlist(innvl, "props", &props);
	if ((error = zfs_check_userprops(poolname, props)) != 0)
		return (error);

	if (!nvlist_empty(props) &&
	    zfs_earlier_version(poolname, SPA_VERSION_SNAP_PROPS))
		return (SET_ERROR(ENOTSUP));

	if (nvlist_lookup_nvlist(innvl, "snaps", &snaps) != 0)
		return (SET_ERROR(EINVAL));
	poollen = strlen(poolname);
	for (pair = nvlist_next_nvpair(snaps, NULL); pair != NULL;
	     pair = nvlist_next_nvpair(snaps, pair)) {
		const char *name = nvpair_name(pair);
		const char *cp = strchr(name, '@');

		/*
		 * The snap name must contain an @, and the part after it must
		 * contain only valid characters.
		 */
		if (cp == NULL ||
		    zfs_component_namecheck(cp + 1, NULL, NULL) != 0)
			return (SET_ERROR(EINVAL));

		/*
		 * The snap must be in the specified pool.
		 */
		if (strncmp(name, poolname, poollen) != 0 ||
		    (name[poollen] != '/' && name[poollen] != '@'))
			return (SET_ERROR(EXDEV));

		/* This must be the only snap of this fs. */
		for (pair2 = nvlist_next_nvpair(snaps, pair); pair2 != NULL;
		     pair2 = nvlist_next_nvpair(snaps, pair2)) {
			if (strncmp(name, nvpair_name(pair2), cp - name + 1) ==
			    0) {
				return (SET_ERROR(EXDEV));
			}
		}
	}

	error = dsl_dataset_snapshot(snaps, props, outnvl);

	return (error);
}

static int
zvol_get_stats(objset_t *os, nvlist_t *nv)
{
	int error;
	dmu_object_info_t *doi;
	uint64_t val;

	error = zap_lookup(os, ZVOL_ZAP_OBJ, "size", 8, 1, &val);
	if (error)
		return (SET_ERROR(error));

	dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_VOLSIZE, val);
	doi = kmem_alloc(sizeof(dmu_object_info_t), KM_SLEEP);
	error = dmu_object_info(os, ZVOL_OBJ, doi);

	if (error == 0) {
		dsl_prop_nvlist_add_uint64(nv, ZFS_PROP_VOLBLOCKSIZE,
		                           doi->doi_data_block_size);
	}

	kmem_free(doi, sizeof(dmu_object_info_t));

	return (SET_ERROR(error));
}

static int
uzfs_ioc_objset_stats_impl(zfs_cmd_t *zc, objset_t *os)
{
	int error = 0;
	nvlist_t *nv;

	dmu_objset_fast_stat(os, &zc->zc_objset_stats);

	if (zc->zc_nvlist_dst != 0 &&
	    (error = dsl_prop_get_all(os, &nv)) == 0) {
		dmu_objset_stats(os, nv);
		/*
		 * NB: zvol_get_stats() will read the objset contents,
		 * which we aren't supposed to do with a
		 * DS_MODE_USER hold, because it could be
		 * inconsistent.  So this is a bit of a workaround...
		 * XXX reading with out owning
		 */
		if (!zc->zc_objset_stats.dds_inconsistent &&
		    dmu_objset_type(os) == DMU_OST_ZVOL) {
			error = zvol_get_stats(os, nv);
			if (error == EIO) {
				nvlist_free(nv);
				return (error);
			}
			VERIFY0(error);
		}
		if (error == 0)
			error = put_nvlist(zc, nv);
		nvlist_free(nv);
	}

	return (error);
}

static int
uzfs_ioc_objset_stats(zfs_cmd_t *zc)
{
	objset_t *os;
	int error;

	error = dmu_objset_hold(zc->zc_name, FTAG, &os);
	if (error == 0) {
		error = uzfs_ioc_objset_stats_impl(zc, os);
		dmu_objset_rele(os, FTAG);
	}

	return (error);
}

static int
uzfs_ioc_snapshot_list_next(zfs_cmd_t *zc)
{
	objset_t *os;
	int error;

	error = dmu_objset_hold(zc->zc_name, FTAG, &os);
	if (error != 0) {
		return (error == ENOENT ? ESRCH : error);
	}

	/*
	 * A dataset name of maximum length cannot have any snapshots,
	 * so exit immediately.
	 */
	if (strlcat(zc->zc_name, "@", sizeof(zc->zc_name)) >=
	    ZFS_MAX_DATASET_NAME_LEN) {
		dmu_objset_rele(os, FTAG);
		return (SET_ERROR(ESRCH));
	}

	error = dmu_snapshot_list_next(os, sizeof(zc->zc_name) -
	                                       strlen(zc->zc_name),
	                               zc->zc_name + strlen(zc->zc_name),
	                               &zc->zc_obj, &zc->zc_cookie, NULL);

	if (error == 0 && !zc->zc_simple) {
		dsl_dataset_t *ds;
		dsl_pool_t *dp = os->os_dsl_dataset->ds_dir->dd_pool;

		error = dsl_dataset_hold_obj(dp, zc->zc_obj, FTAG, &ds);
		if (error == 0) {
			objset_t *ossnap;

			error = dmu_objset_from_ds(ds, &ossnap);
			if (error == 0)
				error = uzfs_ioc_objset_stats_impl(zc, ossnap);
			dsl_dataset_rele(ds, FTAG);
		}
	} else if (error == ENOENT) {
		error = SET_ERROR(ESRCH);
	}

	dmu_objset_rele(os, FTAG);
	/* if we failed, undo the @ that we tacked on to zc_name */
	if (error != 0)
		*strchr(zc->zc_name, '@') = '\0';
	return (error);
}

static int
uzfs_ioc_pool_stats(zfs_cmd_t *zc)
{
	nvlist_t *config;
	int error;
	int ret = 0;

	error = spa_get_stats(zc->zc_name, &config, zc->zc_value,
	                      sizeof(zc->zc_value));

	if (config != NULL) {
		ret = put_nvlist(zc, config);
		nvlist_free(config);

		/*
		 * The config may be present even if 'error' is non-zero.
		 * In this case we return success, and preserve the real errno
		 * in 'zc_cookie'.
		 */
		zc->zc_cookie = error;
	} else {
		ret = error;
	}

	return (ret);
}

static int
uzfs_ioc_pool_tryimport(zfs_cmd_t *zc)
{
	nvlist_t *tryconfig, *config = NULL;
	int error;

	if ((error = get_nvlist(zc->zc_nvlist_conf, zc->zc_nvlist_conf_size,
	                        zc->zc_iflags, &tryconfig)) != 0)
		return (error);

	config = spa_tryimport(tryconfig);

	nvlist_free(tryconfig);

	if (config == NULL)
		return (SET_ERROR(EINVAL));

	error = put_nvlist(zc, config);
	nvlist_free(config);

	return (error);
}

/*
 * Sanity check volume block size.
 */
int
zvol_check_volblocksize(const char *name, uint64_t volblocksize)
{
	/* Record sizes above 128k need the feature to be enabled */
	if (volblocksize > SPA_OLD_MAXBLOCKSIZE) {
		spa_t *spa;
		int error;

		if ((error = spa_open(name, &spa, FTAG)) != 0)
			return (error);

		if (!spa_feature_is_enabled(spa, SPA_FEATURE_LARGE_BLOCKS)) {
			spa_close(spa, FTAG);
			return (SET_ERROR(ENOTSUP));
		}

		/*
		 * We don't allow setting the property above 1MB,
		 * unless the tunable has been changed.
		 */
		if (volblocksize > zfs_max_recordsize)
			return (SET_ERROR(EDOM));

		spa_close(spa, FTAG);
	}

	if (volblocksize < SPA_MINBLOCKSIZE ||
	    volblocksize > SPA_MAXBLOCKSIZE || !ISP2(volblocksize))
		return (SET_ERROR(EDOM));

	return (0);
}

/*
 * Sanity check volume size.
 */
int
zvol_check_volsize(uint64_t volsize, uint64_t blocksize)
{
	if (volsize == 0)
		return (SET_ERROR(EINVAL));

	if (volsize % blocksize != 0)
		return (SET_ERROR(EINVAL));

#ifdef _ILP32
	if (volsize - 1 > SPEC_MAXOFFSET_T)
		return (SET_ERROR(EOVERFLOW));
#endif
	return (0);
}

int
zfs_set_prop_nvlist(const char *dsname, zprop_source_t source, nvlist_t *nvl,
    nvlist_t *errlist)
{
	nvpair_t *pair;
	nvpair_t *propval;
	int rv = 0;
	uint64_t intval;
	char *strval;

	nvlist_t *genericnvl = fnvlist_alloc();
	nvlist_t *retrynvl = fnvlist_alloc();
retry:
	pair = NULL;
	while ((pair = nvlist_next_nvpair(nvl, pair)) != NULL) {
		const char *propname = nvpair_name(pair);
		zfs_prop_t prop = zfs_name_to_prop(propname);
		int err = 0;

		/* decode the property value */
		propval = pair;
		if (nvpair_type(pair) == DATA_TYPE_NVLIST) {
			nvlist_t *attrs;
			attrs = fnvpair_value_nvlist(pair);
			if (nvlist_lookup_nvpair(attrs, ZPROP_VALUE,
			    &propval) != 0)
				err = SET_ERROR(EINVAL);
		}

		/* Validate value type */
		if (err == 0 && source == ZPROP_SRC_INHERITED) {
			/* inherited properties are expected to be booleans */
			if (nvpair_type(propval) != DATA_TYPE_BOOLEAN)
				err = SET_ERROR(EINVAL);
		} else if (err == 0 && prop == ZPROP_INVAL) {
			if (zfs_prop_user(propname)) {
				if (nvpair_type(propval) != DATA_TYPE_STRING)
					err = SET_ERROR(EINVAL);
			} else if (zfs_prop_userquota(propname)) {
				if (nvpair_type(propval) !=
				    DATA_TYPE_UINT64_ARRAY)
					err = SET_ERROR(EINVAL);
			} else {
				err = SET_ERROR(EINVAL);
			}
		} else if (err == 0) {
			if (nvpair_type(propval) == DATA_TYPE_STRING) {
				if (zfs_prop_get_type(prop) != PROP_TYPE_STRING)
					err = SET_ERROR(EINVAL);
			} else if (nvpair_type(propval) == DATA_TYPE_UINT64) {
				const char *unused;

				intval = fnvpair_value_uint64(propval);

				switch (zfs_prop_get_type(prop)) {
				case PROP_TYPE_NUMBER:
					break;
				case PROP_TYPE_STRING:
					err = SET_ERROR(EINVAL);
					break;
				case PROP_TYPE_INDEX:
					if (zfs_prop_index_to_string(prop,
					    intval, &unused) != 0)
						err = SET_ERROR(EINVAL);
					break;
				default:
					cmn_err(CE_PANIC,
					    "unknown property type");
				}
			} else {
				err = SET_ERROR(EINVAL);
			}
		}

#ifdef _FIX_ME
		/* Validate permissions */
		if (err == 0)
			err = zfs_check_settable(dsname, pair, CRED());
#endif
		if (err == 0) {
			if (source == ZPROP_SRC_INHERITED)
				err = -1; /* does not need special handling */
			else
#ifdef _FIX_ME
				err = zfs_prop_set_special(dsname, source, pair);
#else
				err = -1;
#endif
			if (err == -1) {
				/*
				 * For better performance we build up a list of
				 * properties to set in a single transaction.
				 */
				err = nvlist_add_nvpair(genericnvl, pair);
			} else if (err != 0 && nvl != retrynvl) {
				/*
				 * This may be a spurious error caused by
				 * receiving quota and reservation out of order.
				 * Try again in a second pass.
				 */
				err = nvlist_add_nvpair(retrynvl, pair);
			}
		}

		if (err != 0) {
			if (errlist != NULL)
				fnvlist_add_int32(errlist, propname, err);
			rv = err;
		}
	}

	if (nvl != retrynvl && !nvlist_empty(retrynvl)) {
		nvl = retrynvl;
		goto retry;
	}

	if (!nvlist_empty(genericnvl) &&
	    dsl_props_set(dsname, source, genericnvl) != 0) {
		/*
		 * If this fails, we still want to set as many properties as we
		 * can, so try setting them individually.
		 */
		pair = NULL;
		while ((pair = nvlist_next_nvpair(genericnvl, pair)) != NULL) {
			const char *propname = nvpair_name(pair);
			int err = 0;

			propval = pair;
			if (nvpair_type(pair) == DATA_TYPE_NVLIST) {
				nvlist_t *attrs;
				attrs = fnvpair_value_nvlist(pair);
				propval = fnvlist_lookup_nvpair(attrs,
				    ZPROP_VALUE);
			}

			if (nvpair_type(propval) == DATA_TYPE_STRING) {
				strval = fnvpair_value_string(propval);
				err = dsl_prop_set_string(dsname, propname,
				    source, strval);
			} else if (nvpair_type(propval) == DATA_TYPE_BOOLEAN) {
				err = dsl_prop_inherit(dsname, propname,
				    source);
			} else {
				intval = fnvpair_value_uint64(propval);
				err = dsl_prop_set_int(dsname, propname, source,
				    intval);
			}

			if (err != 0) {
				if (errlist != NULL) {
					fnvlist_add_int32(errlist, propname,
					    err);
				}
				rv = err;
			}
		}
	}
	nvlist_free(genericnvl);
	nvlist_free(retrynvl);

	return (rv);
}

static int
uzfs_ioc_create(const char *fsname, nvlist_t *innvl, nvlist_t *outnvl)
{
	int error = 0;
	zfs_creat_t zct = {0};
	nvlist_t *nvprops = NULL;
	void (*cbfunc)(objset_t * os, void *arg, cred_t *cr, dmu_tx_t *tx);
	int32_t type32;
	dmu_objset_type_t type;

	if (nvlist_lookup_int32(innvl, "type", &type32) != 0)
		return (SET_ERROR(EINVAL));
	type = type32;
	(void) nvlist_lookup_nvlist(innvl, "props", &nvprops);

	switch (type) {
	case DMU_OST_ZVOL:
		cbfunc = zvol_create_cb;
		break;

	default:
		cbfunc = NULL;
		break;
	}
	if (strchr(fsname, '@') || strchr(fsname, '%'))
		return (SET_ERROR(EINVAL));

	zct.zct_props = nvprops;

	if (cbfunc == NULL)
		return (SET_ERROR(EINVAL));

	if (type == DMU_OST_ZVOL) {
		uint64_t volsize, volblocksize;

		if (nvprops == NULL)
			return (SET_ERROR(EINVAL));
		if (nvlist_lookup_uint64(nvprops,
		                         zfs_prop_to_name(ZFS_PROP_VOLSIZE),
		                         &volsize) != 0)
			return (SET_ERROR(EINVAL));

		if ((error = nvlist_lookup_uint64(nvprops,
		                                  zfs_prop_to_name(
		                                      ZFS_PROP_VOLBLOCKSIZE),
		                                  &volblocksize)) != 0 &&
		    error != ENOENT)
			return (SET_ERROR(EINVAL));

		if (error != 0)
			volblocksize =
			    zfs_prop_default_numeric(ZFS_PROP_VOLBLOCKSIZE);

		if ((error = zvol_check_volblocksize(fsname, volblocksize)) !=
		        0 ||
		    (error = zvol_check_volsize(volsize, volblocksize)) != 0)
			return (error);
	}

	error = dmu_objset_create(fsname, type, 0, cbfunc, &zct);

	/*
	 * It would be nice to do this atomically.
	 */
	if (error == 0) {
		error = zfs_set_prop_nvlist(fsname, ZPROP_SRC_LOCAL, nvprops,
		                            outnvl);
		if (error != 0) {
			spa_t *spa;
			int error2;

			/*
			 * Volumes will return EBUSY and cannot be destroyed
			 * until all asynchronous minor handling has completed.
			 * Wait for the spa_zvol_taskq to drain then retry.
			 */
			error2 = dsl_destroy_head(fsname);
			while ((error2 == EBUSY) && (type == DMU_OST_ZVOL)) {
				error2 = spa_open(fsname, &spa, FTAG);
				if (error2 == 0) {
					taskq_wait(spa->spa_zvol_taskq);
					spa_close(spa, FTAG);
				}
				error2 = dsl_destroy_head(fsname);
			}
		}
	}
	return (error);
}

static int
uzfs_ioc_pool_configs(zfs_cmd_t *zc)
{
	nvlist_t *configs;
	int error;

	if ((configs = spa_all_configs(&zc->zc_cookie)) == NULL)
		return (SET_ERROR(EEXIST));

	error = put_nvlist(zc, configs);

	nvlist_free(configs);

	return (error);
}

static int
uzfs_ioc_dataset_list_next(zfs_cmd_t *zc)
{
	objset_t *os;
	int error;
	char *p;
	size_t orig_len = strlen(zc->zc_name);

top:
	if ((error = dmu_objset_hold(zc->zc_name, FTAG, &os))) {
		if (error == ENOENT)
			error = SET_ERROR(ESRCH);
		return (error);
	}

	p = strrchr(zc->zc_name, '/');
	if (p == NULL || p[1] != '\0')
		(void) strlcat(zc->zc_name, "/", sizeof(zc->zc_name));
	p = zc->zc_name + strlen(zc->zc_name);

	do {
		error = dmu_dir_list_next(os, sizeof(zc->zc_name) -
		                                  (p - zc->zc_name),
		                          p, NULL, &zc->zc_cookie);
		if (error == ENOENT)
			error = SET_ERROR(ESRCH);
	} while (error == 0 && dataset_name_hidden(zc->zc_name));
	dmu_objset_rele(os, FTAG);

	/*
	 * If it's an internal dataset (ie. with a '$' in its name),
	 * don't try to get stats for it, otherwise we'll return ENOENT.
	 */
	if (error == 0 && strchr(zc->zc_name, '$') == NULL) {
		error = uzfs_ioc_objset_stats(zc); /* fill in the stats */
		if (error == ENOENT) {
			/* We lost a race with destroy, get the next one. */
			zc->zc_name[orig_len] = '\0';
			goto top;
		}
	}
	return (error);
}

static int
uzfs_ioc_get_bookmarks(const char *fsname, nvlist_t *innvl, nvlist_t *outnvl)
{
	return (dsl_get_bookmarks(fsname, innvl, outnvl));
}

static int
uzfs_ioc_pool_get_props(zfs_cmd_t *zc)
{
	spa_t *spa;
	int error;
	nvlist_t *nvp = NULL;

	if ((error = spa_open(zc->zc_name, &spa, FTAG)) != 0) {
		/*
		 * If the pool is faulted, there may be properties we can still
		 * get (such as altroot and cachefile), so attempt to get them
		 * anyway.
		 */
		mutex_enter(&spa_namespace_lock);
		if ((spa = spa_lookup(zc->zc_name)) != NULL)
			error = spa_prop_get(spa, &nvp);
		mutex_exit(&spa_namespace_lock);
	} else {
		error = spa_prop_get(spa, &nvp);
		spa_close(spa, FTAG);
	}

	if (error == 0 && zc->zc_nvlist_dst != 0)
		error = put_nvlist(zc, nvp);
	else
		error = SET_ERROR(EFAULT);

	nvlist_free(nvp);
	return (error);
}

/*
 * Write out a history event.
 */
int
spa_history_log(spa_t *spa, const char *msg)
{
	int err;
	nvlist_t *nvl = fnvlist_alloc();

	fnvlist_add_string(nvl, ZPOOL_HIST_CMD, msg);
	err = spa_history_log_nvl(spa, nvl);
	fnvlist_free(nvl);
	return (err);
}

static char *
history_str_get(zfs_cmd_t *zc)
{
	char *buf;

	if (zc->zc_history == 0)
		return (NULL);

	buf = (char *) zc->zc_history;

	return (buf);
}

static void
zfs_log_history(zfs_cmd_t *zc)
{
	spa_t *spa;
	char *buf;

	if ((buf = history_str_get(zc)) == NULL)
		return;

	if (spa_open(zc->zc_name, &spa, FTAG) == 0) {
		if (spa_version(spa) >= SPA_VERSION_ZPOOL_HISTORY)
			(void) spa_history_log(spa, buf);
		spa_close(spa, FTAG);
	}
}

static int
uzfs_ioc_pool_export(zfs_cmd_t *zc)
{
	int error;
	boolean_t force = (boolean_t) zc->zc_cookie;
	boolean_t hardforce = (boolean_t) zc->zc_guid;
	zfs_log_history(zc);
	error = spa_export(zc->zc_name, NULL, force, hardforce);

	return (error);
}

static int
uzfs_ioc_pool_get_history(zfs_cmd_t *zc)
{
	spa_t *spa;
	char *hist_buf;
	uint64_t size;
	int error;

	if ((size = zc->zc_history_len) == 0)
		return (SET_ERROR(EINVAL));

	if ((error = spa_open(zc->zc_name, &spa, FTAG)) != 0)
		return (error);

	if (spa_version(spa) < SPA_VERSION_ZPOOL_HISTORY) {
		spa_close(spa, FTAG);
		return (SET_ERROR(ENOTSUP));
	}

	hist_buf = (char *) zc->zc_history;
	error = spa_history_get(spa, &zc->zc_history_offset,
	                        &zc->zc_history_len, hist_buf);

	spa_close(spa, FTAG);
	return (error);
}

static int
uzfs_ioc_log_history(const char *poolname, nvlist_t *innvl, nvlist_t *outnvl)
{
	char *message;
	spa_t *spa;
	int error;

	if (poolname == NULL)
		return (SET_ERROR(EINVAL));
	error = spa_open(poolname, &spa, FTAG);
	if (error != 0)
		return (error);

	if (nvlist_lookup_string(innvl, "message", &message) != 0) {
		spa_close(spa, FTAG);
		return (SET_ERROR(EINVAL));
	}

	if (spa_version(spa) < SPA_VERSION_ZPOOL_HISTORY) {
		spa_close(spa, FTAG);
		return (SET_ERROR(ENOTSUP));
	}

	error = spa_history_log(spa, message);
	spa_close(spa, FTAG);
	return (error);
}

static int
uzfs_ioc_pool_destroy(zfs_cmd_t *zc)
{
	int error;
	zfs_log_history(zc);
	error = spa_destroy(zc->zc_name);

	return (error);
}

static int
uzfs_ioc_destroy_snaps(const char *poolname, nvlist_t *innvl, nvlist_t *outnvl)
{
	nvlist_t *snaps;
	boolean_t defer;

	if (nvlist_lookup_nvlist(innvl, "snaps", &snaps) != 0)
		return (SET_ERROR(EINVAL));
	defer = nvlist_exists(innvl, "defer");

	return (dsl_destroy_snapshots_nvl(snaps, defer, outnvl));
}

static int
uzfs_ioc_destroy(zfs_cmd_t *zc)
{
	int err;

	if (strchr(zc->zc_name, '@')) {
		err = dsl_destroy_snapshot(zc->zc_name, zc->zc_defer_destroy);
	} else {
		err = dsl_destroy_head(zc->zc_name);
		if (err == EEXIST) {
			/*
			 * It is possible that the given DS may have
			 * hidden child (%recv) datasets - "leftovers"
			 * resulting from the previously interrupted
			 * 'zfs receive'.
			 *
			 * 6 extra bytes for /%recv
			 */
			char namebuf[ZFS_MAX_DATASET_NAME_LEN + 6];

			if (snprintf(namebuf, sizeof (namebuf), "%s/%s",
			    zc->zc_name, recv_clone_name) >=
			    sizeof (namebuf))
				return (SET_ERROR(EINVAL));

			/*
			 * Try to remove the hidden child (%recv) and after
			 * that try to remove the target dataset.
			 * If the hidden child (%recv) does not exist
			 * the original error (EEXIST) will be returned
			 */
			err = dsl_destroy_head(namebuf);
			if (err == 0)
				err = dsl_destroy_head(zc->zc_name);
			else if (err == ENOENT)
				err = EEXIST;
		}
	}

	return (err);
}

static int
uzfs_ioc_pool_set_props(zfs_cmd_t *zc)
{
	nvlist_t *props;
	spa_t *spa;
	int error;
	nvpair_t *pair;

	if ((error = get_nvlist(zc->zc_nvlist_src, zc->zc_nvlist_src_size,
	    zc->zc_iflags, &props)))
		return (error);

	/*
	 * If the only property is the configfile, then just do a spa_lookup()
	 * to handle the faulted case.
	 */
	pair = nvlist_next_nvpair(props, NULL);
	if (pair != NULL && strcmp(nvpair_name(pair),
	    zpool_prop_to_name(ZPOOL_PROP_CACHEFILE)) == 0 &&
	    nvlist_next_nvpair(props, pair) == NULL) {
		mutex_enter(&spa_namespace_lock);
		if ((spa = spa_lookup(zc->zc_name)) != NULL) {
			spa_configfile_set(spa, props, B_FALSE);
			spa_config_sync(spa, B_FALSE, B_TRUE);
		}
		mutex_exit(&spa_namespace_lock);
		if (spa != NULL) {
			nvlist_free(props);
			return (0);
		}
	}

	if ((error = spa_open(zc->zc_name, &spa, FTAG)) != 0) {
		nvlist_free(props);
		return (error);
	}

	error = spa_prop_set(spa, props);

	nvlist_free(props);
	spa_close(spa, FTAG);

	return (error);
}

static void
props_skip(nvlist_t *props, nvlist_t *skipped, nvlist_t **newprops)
{
	nvpair_t *pair;

	VERIFY(nvlist_alloc(newprops, NV_UNIQUE_NAME, KM_SLEEP) == 0);

	pair = NULL;
	while ((pair = nvlist_next_nvpair(props, pair)) != NULL) {
		if (nvlist_exists(skipped, nvpair_name(pair)))
			continue;

		VERIFY(nvlist_add_nvpair(*newprops, pair) == 0);
	}
}

static int
clear_received_props(const char *dsname, nvlist_t *props,
    nvlist_t *skipped)
{
	int err = 0;
	nvlist_t *cleared_props = NULL;
	props_skip(props, skipped, &cleared_props);
	if (!nvlist_empty(cleared_props)) {
		/*
		 * Acts on local properties until the dataset has received
		 * properties at least once on or after SPA_VERSION_RECVD_PROPS.
		 */
		zprop_source_t flags = (ZPROP_SRC_NONE |
		    (dsl_prop_get_hasrecvd(dsname) ? ZPROP_SRC_RECEIVED : 0));
		err = zfs_set_prop_nvlist(dsname, flags, cleared_props, NULL);
	}
	nvlist_free(cleared_props);
	return (err);
}

static int
uzfs_ioc_set_prop(zfs_cmd_t *zc)
{
	nvlist_t *nvl;
	boolean_t received = zc->zc_cookie;
	zprop_source_t source = (received ? ZPROP_SRC_RECEIVED :
	    ZPROP_SRC_LOCAL);
	nvlist_t *errors;
	int error;

	if ((error = get_nvlist(zc->zc_nvlist_src, zc->zc_nvlist_src_size,
	    zc->zc_iflags, &nvl)) != 0)
		return (error);

	if (received) {
		nvlist_t *origprops;

		if (dsl_prop_get_received(zc->zc_name, &origprops) == 0) {
			(void) clear_received_props(zc->zc_name,
			    origprops, nvl);
			nvlist_free(origprops);
		}

		error = dsl_prop_set_hasrecvd(zc->zc_name);
	}

	errors = fnvlist_alloc();
	if (error == 0)
		error = zfs_set_prop_nvlist(zc->zc_name, source, nvl, errors);

	if (zc->zc_nvlist_dst != 0 && errors != NULL) {
		(void) put_nvlist(zc, errors);
	}

	nvlist_free(errors);
	nvlist_free(nvl);
	return (error);
}

int
uzfs_ioctl(int fd, unsigned long request, zfs_cmd_t *zc)
{
#ifndef _UZFS
	return ioctl(fd, request, zc);
#else
	if (uzfs_send_ioctl(fd, request, zc)) {
		fprintf(stderr, "ioctl send failed\n");
		exit(1);
	}

	int ret = uzfs_recv_response(fd, zc);

	int err = (ret < 0 ? errno : ret);

	if (err)
		return SET_ERR(err);

	return 0;
#endif
}

int
uzfs_handle_ioctl(const char *pool, uint64_t request, zfs_cmd_t *zc)
{
	int err;
	nvlist_t *innvl = NULL;
	if (zc->zc_nvlist_src_size > MAX_NVLIST_SRC_SIZE) {
		/*
		 * Make sure the user doesn't pass in an insane value for
		 * zc_nvlist_src_size.  We have to check, since we will end
		 * up allocating that much memory inside of get_nvlist().  This
		 * prevents a nefarious user from allocating tons of kernel
		 * memory.
		 *
		 * Also, we return EINVAL instead of ENOMEM here.  The reason
		 * being that returning ENOMEM from an ioctl() has a special
		 * connotation; that the user's size value is too small and
		 * needs to be expanded to hold the nvlist.  See
		 * zcmd_expand_dst_nvlist() for details.
		 */
		return (EINVAL); /* User's size too big */
	} else if (zc->zc_nvlist_src_size != 0) {
		err = get_nvlist(zc->zc_nvlist_src, zc->zc_nvlist_src_size, 0,
		                 &innvl);
		if (err != 0)
			return err;
	}

	err = ENOTSUP;
	switch (request) {
	case ZFS_IOC_OBJSET_STATS:
		return (uzfs_ioc_objset_stats(zc));
	case ZFS_IOC_POOL_CREATE:
		return (uzfs_ioc_pool_create(zc));
	case ZFS_IOC_POOL_IMPORT:
		return (uzfs_ioc_pool_import(zc));
	case ZFS_IOC_POOL_STATS:
		return (uzfs_ioc_pool_stats(zc));
	case ZFS_IOC_POOL_TRYIMPORT:
		return (uzfs_ioc_pool_tryimport(zc));
	case ZFS_IOC_CREATE: {
		nvlist_t *outnvl = fnvlist_alloc();

		err = uzfs_ioc_create(zc->zc_name, innvl, outnvl);
		if (!nvlist_empty(outnvl) || zc->zc_nvlist_dst_size != 0)
			err = put_nvlist(zc, outnvl);
		nvlist_free(outnvl);

		return (err);
	}
	case ZFS_IOC_POOL_CONFIGS:
		return (uzfs_ioc_pool_configs(zc));
	case ZFS_IOC_DATASET_LIST_NEXT:
		return (uzfs_ioc_dataset_list_next(zc));
	case ZFS_IOC_GET_BOOKMARKS: {
		nvlist_t *outnvl = fnvlist_alloc();
		err = uzfs_ioc_get_bookmarks(zc->zc_name, innvl, outnvl);
		if (!nvlist_empty(outnvl) || zc->zc_nvlist_dst_size != 0)
			err = put_nvlist(zc, outnvl);
		nvlist_free(outnvl);

		return (err);
	}
	case ZFS_IOC_POOL_GET_PROPS:
		return (uzfs_ioc_pool_get_props(zc));
	case ZFS_IOC_POOL_EXPORT:
		return (uzfs_ioc_pool_export(zc));
	case ZFS_IOC_POOL_GET_HISTORY:
		return (uzfs_ioc_pool_get_history(zc));
	case ZFS_IOC_LOG_HISTORY: {
		nvlist_t *outnvl = fnvlist_alloc();

		err = uzfs_ioc_log_history(pool, innvl, outnvl);
		if (!nvlist_empty(outnvl) || zc->zc_nvlist_dst_size != 0)
			err = put_nvlist(zc, outnvl);

		nvlist_free(outnvl);
		return (err);
	}
	case ZFS_IOC_SNAPSHOT: {
		nvlist_t *outnvl = fnvlist_alloc();

		err = uzfs_ioc_snapshot(zc->zc_name, innvl, outnvl);
		if (!nvlist_empty(outnvl) || zc->zc_nvlist_dst_size != 0)
			err = put_nvlist(zc, outnvl);

		nvlist_free(outnvl);
		return (err);
	}
	case ZFS_IOC_SNAPSHOT_LIST_NEXT:
		return (uzfs_ioc_snapshot_list_next(zc));
	case ZFS_IOC_POOL_DESTROY:
		return (uzfs_ioc_pool_destroy(zc));
	case ZFS_IOC_DESTROY_SNAPS: {
		nvlist_t *outnvl = fnvlist_alloc();

		err = uzfs_ioc_destroy_snaps(zc->zc_name, innvl, outnvl);
		if (!nvlist_empty(outnvl) || zc->zc_nvlist_dst_size != 0)
			err = put_nvlist(zc, outnvl);

		nvlist_free(outnvl);
		return (err);
	}
	case ZFS_IOC_DESTROY:
		return (uzfs_ioc_destroy(zc));
	case ZFS_IOC_POOL_SET_PROPS:
		return (uzfs_ioc_pool_set_props(zc));
	case ZFS_IOC_SET_PROP:
		return (uzfs_ioc_set_prop(zc));
	}
	return err;
}
