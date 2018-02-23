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
#include <uzfs_zap.h>

/*
 * update/add key-value entry in zvol zap object
 */
int
uzfs_update_zap_entry(void *zvol, const uzfs_zap_kv_t **array,
    uint64_t count)
{
	zvol_state_t *zv = (zvol_state_t *)zvol;
	objset_t *os = zv->zv_objset;
	dmu_tx_t *tx;
	const uzfs_zap_kv_t *kv;
	int err;
	int i = 0;

	tx = dmu_tx_create(os);
	dmu_tx_hold_zap(tx, ZVOL_ZAP_OBJ, TRUE, NULL);

	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err) {
		dmu_tx_abort(tx);
		return (SET_ERROR(err));
	}

	for (i = 0; i < count; i++) {
		kv = array[i];
		VERIFY0(zap_update(os, ZVOL_ZAP_OBJ, kv->key, 1, kv->size,
		    kv->value, tx));
	}

	dmu_tx_commit(tx);

	return (0);
}

/*
 * fetch value stored in zap object of zvol by key
 */
int
uzfs_read_zap_entry(void *zvol, uzfs_zap_kv_t *entry)
{
	zvol_state_t *zv = (zvol_state_t *)zvol;
	objset_t *os = zv->zv_objset;
	int err;

	err = zap_lookup(os, ZVOL_ZAP_OBJ, entry->key, 1, entry->size,
	    entry->value);
	if (err)
		return (SET_ERROR(err));

	return (0);
}
