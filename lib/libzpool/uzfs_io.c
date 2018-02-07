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

/* Writes data 'buf' to dataset 'zv' at 'offset' for 'len' */
int
uzfs_write_data(zvol_state_t *zv, char *buf, uint64_t offset, uint64_t len)
{
	uint64_t bytes = 0, sync = zv->zv_sync;
	uint64_t volsize = zv->zv_volsize;
	uint64_t blocksize = zv->zv_volblocksize;
	uint64_t end = len + offset;
	uint64_t wrote = 0;
	objset_t *os = zv->zv_objset;
	rl_t *rl;
	int ret = 0, error;
	uint64_t r_offset, r_len;

	/*
	 * Taking lock on entire block at ZFS layer.
	 * Handling the case where readlen is smaller than blocksize.
	 * This can also be avoided later for better performance.
	 */
	r_offset = (offset / blocksize) * blocksize;
	r_len = ((len + blocksize - 1) / blocksize) * blocksize;

	rl = zfs_range_lock(&zv->zv_range_lock, r_offset, r_len, RL_WRITER);
	while (offset < end && offset < volsize) {
		bytes = (len < blocksize) ? len : blocksize;

		if (bytes > (volsize - offset))
			bytes = volsize - offset;

		dmu_tx_t *tx = dmu_tx_create(os);
		dmu_tx_hold_write(tx, ZVOL_OBJ, offset, bytes);
		error = dmu_tx_assign(tx, TXG_WAIT);
		if (error) {
			dmu_tx_abort(tx);
			ret = UZFS_IO_TX_ASSIGN_FAIL;
			goto end;
		}
		dmu_write(os, ZVOL_OBJ, offset, bytes, buf + wrote, tx);
		zvol_log_write(zv, tx, offset, bytes, sync);

		dmu_tx_commit(tx);

		if (sync)
			zil_commit(zv->zv_zilog, ZVOL_OBJ);
		offset += bytes;
		wrote += bytes;
		len -= bytes;
	}
end:
	zfs_range_unlock(rl);
	return (ret);
}

/* Reads data from volume 'zv', and fills up memory at buf */
int
uzfs_read_data(zvol_state_t *zv, char *buf, uint64_t offset, uint64_t len)
{
	uint64_t bytes = 0;
	int error = 0;
	uint64_t volsize = zv->zv_volsize;
	uint64_t blocksize = zv->zv_volblocksize;
	uint64_t end = len + offset;
	uint64_t read = 0;
	objset_t *os = zv->zv_objset;
	rl_t *rl;
	int ret = 0;
	uint64_t r_offset, r_len;


	r_offset = (offset / blocksize) * blocksize;
	r_len = ((len + blocksize - 1) / blocksize) * blocksize;

	rl = zfs_range_lock(&zv->zv_range_lock, r_offset, r_len, RL_READER);
	while ((offset < end) && (offset < volsize)) {
		bytes = (len < blocksize) ? len : blocksize;

		if (bytes > (volsize - offset))
			bytes = volsize - offset;

		error = dmu_read(os, ZVOL_OBJ, offset, bytes, buf + read, 0);
		if (error) {
			ret = UZFS_IO_READ_FAIL;
			goto end;
		}
		offset += bytes;
		read += bytes;
		len -= bytes;
	}
end:
	zfs_range_unlock(rl);
	return (0);
}

void
uzfs_flush_data(zvol_state_t *zv)
{
	zil_commit(zv->zv_zilog, ZVOL_OBJ);
}
