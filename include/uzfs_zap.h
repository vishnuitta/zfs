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

#ifndef	_UZFS_ZAP_H
#define	_UZFS_ZAP_H

typedef struct {
	char *key; 	/* zap key to update */
	char *value;	/* value to update against zap key */
	size_t size;	/* size of value */
} uzfs_zap_kv_t;

/*
 * Here, allocation/freeing of kv_array needs to be handled by caller function.
 */
int uzfs_update_zap_entry(void *zv, const uzfs_zap_kv_t **kv_array, uint64_t n);
int uzfs_read_zap_entry(void *zv, uzfs_zap_kv_t *entry);

#endif
