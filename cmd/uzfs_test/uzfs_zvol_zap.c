#include <sys/types.h>
#include <sys/spa.h>
#include <uzfs_mgmt.h>
#include <uzfs_zap.h>
#include <uzfs_test.h>

/*
 * populate_string will fill buf with [A-Z] characters
 */
static void
populate_string(char *buf, uint64_t size)
{
	int i = 0;
	int idx;

	for (i = 0; i < size; i++) {
		idx = uzfs_random('Z' - 'A');
		idx += 'A';
		buf[i] = (char)idx;
	}
	buf[size - 1] = '\0';
}

static void
destroy_zap_entries(uzfs_zap_kv_t **kv_array, uint64_t zap_count)
{
	int i = 0;
	uzfs_zap_kv_t *kv;

	for (i = 0; i < zap_count; i++) {
		kv = kv_array[i];
		free(kv->key);
		free(kv->value);
		free(kv);
		kv = NULL;
	}
}

static void
fill_up_zap_entries(uzfs_zap_kv_t **array, uint64_t n)
{
	int i = 0;
	uzfs_zap_kv_t *zap;
	uint64_t key_len, value_len;

	for (i = 0; i < n; i++, zap = NULL) {
		zap = malloc(sizeof (uzfs_zap_kv_t));
		key_len = uzfs_random(32);
		value_len = uzfs_random(32);

		key_len = (key_len < 8) ? 8 : key_len;
		value_len = (value_len < 8) ? 8 : value_len;

		zap->key = malloc(key_len);
		zap->value = malloc(value_len);
		zap->size = value_len;

		populate_string(zap->key, key_len);
		populate_string(zap->value, value_len);
		array[i] = zap;
	}
}

static void
update_zap_entries(uzfs_zap_kv_t **array, uint64_t n)
{
	int i = 0;
	uzfs_zap_kv_t *zap;

	for (i = 0; i < n; i++) {
		zap = array[i];
		populate_string(zap->value, zap->size);
	}

}

void
verify_zap_entries(void *zvol, uzfs_zap_kv_t **key_array, uint64_t count)
{
	uzfs_zap_kv_t *kv;
	char *value, *temp_value;
	int i = 0, err;
	uzfs_zap_kv_t dummy_key;

	for (i = 0; i < count; i++) {
		kv = key_array[i];
		temp_value = kv->value;
		kv->value = calloc(1, kv->size);
		uzfs_read_zap_entry(zvol, kv);
		VERIFY0(strncmp(kv->value, temp_value, kv->size));
		free(temp_value);
		value = NULL;
	}

	dummy_key.key = malloc(20);
	dummy_key.value = malloc(20);
	dummy_key.size = 20;

	dummy_key.key = "DUMMY";
	err = uzfs_read_zap_entry(zvol, &dummy_key);
	if (err == 0) {
		printf("read zap should fail..\n");
		exit(1);
	}
}

void
uzfs_zvol_zap_operation(void *arg)
{
	uzfs_test_info_t *test_info = (uzfs_test_info_t *)arg;
	int i = 0;
	hrtime_t end, now;
	void *spa, *zvol;
	uzfs_zap_kv_t **kv_array;
	int zap_count;
	uint64_t txg1, txg2, txg3, txg4;
	struct timespec ts;
	int err1, err2;
	txg_update_interval_time = hz;

	setup_unit_test();
	unit_test_create_pool_ds();
	open_pool(&spa);
	open_ds(spa, &zvol);

	while (i++ < test_iterations) {
		zap_count = uzfs_random(16) + 1;

		kv_array = malloc(zap_count * sizeof (*kv_array));
		fill_up_zap_entries(kv_array, zap_count);

		/* update key/value pair in ZAP entries */
		VERIFY0(uzfs_update_zap_entries(zvol,
		    (const uzfs_zap_kv_t **) kv_array, zap_count));

		verify_zap_entries(zvol, kv_array, zap_count);

		/* update value against existing ZAP key entries */
		update_zap_entries(kv_array, zap_count);

		VERIFY0(uzfs_update_zap_entries(zvol,
		    (const uzfs_zap_kv_t **) kv_array, zap_count));

		verify_zap_entries(zvol, kv_array, zap_count);

		destroy_zap_entries(kv_array, zap_count);
		free(kv_array);
		kv_array = NULL;

		printf("%s pass:%d\n", test_info->name, i);
	}

	now = gethrtime();
	end = now + (hrtime_t)(total_time_in_sec * (hrtime_t)(NANOSEC));

	zfs_txg_timeout = 1;
	ts.tv_sec = 3;
	ts.tv_nsec = 0;

	while (1) {
		err1 = uzfs_read_last_iter_txg(spa, &txg1);
		if ((err1 != 0) && (err1 != 2)) {
			printf("error in reading last iter txg..\n");
			exit(1);
		}

		txg2 = spa_last_synced_txg(spa);

		nanosleep(&ts, NULL);

		err2 = uzfs_read_last_iter_txg(spa, &txg3);
		if ((err2 != 0) && (err2 != 2)) {
			printf("error in reading last iter txg..\n");
			exit(1);
		}

		txg4 = spa_last_synced_txg(spa);

		if (txg2 != txg4)
			if ((txg1 == txg3) && ((err1 == 0) || (err2 == 0))) {
				printf("doesn't seem to be updating txg..\n");
				exit(1);
			}

		now = gethrtime();
		if (now > end)
			break;
	}

	uzfs_close_dataset(zvol);
	uzfs_close_pool(spa);
}
