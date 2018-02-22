#!/bin/bash
for i in {1..10}
do
	sudo $UZFS_TEST -S -r -w > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -r -V `awk '{print $1}' $PWD/$1/uzfs_sync_data` -m `awk '{print $2}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
for i in {1..10}
do
	sudo $UZFS_TEST -S -l -r -w > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -r -V `awk '{print $1}' $PWD/$1/uzfs_sync_data` -m `awk '{print $2}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
for i in {1..10}
do
	sudo $UZFS_TEST -S -s -r -w > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -r -V `awk '{print $1}' $PWD/$1/uzfs_sync_data` -m `awk '{print $2}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
for i in {1..10}
do
	sudo $UZFS_TEST -S -l -s -r -w > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -r -V `awk '{print $1}' $PWD/$1/uzfs_sync_data` -m `awk '{print $2}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done

for i in {1..10}
do
	sudo $UZFS_TEST -S -i 8192 -b 65536 -r -w > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -i 8192 -b 65536 -r -V `awk '{print $1}' $PWD/$1/uzfs_sync_data` -m `awk '{print $2}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
for i in {1..10}
do
	sudo $UZFS_TEST -S -i 8192 -b 65536 -l -r -w > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -i 8192 -b 65536 -r -V `awk '{print $1}' $PWD/$1/uzfs_sync_data` -m `awk '{print $2}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
for i in {1..10}
do
	sudo $UZFS_TEST -S -s -i 8192 -b 65536 -r -w > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -i 8192 -b 65536 -r -V `awk '{print $1}' $PWD/$1/uzfs_sync_data` -m `awk '{print $2}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
for i in {1..10}
do
	sudo $UZFS_TEST -S -i 8192 -b 65536 -l -s -r -w > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $UZFS_TEST -i 8192 -b 65536 -r -V `awk '{print $1}' $PWD/$1/uzfs_sync_data` -m `awk '{print $2}' $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
exit 0
