#!/bin/bash
for i in {1..10}
do
	sudo $PWD/$1/uzfs_test_sync -s -S -w > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $PWD/$1/uzfs_test_sync -v `cat $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done
for i in {1..10}
do
	sudo $PWD/$1/uzfs_test_sync -S -w > $PWD/$1/uzfs_sync_data
	if [ $? != 0 ]; then
		exit 1;
	fi

	sudo $PWD/$1/uzfs_test_sync -v `cat $PWD/$1/uzfs_sync_data`
	if [ $? != 0 ]; then
		exit 1;
	fi
done

