#!/bin/sh

set -o errexit
trap 'call_exit $LINE_NO' EXIT

call_exit()
{
echo "at call_exit.."     
echo  "exit code:" $?
echo "reference: "  $0 
exit 1
}


if [ -z "$LOGLEVEL" ]; then
	LOGLEVEL=info
fi

# Disabling coredumps by default in the shell where zrepl runs
if [ -z "$ENABLE_COREDUMP" ]; then
	echo "Disabling dumping core"
	ulimit -c 0
else
	echo "Enabling coredumps"
	ulimit -c unlimited
	cd /var/openebs/sparse || exit 1
fi
# ulimit being shell specific, ulimit -c in container shows as unlimited


echo "sleeping for 2 sec"
sleep 2
ARCH=$(uname -m)
export LD_PRELOAD=/usr/lib/${ARCH}-linux-gnu/libjemalloc.so
exec /usr/local/bin/zrepl -l $LOGLEVEL
