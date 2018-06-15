#!/bin/sh

set -o errexit

# This relies on fact that /tmp is defined as k8s emptyDir volume
echo '/tmp/core.%h.%e.%t' > /proc/sys/kernel/core_pattern
ulimit -c unlimited

exec /usr/local/bin/zrepl
