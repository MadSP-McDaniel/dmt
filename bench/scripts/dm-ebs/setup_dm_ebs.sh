#!/bin/bash

set -e -x

sudo() {
    [[ $EUID = 0 ]] || set -- command sudo "$@"
    "$@"
}

# Note: if running this in a Docker container, the container must
# be run with the --privileged flag (or the appropriate capabilities).
if [ "$EUID" -ne 0 ]; then
    sudo rmmod dm_ebs_target dm_bufio || true
else
    rmmod dm_ebs_target dm_bufio || true
fi

d=$DMT_HOME/bench/scripts/dm-ebs
pushd $d
make clean && make

# For Debian 11 image with manually installed 6.1 kernel
# sudo insmod /lib/modules/6.1.0-0.deb11.11-amd64/kernel/drivers/md/dm-bufio.ko
# sudo insmod /lib/modules/5.15.0-89-generic/kernel/drivers/md/dm-bufio.ko
# sudo insmod /lib/modules/5.10.0-26-amd64/kernel/drivers/md/dm-bufio.ko
# For AWS Ubuntu 22.04 image
# sudo insmod /lib/modules/6.2.0-1012-aws/kernel/drivers/md/dm-bufio.ko
# For AWS Ubuntu 20.04 image
# sudo insmod /lib/modules/5.15.0-1053-aws/kernel/drivers/md/dm-bufio.ko
# sudo insmod /lib/modules/5.15.0-1036-aws/kernel/drivers/md/dm-bufio.ko
kernel_version="$(uname -r)"
if [ "$EUID" -ne 0 ]; then
    sudo insmod /lib/modules/$kernel_version/kernel/drivers/md/dm-bufio.ko
else
    insmod /lib/modules/$kernel_version/kernel/drivers/md/dm-bufio.ko
fi

if [[ -z "$(lsmod | grep dm_bufio)" ]]; then
    echo "dm_bufio module not loaded"
    exit -1
fi

if [ "$EUID" -ne 0 ]; then
    sudo insmod dm_ebs_target.ko
else
    insmod dm_ebs_target.ko
fi
if [[ -z "$(lsmod | grep dm_ebs_target)" ]]; then
    echo "dm_ebs_target module not loaded"
    exit -1
fi

popd
