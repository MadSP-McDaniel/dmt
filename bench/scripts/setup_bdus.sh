#!/bin/bash

set -x -e

sudo() {
    [[ $EUID = 0 ]] || set -- command sudo "$@"
    "$@"
}

d=~/bdus
rm -rf $d

git clone https://github.com/albertofaria/bdus $d
cp $DMT_HOME/bench/scripts/disable_daemonize.patch $d
pushd $d
git checkout 4f4e7e26fe02c91c621502441af56ab844cbd3c7
git apply disable_daemonize.patch
if [ "$1" -eq 0 ]; then
    sudo make install
else
    sudo make install-libbdus
    sudo make install-cmdbdus
fi
# To install kmod, libbdus and cmdbdus:
# sudo make install
# To just install libbdus:
# sudo make install-lib
# To just install cmdbdus:
# sudo make install-cmdbdus
popd
