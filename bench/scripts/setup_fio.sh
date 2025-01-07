#!/bin/bash

set -x -e

sudo() {
    [[ $EUID = 0 ]] || set -- command sudo "$@"
    "$@"
}

d=~/fio
rm -rf $d

git clone https://github.com/axboe/fio.git $d
pushd $d

git checkout fio-3.36
sudo make clean || true
make clean || true

./configure
make -j8
sudo make install
popd
