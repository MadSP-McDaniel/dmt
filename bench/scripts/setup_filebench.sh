#!/bin/bash

set -x -e

sudo() {
    [[ $EUID = 0 ]] || set -- command sudo "$@"
    "$@"
}

d=~/filebench
rm -rf $d

git clone https://github.com/filebench/filebench.git $d
cp $DMT_HOME/bench/scripts/fix_stats.patch $d
pushd $d
git apply fix_stats.patch

libtoolize
aclocal
autoheader
automake --add-missing
autoconf

./configure
make
if [ "$EUID" -ne 0 ]; then
    sudo make install
else
    make install
fi
popd
