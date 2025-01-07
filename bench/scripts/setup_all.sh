#!/bin/bash

# This script is mainly to speed up environment setup when using AWS/CloudLab.

set -x -e

if [ $1 -eq -1 ]; then
    sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"
elif [ $1 -eq 0 ]; then
    sudo apt update && sudo apt install -y zsh linux-image-unsigned-5.15.0-1036-aws/focal-updates
    sudo timedatectl set-timezone America/Chicago
    echo "export BDUS_HOME=~/bdus" >>~/.zshrc
    echo "export DMT_HOME=~/repos/dmt" >>~/.zshrc
    echo "export PATH=~/.local/bin:$PATH" >>~/.zshrc
elif [ $1 -eq 1 ]; then
    sudo apt update && sudo apt install -y linux-headers-$(uname -r) \
        build-essential libgcrypt-dev pkg-config gdb pip nano htop \
        valgrind python-is-python3 make kmod g++ apt-utils autotools-dev screen \
        git libaio1 libaio-dev cgroup-tools stress libsnappy-dev libgflags-dev \
        cryptsetup autotools-dev autoconf libtool zlib1g-dev libjpeg-dev \
        python3-pip bison flex iotop python3.9

    # Setup cgroup
    sudo cgcreate -g memory:/dmt && sudo cgset -r memory.limit_in_bytes=32G dmt

    $DMT_HOME/bench/scripts/setup_fio.sh

    pip3 install pandas numpy scipy seaborn matplotlib fio-plot
    sudo su -c 'pip3 install numpy scipy seaborn matplotlib fio-plot'

    $DMT_HOME/bench/scripts/setup_filebench.sh
    echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

    $DMT_HOME/bench/scripts/setup_bdus.sh 0

    $DMT_HOME/bench/scripts/dm-ebs/setup_dm_ebs.sh
else
    # Setup dmt top-level disks
    sudo dmsetup create data_dev --table '0 2147483648 linear /dev/nvme1n1 0'
    sudo dmsetup create metadata_dev --table '0 268435456 linear /dev/nvme1n1 2147483648'

    # Setup two extra partitions for dmt scratch space - one for bench
    # output (bench/o) and one for dmt binaries (bcc and rocksdb).
    # sudo dmsetup create dmt_output_dev --table '0 268435456 linear /dev/nvme0n1p4 0'
    # sudo mkfs.ext4 /dev/mapper/dmt_output_dev && mkdir -p ~/repos/dmt/bench/o
    # sudo mount /dev/mapper/dmt_output_dev ~/repos/dmt/bench/o && sudo chown -R $USER ~/repos/dmt/bench/o

    # sudo dmsetup create dmt_bin_dev --table '0 268435456 linear /dev/nvme0n1p4 268435456'
    # sudo mkfs.ext4 /dev/mapper/dmt_bin_dev && sudo mkdir -p /mnt/dmt_bin
    # sudo mount /dev/mapper/dmt_bin_dev /mnt/dmt_bin && sudo chown -R $USER /mnt/dmt_bin

    # # Setup bcc
    # sudo rm -rf /usr/lib/python3/dist-packages/bcc
    # sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
    #     libllvm12 llvm-12-dev libclang-12-dev python zlib1g-dev libelf-dev libfl-dev python3-setuptools \
    #     liblzma-dev arping iperf
    # pushd /mnt/dmt_bin
    # git clone https://github.com/iovisor/bcc.git
    # mkdir bcc/build
    # cd bcc/build
    # cmake ..
    # make -j$(nproc)
    # sudo make install
    # cmake -DPYTHON_CMD=python3 .. # build python3 binding
    # pushd src/python/
    # make
    # sudo make install
    # popd
    # popd

    # # Setup rocksdb
    # pushd /mnt/dmt_bin
    # git clone https://github.com/facebook/rocksdb.git
    # cd rocksdb
    # sudo apt install -y libgflags-dev libsnappy-dev zlib1g-dev libbz2-dev liblz4-dev libzstd-dev
    # make -j$(nproc) all

    echo "Done"

fi
