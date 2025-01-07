#!/bin/bash

set -e -x

sudo() {
    [[ $EUID = 0 ]] || set -- command sudo "$@"
    "$@"
}

###
# Cleanup disks if needed.
###
if [ "$1" == "c" ]; then
    sudo dmsetup remove data_disk || true
    sudo dmsetup remove data_disk_base || true

    sudo dmsetup remove top_leaf_meta_disk || true
    sudo dmsetup remove leaf_meta_disk_base || true

    sudo dmsetup remove top_internal_meta_disk || true
    sudo dmsetup remove internal_meta_disk_base || true

    exit 0
fi

###
# Otherwise setup new disks.
###

d1=$2 # data device (SSD)
sudo chmod 777 $d1

d2=$4 # metadata device (SSD)
sudo chmod 777 $d2

########
# Set up data device to get the other baseline (simple SSD or HDD)

off=0
size=$3
size=$((size / 512))
sudo dmsetup create data_disk_base --table "0 $size linear $d1 $off"
if [ ! -e /dev/mapper/data_disk_base ]; then
    dm_num=$(sudo dmsetup ls | grep -m1 "data_disk_base" | cut -d':' -f2 | cut -d')' -f1)
    sudo ln -s /dev/dm-$dm_num /dev/mapper/data_disk_base
fi
sudo chmod 777 /dev/mapper/data_disk_base
sudo dmsetup create data_disk --table "0 $size ebs \
    /dev/mapper/data_disk_base 0 8 1"
if [ ! -e /dev/mapper/data_disk ]; then
    dm_num=$(sudo dmsetup ls | grep -m1 "data_disk" | cut -d':' -f2 | cut -d')' -f1)
    sudo ln -s /dev/dm-$dm_num /dev/mapper/data_disk
fi
sudo chmod 777 /dev/mapper/data_disk
off=$((off + size))
sudo dd if=/dev/zero of=/dev/mapper/data_disk bs=4096 count=1

off=0
meta_size=$5
meta_size=$((meta_size / 512))
sudo dmsetup create leaf_meta_disk_base --table "0 $meta_size linear $d2 $off"
if [ ! -e /dev/mapper/leaf_meta_disk_base ]; then
    dm_num=$(sudo dmsetup ls | grep -m1 "leaf_meta_disk_base" | cut -d':' -f2 | cut -d')' -f1)
    sudo ln -s /dev/dm-$dm_num /dev/mapper/leaf_meta_disk_base
fi
sudo chmod 777 /dev/mapper/leaf_meta_disk_base
sudo dmsetup create top_leaf_meta_disk --table "0 $meta_size ebs \
    /dev/mapper/leaf_meta_disk_base 0 8 1"
if [ ! -e /dev/mapper/top_leaf_meta_disk ]; then
    dm_num=$(sudo dmsetup ls | grep -m1 "top_leaf_meta_disk" | cut -d':' -f2 | cut -d')' -f1)
    sudo ln -s /dev/dm-$dm_num /dev/mapper/top_leaf_meta_disk
fi
off=$((off + meta_size))
sudo chmod 777 /dev/mapper/top_leaf_meta_disk
sudo dd if=/dev/zero of=/dev/mapper/top_leaf_meta_disk bs=4096 count=1

meta_size=$5
meta_size=$((meta_size / 512))
sudo dmsetup create internal_meta_disk_base --table "0 $meta_size linear $d2 $off"
if [ ! -e /dev/mapper/internal_meta_disk_base ]; then
    dm_num=$(sudo dmsetup ls | grep -m1 "internal_meta_disk_base" | cut -d':' -f2 | cut -d')' -f1)
    sudo ln -s /dev/dm-$dm_num /dev/mapper/internal_meta_disk_base
fi
sudo chmod 777 /dev/mapper/internal_meta_disk_base
sudo dmsetup create top_internal_meta_disk --table "0 $meta_size ebs \
    /dev/mapper/internal_meta_disk_base 0 8 1"
if [ ! -e /dev/mapper/top_internal_meta_disk ]; then
    dm_num=$(sudo dmsetup ls | grep -m1 "top_internal_meta_disk" | cut -d':' -f2 | cut -d')' -f1)
    sudo ln -s /dev/dm-$dm_num /dev/mapper/top_internal_meta_disk
fi
sudo chmod 777 /dev/mapper/top_internal_meta_disk
sudo dd if=/dev/zero of=/dev/mapper/top_internal_meta_disk bs=4096 count=1
