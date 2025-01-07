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
    sudo veritysetup close data_disk || true
    sudo cryptsetup luksClose data_disk_crypt || true
    sudo dmsetup remove data_disk || true

    sudo dmsetup remove data_disk_base2 || true
    sudo dmsetup remove data_disk_base || true

    sudo dmsetup remove meta_disk || true
    sudo dmsetup remove meta_disk_base || true

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
# size=$((size + size / 20 / 4096 * 4096)) # make space to fit LUKS metadata
sudo dmsetup create data_disk_base --table "0 $size linear $d1 $off"
sudo dmsetup create data_disk_base2 --table "0 $size ebs \
    /dev/mapper/data_disk_base 0 8 1"
sudo chmod 777 /dev/mapper/data_disk_base
sudo chmod 777 /dev/mapper/data_disk_base2
sudo dd if=/dev/zero of=/dev/mapper/data_disk_base2 bs=4096 count=1

off=0
meta_size=$5
meta_size=$((meta_size / 512))
sudo dmsetup create meta_disk_base --table "0 $meta_size linear $d2 $off"
sudo dmsetup create meta_disk --table "0 $meta_size ebs \
    /dev/mapper/meta_disk_base 0 8 1"
sudo chmod 777 /dev/mapper/meta_disk_base
sudo chmod 777 /dev/mapper/meta_disk
sudo dd if=/dev/zero of=/dev/mapper/meta_disk bs=4096 count=1

########
# Now setup the dm-crypt devices.
sudo cryptsetup -q --cipher aes-xts-plain --key-size 256 --key-file scripts/key.bin \
    luksFormat /dev/mapper/data_disk_base2
sudo cryptsetup --key-file scripts/key.bin --readonly \
    luksOpen /dev/mapper/data_disk_base2 data_disk_crypt
sudo chmod 777 /dev/mapper/data_disk_crypt

########
# Finally setup the dm-verity devices over the dm-crypt devices.

sudo veritysetup format /dev/mapper/data_disk_crypt \
    /dev/mapper/meta_disk &>verity.log

root_hash=$(cat verity.log | grep "Root" | cut -d':' -f2 | xargs)

sudo veritysetup open /dev/mapper/data_disk_crypt data_disk \
    /dev/mapper/meta_disk $root_hash
sudo chmod 777 /dev/mapper/data_disk
