#!/bin/bash

if [ -z $1 ] 
then
    echo provide destination directory
else 
    cp qemu/hw/char/* $1/hw/char/
    cp qemu/hw/virtio/* $1/hw/virtio/
    cp qemu/include/hw/virtio/* $1/include/hw/virtio/
fi
