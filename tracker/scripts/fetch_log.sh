#!/bin/bash

LOG_DIR=$1
FS_PATH=$2

MOUNT_FOLDER=`mktemp -d`
mount $FS_PATH $MOUNT_FOLDER

if [ $? -eq 0 ]; then
    cp -rf $MOUNT_FOLDER/bot/log $LOG_DIR/
    cp -rf $MOUNT_FOLDER/bot/syscall $LOG_DIR/
fi

umount $MOUNT_FOLDER
rm -rf $MOUNT_FOLDER

