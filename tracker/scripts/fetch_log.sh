#!/bin/bash

FS_PATH=$1
LOG_DIR=$2

MOUNT_FOLDER=`mktemp -d`
mount $FS_PATH $MOUNT_FOLDER

if [ $? -eq 0 ]; then
    cd $LOG_DIR
    cp -rf $MOUNT_FOLDER/bot/log $LOG_DIR/
    cp -rf $MOUNT_FOLDER/bot/syscall $LOG_DIR/
fi

umount $MOUNT_FOLDER
rm -rf $MOUNT_FOLDER
