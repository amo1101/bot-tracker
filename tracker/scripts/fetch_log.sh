#!/bin/bash

LOG_DIR=$1
FS_PATH=$2

MOUNT_FOLDER=`mktemp -d`
mount $FS_PATH $MOUNT_FOLDER

if [ $? -eq 0 ]; then
    #  roll current log
    cd $LOG_DIR

    max_folder=$(ls -d [0-9][0-9][0-9][0-9] 2>/dev/null | sort | tail -n 1)
    if [ -z "$max_folder" ]; then
        new_folder="0000"
    else
        next_folder=$((10#$max_folder + 1))
        new_folder=$(printf "%04d" "$next_folder")
    fi

    mkdir "$new_folder"
    mv log $new_folder/
    mv syscall $new_folder/
    mv *.pcap $new_folder/

    cp -rf $MOUNT_FOLDER/bot/log $LOG_DIR/
    cp -rf $MOUNT_FOLDER/bot/syscall $LOG_DIR/
fi

umount $MOUNT_FOLDER
rm -rf $MOUNT_FOLDER

