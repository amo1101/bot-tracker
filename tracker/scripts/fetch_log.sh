#!/bin/bash

FS_PATH=$1
LOG_DIR=$2
S_TIME=$3
E_TIME=$4

MOUNT_FOLDER=`mktemp -d`
mount $FS_PATH $MOUNT_FOLDER

if [ $? -eq 0 ]; then
    #  roll current log
    cd $LOG_DIR

    new_folder=$(printf "%s_%s" "$S_TIME" "$E_TIME")

    mkdir "$new_folder"
    
    mv *.pcap *.csv $new_folder/
    cp -rf $MOUNT_FOLDER/bot/log $LOG_DIR/$new_folder/
    cp -rf $MOUNT_FOLDER/bot/syscall $LOG_DIR/$new_folder/
fi

umount $MOUNT_FOLDER
rm -rf $MOUNT_FOLDER

