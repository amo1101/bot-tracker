#!/bin/bash

BOT_NAME=$1
BOT_DIR=$2
FS_PATH=$3

MOUNT_FOLDER=`mktemp -d`
mount $FS_PATH $MOUNT_FOLDER

if [ $? -eq 0 ]; then
    cp -rf $BOT_DIR $MOUNT_FOLDER/
    chmod +x $MOUNT_FOLDER/bot/start_bot.sh
    cat > $MOUNT_FOLDER/etc/rc.local << EOF
        /bot/start_bot.sh $BOT_NAME
        exit 0 
EOF
fi

umount $MOUNT_FOLDER
rm -rf $MOUNT_FOLDER
