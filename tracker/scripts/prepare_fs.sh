#!/bin/bash

BOT_NAME=$1
BOT_DIR=$2
FS_PATH=$3

MOUNT_FOLDER=`mktemp -d`
mount $FS_PATH $MOUNT_FOLDER

if [ $? -eq 0 ]; then
    cp -rf $BOT_DIR $MOUNT_FOLDER/
    cat > $MOUNT_FOLDER/etc/rc.local << EOF
        # start bot
        if [[$BOT_NAME == "TEST*"]]; then
            # start testbot
            /bot/bot.py $BOT_NAME
        else
            /bot/start_bot.sh $BOT_NAME
        exit 0 
    EOF
fi

umount $MOUNT_FOLDER
rm -rf $MOUNT_FOLDER
