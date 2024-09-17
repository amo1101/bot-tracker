#!/bin/bash

BOT_NAME=$1
BOT_DIR=$2
FS_PATH=$3
BOT_REPO_IP=$4
BOT_REPO_USER=$5
BOT_REPO_PATH=$6
TRACE_SYSCALL=$7
DNS_SERVER=$8

MOUNT_FOLDER=`mktemp -d`
chmod 755 $FS_PATH
mount $FS_PATH $MOUNT_FOLDER

cat > $MOUNT_FOLDER/etc/run_bot.sh << EOF
#!/bin/sh
/bot/start_net.sh $DNS_SERVER
sleep 20
cd /bot; ./start_bot.sh $BOT_NAME $BOT_REPO_IP $BOT_REPO_USER $BOT_REPO_PATH $TRACE_SYSCALL &
EOF

chmod +x $MOUNT_FOLDER/etc/run_bot.sh

if [ $? -eq 0 ]; then
    cp -rf $BOT_DIR $MOUNT_FOLDER/
    chmod +x $MOUNT_FOLDER/bot/start_net.sh
    chmod +x $MOUNT_FOLDER/bot/start_bot.sh
    cat > $MOUNT_FOLDER/etc/rc.local << EOF
        /etc/run_bot.sh
        exit 0 
EOF
fi

umount $MOUNT_FOLDER
rm -rf $MOUNT_FOLDER
