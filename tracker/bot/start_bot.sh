#!/bin/sh

if [ $# -lt 1 ]; then
    echo "Usage: $0 bot_name"
    exit 1
fi

BOT_NAME=$1

# configure malware repo
USERNAME=frankwu
HOST=10.11.45.60
DOWNLOAD_PATH=/home/$USERNAME/code/bot-tracker/downloader/malware_repo

# sandbox key file
# make sure sandbox pub key is in ~/.ssh/authorized_keys on malware_repo server
KEY_FILE=sandbox_key

mkdir -p log syscall

# malware repo server should be a known host
mkdir -p /root/.ssh
cp known_hosts /root/.ssh/

# wait for network
sleep 30

echo "Downloading bot from $HOST:$DOWNLOAD_PATH"
scp -i $KEY_FILE $USERNAME@$HOST:$DOWNLOAD_PATH/$BOT_NAME .
chmod +x $BOT_NAME

echo "Running bot with strace: $BOT_NAME"
rm -f alice
ln /usr/bin/strace alice 
./alice -ftttT -s999 -o syscall/$BOT_NAME.log ./$BOT_NAME >log/$BOT_NAME.out &

echo "Execution complete"

