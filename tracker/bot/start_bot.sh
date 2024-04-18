#!/bin/sh

if [ $# -lt 4 ]; then
    echo "Usage: $0 bot_name bot_repo_ip bot_repo_user bot_repo_path"
    exit 1
fi

BOT_NAME=$1

# configure malware repo
HOST=$2
USERNAME=$3
DOWNLOAD_PATH=$4

# sandbox key file
# make sure sandbox pub key is in ~/.ssh/authorized_keys on malware_repo server
KEY_FILE=sandbox_key

mkdir -p log syscall

# malware repo server should be a known host
mkdir -p /root/.ssh
mkdir -p /.ssh
cp known_hosts /root/.ssh/
cp known_hosts /.ssh/

echo "Downloading bot from $HOST:$DOWNLOAD_PATH/$BOT_NAME"
/usr/bin/scp -i ./$KEY_FILE $USERNAME@$HOST:$DOWNLOAD_PATH/$BOT_NAME ./$BOT_NAME
chmod +x ./$BOT_NAME

echo "Running bot with strace: $BOT_NAME"
rm -f alice
ln /usr/bin/strace alice 
./alice -ftttT -s999 -o syscall/$BOT_NAME.log ./$BOT_NAME >log/$BOT_NAME.out &

echo "Execution complete"

