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

MAX_RETRIES=10
retry_count=0

echo "Downloading bot from $HOST:$DOWNLOAD_PATH/$BOT_NAME"
while [ $retry_count -lt $MAX_RETRIES ]; do
    /usr/bin/scp -i ./$KEY_FILE $USERNAME@$HOST:$DOWNLOAD_PATH/$BOT_NAME ./$BOT_NAME
    if [ $? -eq 0 ]; then
        echo "Bot downloaded successfully."
        break
    else
        echo "Failed to download bot. Retrying... ($((retry_count + 1))/$MAX_RETRIES)"
        retry_count=$((retry_count + 1))
    fi
    sleep 3
done

chmod +x ./$BOT_NAME

echo "Running bot with strace: $BOT_NAME"
rm -f alice
ln /usr/bin/strace alice 
./alice -ftttT -s999 -o syscall/$BOT_NAME.log ./$BOT_NAME >log/$BOT_NAME.out &

echo "Execution complete"

