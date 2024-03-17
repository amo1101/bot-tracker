#!/bin/sh

if [ $# -lt 1 ]; then
    echo "Usage: $0 bot_name"
    exit 1
fi

BOT_NAME=$1
USERNAME=remnux
HOST=192.168.1.66
DOWNLOAD_PATH=/home/$USERNAME/malware_repo
KEY_FILE=sandbox_key

mkdir -p log syscall
cp known_hosts /root/.ssh/

# wait for network
sleep 30

echo "Downloading binary from $HOST:$DOWNLOAD_PATH"
scp -i $KEY_FILE $USERNAME@$HOST:$DOWNLOAD_PATH/$BOT_NAME .
chmod +x $BOT_NAME

echo "Running binary with strace: $BOT_NAME"
rm -f alice
ln /usr/bin/strace alice 
./alice -ftttT -s999 -o syscall/$BOT_NAME.log ./$BOT_NAME >log/$BOT_NAME.out &

echo "Execution complete"

