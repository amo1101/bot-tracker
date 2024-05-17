#!/bin/bash

SWITCH=$1
SRC_IP=$2
TCP_PORTS=$3
SERVER_IP=$4
CNC_IP=$5

OP='-A'
if [ $SWITCH == 'OFF' ]; then
    OP='-D'
fi

IFS=','
read -ra ports <<< "$TCP_PORTS"
for port in "${ports[@]}"; do
    iptables -t nat $OP PREROUTING -s $SRC_IP -p TCP --dport $port ! -d $CNC_IP  -j DNAT --to-destination $SERVER_IP
done

