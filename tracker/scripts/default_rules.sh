#!/bin/bash

SWITCH=$1
SUBNET=$2
DNS_RATE=$2
HTTPS_PROXY_PORT=$4

if [ $SWITCH == 'OFF' ]; then
    iptables -I FORWARD 1 -p udp --dport 53 -d 8.8.8.8 -s $SUBNET -m limit --limit $DNS_RATE/sec --limit-burst $DNS_RATE -j ACCEPT
    iptables -I FORWARD 1 -p udp --dport 53 -d 8.8.8.8 -s $SUBNET -m limit --limit $DNS_RATE/sec --limit-burst $DNS_RATE -j ACCEPT
fi

