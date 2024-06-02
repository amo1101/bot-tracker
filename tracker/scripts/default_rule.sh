#!/bin/bash

SWITCH=$1
SUBNET=$2
DNS_RATE=$3
HTTPS_PROXY_PORT=$4

CHAIN=BC_FWO

if [ $SWITCH == 'ON' ]; then
    iptables -N $CHAIN

    iptables -A $CHAIN -p udp --dport 53 -s $SUBNET -m limit --limit $DNS_RATE/sec --limit-burst $DNS_RATE -j RETURN
    iptables -A $CHAIN -p tcp --dport 53 -s $SUBNET -m limit --limit $DNS_RATE/sec --limit-burst $DNS_RATE -j RETURN
    iptables -A $CHAIN -j DROP

    iptables -I FORWARD 1 -s $SUBNET -p udp --dport 53 -j $CHAIN
    iptables -I FORWARD 1 -s $SUBNET -p tcp --dport 53 -j $CHAIN
else
    iptables -F $CHAIN
    iptables -D FORWARD -s $SUBNET -p udp --dport 53 -j $CHAIN
    iptables -D FORWARD -s $SUBNET -p tcp --dport 53 -j $CHAIN
    iptables -X $CHAIN
fi
