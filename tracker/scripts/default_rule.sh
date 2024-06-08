#!/bin/bash

SWITCH=$1
SUBNET=$2
DNS_RATE=$3

CHAIN=FWD-BC

if [ $SWITCH == 'ON' ]; then
    iptables -N $CHAIN

    iptables -A $CHAIN -p udp --dport 53 -s $SUBNET -m limit --limit $DNS_RATE/sec --limit-burst $DNS_RATE -j RETURN
    iptables -A $CHAIN -p tcp --dport 53 -s $SUBNET -m limit --limit $DNS_RATE/sec --limit-burst $DNS_RATE -j RETURN
    iptables -A $CHAIN -j DROP

    iptables -A FORWARD -s $SUBNET -p udp --dport 53 -j $CHAIN
    iptables -A FORWARD -s $SUBNET -p tcp --dport 53 -j $CHAIN

    # mark outgoing packets for monitoring
    iptables -t mangle -A PREROUTING -s $SUBNET -j MARK --set-mark 0xb
else
    iptables -F $CHAIN
    iptables -D FORWARD -s $SUBNET -p udp --dport 53 -j $CHAIN
    iptables -D FORWARD -s $SUBNET -p tcp --dport 53 -j $CHAIN
    iptables -X $CHAIN

    iptables -t mangle -D PREROUTING -s $SUBNET -j MARK --set-mark 0xb
fi
