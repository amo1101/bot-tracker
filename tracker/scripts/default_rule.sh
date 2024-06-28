#!/bin/bash

SWITCH=$1
SUBNET=$2
DNS_RATE=$3
SIM_SERVER=$4
TCP_PORTS=$5

CHAIN=FWD-BC
CHAIN_NAT=NAT-BC
IFS=','

if [ "$SWITCH" == "ON" ]; then
    # forward chain for dns traffic rate-limiting
    iptables -N $CHAIN
    iptables -A $CHAIN -p udp --dport 53 -s "$SUBNET" -m limit --limit "$DNS_RATE"/sec --limit-burst "$DNS_RATE" -j RETURN
    iptables -A $CHAIN -p tcp --dport 53 -s "$SUBNET" -m limit --limit "$DNS_RATE"/sec --limit-burst "$DNS_RATE" -j RETURN
    iptables -A $CHAIN -j DROP
    iptables -A FORWARD -s "$SUBNET" -p udp --dport 53 -j $CHAIN
    iptables -A FORWARD -s "$SUBNET" -p tcp --dport 53 -j $CHAIN

    # nat table PREROUTING chain for traffic redirection
    if [ -n "$SIM_SERVER" ]; then
        iptables -N $CHAIN_NAT -t nat
        iptables -t nat -A $CHAIN_NAT -j DNAT --to-destination "$SIM_SERVER"
        read -ra ports <<< "$TCP_PORTS"
        for port in "${ports[@]}"; do
            iptables -t nat -A PREROUTING -s "$SUBNET" -p TCP --dport "$port" -j $CHAIN_NAT
        done
    fi

    # mark outgoing packets for monitoring
    iptables -t mangle -A PREROUTING -s "$SUBNET" -j MARK --set-mark 0xb
else
    iptables -F $CHAIN
    iptables -D FORWARD -s "$SUBNET" -p udp --dport 53 -j $CHAIN
    iptables -D FORWARD -s "$SUBNET" -p tcp --dport 53 -j $CHAIN
    iptables -X $CHAIN

    if [ -n "$SIM_SERVER" ]; then
        iptables -F $CHAIN_NAT -t nat
        read -ra ports <<< "$TCP_PORTS"
        for port in "${ports[@]}"; do
            iptables -t nat -D PREROUTING -s "$SUBNET" -p TCP --dport "$port" -j $CHAIN_NAT
        done
        iptables -X $CHAIN_NAT -t nat
    fi

    iptables -t mangle -D PREROUTING -s "$SUBNET" -j MARK --set-mark 0xb
fi
