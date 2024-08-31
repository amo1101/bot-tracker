#!/bin/bash

SWITCH=$1
SUBNET=$2
SIM_SERVER=$3
TCP_PORTS=$4

CHAIN_NAT=NAT-BC
IFS=','

if [ "$SWITCH" == "ON" ]; then
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
