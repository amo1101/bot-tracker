#!/bin/bash

SWITCH=$1
CNC_IPS=$2

CHAIN_NAT=NAT-BC
OP='-I'
if [ $SWITCH == 'OFF' ]; then
    OP='-D'
fi

IFS=','
read -ra cnc_ip <<< "$CNC_IPS"
for cnc_ip in "${cnc_ip[@]}"; do
    # traffic to cnc ip should not be redirected
    iptables -t nat $OP $CHAIN_NAT -d $cnc_ip -j RETURN
done

