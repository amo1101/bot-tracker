#!/bin/sh

if [ $# -lt 1 ]; then
    echo "Usage: $0 dns_server"
    exit 1
fi

DNS_SERVER=$1

uci delete network.lan
uci set network.wan=interface
uci set network.wan.proto='dhcp'
uci set network.wan.ifname='eth0'
if [ "$DNS_SERVER" != "*" ]; then
  uci set network.wan.dns=$DNS_SERVER
fi
uci commit network
/etc/init.d/network restart

