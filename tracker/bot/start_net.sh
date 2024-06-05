#!/bin/sh

uci delete network.lan
uci set network.wan=interface
uci set network.wan.proto='dhcp'
uci set network.wan.ifname='eth0'
uci set network.wan.dns='8.8.8.8'
uci commit network
/etc/init.d/network restart

