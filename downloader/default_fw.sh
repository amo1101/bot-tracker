#!/usr/bin/bash

SWITCH=$1

OP='-A'
if [ $SWITCH == 'OFF' ]; then
    OP='-D'
fi

# allow inbound traffic from botnet-tracker
iptables $OP INPUT -s 192.168.100.5 -j ACCEPT
iptables $OP INPUT -s 192.168.100.4 -j ACCEPT
iptables $OP INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables $OP INPUT -j DROP

# allow dns traffic
iptables $OP OUTPUT -p udp --dport 53 -j ACCEPT
iptables $OP OUTPUT -p tcp --dport 53 -j ACCEPT

# allow outbound traffic to botnet tracker and online bot repo
iptables $OP OUTPUT -d 192.168.100.5 -j ACCEPT
iptables $OP OUTPUT -d 192.168.100.4 -j ACCEPT
iptables $OP OUTPUT -d 34.111.17.235 -j ACCEPT
iptables $OP OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables $OP OUTPUT -j DROP

# redirect https traffic to PolarProxy
iptables -t nat $OP PREROUTING -p tcp --dport 443 -j REDIRECT --to 10443

iptables -I INPUT 1 -i lo -j ACCEPT

# /sbin/iptables-save
