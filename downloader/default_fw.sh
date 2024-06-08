#!/usr/bin/bash

SWITCH=$1

OP='-A'
if [ $SWITCH == 'OFF' ]; then
    OP='-D'
fi


# allow for db connection to host
sudo iptables $OP OUTPUT -d 192.168.100.5 -p tcp --dport 5432 -j ACCEPT
	
# allow for ssh connection from sandbox to download bot using scp command
iptables $OP INPUT -p tcp --dport 22 -j ACCEPT

# allow for web traffic from botnet-tracker
iptables $OP INPUT -p tcp -s 192.168.100.0/24 --dport 80 -j ACCEPT
iptables $OP INPUT -p tcp -s 192.168.100.0/24 --dport 443 -j ACCEPT
iptables $OP INPUT -p tcp -s 192.168.100.0/24 --dport 10443 -j ACCEPT

# redirect https traffic to PolarProxy
iptables -t nat $OP PREROUTING -p tcp --dport 443 -j REDIRECT --to 10443

# allow established or related traffic in the other direction
iptables $OP INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables $OP OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	
	
iptables -I INPUT 1 -i lo -j ACCEPT

if [ $SWITCH == 'ON' ]; then
    iptables -P INPUT DROP
    iptables -P OUTPUT DROP
else
    iptables -P INPUT ACCEPT
    iptables -P OUTPUT ACCEPT
fi

# /sbin/iptables-save
