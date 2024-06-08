#!/usr/bin/bash

# allow for db connection to host
sudo iptables -A OUTPUT -d 192.168.100.5 -p tcp --dport 5432 -j ACCEPT
	
# allow for ssh connection from sandbox to download bot using scp command
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# allow for web traffic from botnet-tracker
iptables -A INPUT -p tcp -s 192.168.100.5/32 --dport 80 -j ACCEPT
iptables -A INPUT -p tcp -s 192.168.100.5/32 --dport 443 -j ACCEPT

# redirect https traffic to PolarProxy
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to 10443

# allow established or related traffic in the other direction
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
	
	
iptables -I INPUT 1 -i lo -j ACCEPT
iptables -P INPUT DROP
iptables -P OUTPUT DROP

# /sbin/iptables-save
