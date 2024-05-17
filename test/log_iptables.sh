iptables -t filter -A INPUT -j LOG --log-prefix "[FILTER_INPUT] "
iptables -t filter -A FORWARD -j LOG --log-prefix "[FILTER_FORWARD] "
iptables -t filter -A OUTPUT -j LOG --log-prefix "[FILTER_OUTPUT] "

iptables -t nat -A PREROUTING -j LOG --log-prefix "[NAT_PREROUTING] "
iptables -t nat -A INPUT -j LOG --log-prefix "[NAT_INPUT] "
iptables -t nat -A OUTPUT -j LOG --log-prefix "[NAT_OUTPUT] "
iptables -t nat -A POSTROUTING -j LOG --log-prefix "[NAT_POSTROUTING] "

iptables -t mangle -A PREROUTING -j LOG --log-prefix "[MANGLE_PREROUTING] "
iptables -t mangle -A INPUT -j LOG --log-prefix "[MANGLE_INPUT] "
iptables -t mangle -A OUTPUT -j LOG --log-prefix "[MANGLE_OUTPUT] "
iptables -t mangle -A POSTROUTING -j LOG --log-prefix "[MANGLE_POSTROUTING] "
