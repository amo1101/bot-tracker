iptables -t filter -D INPUT -j LOG --log-prefix "[FILTER_INPUT] "
iptables -t filter -D FORWARD -j LOG --log-prefix "[FILTER_FORWARD] "
iptables -t filter -D OUTPUT -j LOG --log-prefix "[FILTER_OUTPUT] "

iptables -t nat -D PREROUTING -j LOG --log-prefix "[NAT_PREROUTING] "
iptables -t nat -D INPUT -j LOG --log-prefix "[NAT_INPUT] "
iptables -t nat -D OUTPUT -j LOG --log-prefix "[NAT_OUTPUT] "
iptables -t nat -D POSTROUTING -j LOG --log-prefix "[NAT_POSTROUTING] "

iptables -t mangle -D PREROUTING -j LOG --log-prefix "[MANGLE_PREROUTING] "
iptables -t mangle -D INPUT -j LOG --log-prefix "[MANGLE_INPUT] "
iptables -t mangle -D OUTPUT -j LOG --log-prefix "[MANGLE_OUTPUT] "
iptables -t mangle -D POSTROUTING -j LOG --log-prefix "[MANGLE_POSTROUTING] "

