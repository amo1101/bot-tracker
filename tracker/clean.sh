doms=$(virsh list | grep -v '^$' | tail -n +3 | awk '{print $2}')
for dom in $doms; do
    virsh destroy $dom
done

bindings=$(virsh nwfilter-binding-list | grep -v '^$' | tail -n +3 | awk '{print $1}')
for b in $bindings; do
    virsh nwfilter-binding-delete $b
done

virsh nwfilter-undefine sandbox-default-filter
virsh nwfilter-undefine sandbox-default-filter-rate-limit
virsh nwfilter-undefine sandbox-cnc-filter
virsh nwfilter-undefine sandbox-cnc-filter-rate-limit
virsh nwfilter-undefine sandbox-base-filter
virsh net-destroy mynet

progs=$(ps -ef | grep 'python3 run.py' | awk '{print $2}' | head -n 3)
for prog in $progs; do
    kill -9 $prog
done

iptables -D FORWARD -s 192.168.122.0/24 -p tcp --dport 53 -j FWD-BC
iptables -D FORWARD -s 192.168.122.0/24 -p udp --dport 53 -j FWD-BC
iptables -F FWD-BC
iptables -X FWD-BC
iptables -F PREROUTING -t nat
iptables -t mangle -D PREROUTING -s 192.168.122.0/24 -j MARK --set-mark 1

rm /var/lib/libvirt/images/openwrt-vm*
