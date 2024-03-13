doms=$(virsh list | grep -v '^$' | tail -n +3 | awk '{print $2}')
for dom in $doms; do
    virsh destroy $dom
done
virsh nwfilter-undefine sandbox-default-filter
virsh nwfilter-undefine sandbox-conn-limit-filter
virsh nwfilter-undefine sandbox-cnc-filter
virsh nwfilter-undefine sandbox-conn-limit-filter
virsh net-destroy mynet
