doms=$(virsh list | grep -v '^$' | tail -n +3 | awk '{print $2}')
for dom in $doms; do
    virsh destroy $dom
done

bindings=$(virsh nwfilter-binding-list | grep -v '^$' | tail -n +3 | awk '{print $1}')
for b in $bindings; do
    virsh nwfilter-binding-delete $b
done

virsh nwfilter-undefine sandbox-default-filter
virsh nwfilter-undefine sandbox-cnc-filter
virsh net-destroy mynet

progs=$(ps -ef | grep 'python3 run.py' | awk '{print $2}' | head -n 3)
for prog in $progs; do
    kill -9 $prog
done

