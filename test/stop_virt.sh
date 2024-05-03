#start libvirt
#stop monolithic services
sudo systemctl stop libvirtd.service
sudo systemctl stop libvirtd{,-ro,-admin,-tcp,-tls}.socket
sudo systemctl disable libvirtd.service
sudo systemctl disable libvirtd{,-ro,-admin,-tcp,-tls}.socket

#enable qemu related modular services
for drv in qemu interface network nodedev nwfilter secret storage 
do
  sudo systemctl mask virt${drv}d.service
  sudo systemctl mask virt${drv}d{,-ro,-admin}.socket
  sudo systemctl disable virt${drv}d.service
  sudo systemctl disable virt${drv}d{,-ro,-admin}.socket
done

#enable logd lockd
for drv in log lock 
do
  sudo systemctl mask virt${drv}d.service
  sudo systemctl mask virt${drv}d{,-admin}.socket
  sudo systemctl disable virt${drv}d.service
  sudo systemctl disable virt${drv}d{,-admin}.socket
done

#start services
for drv in qemu network nodedev nwfilter secret storage
do
  sudo systemctl stop virt${drv}d{,-ro,-admin}.socket
done

#start logd lockd 
for drv in log lock
do
  sudo systemctl stop virt${drv}d{,-admin}.socket
done

sudo systemctl mask postgresql
sudo systemctl disable postgresql
sudo systemctl stop postgresql

#check service
sudo systemctl is-active virtqemud.socket
sudo systemctl is-active virtlogd.socket
sudo systemctl is-active virtlockd.socket
sudo systemctl is-active postgresql
