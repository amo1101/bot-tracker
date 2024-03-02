import asyncio
import libvirt
import libvirtaio
import aiofiles
import os
import logging
import time
import sys
from lxml import etree

l = logging.getLogger(__name__)

CUR_DIR = os.path.dirname(os.path.realpath(__file__))

class SandboxContext:
    def __init__(self):
        #  self.loop = loop
        self.event_imp = None
        self.conn = None
        self.net = None
        self.image_dir = "/var/lib/libvirt/images"
        self.config_base = CUR_DIR + os.sep + "config"
        self.image_base = CUR_DIR + os.sep + "image"
        self.net_conf = self.config_base + os.sep + "network.xml"
        self.sandbox_registry = \
        {
            "armv7": [
                        "sandbox_armv7.xml",
                        "openwrt-armsr-armv7-generic-kernel.bin",
                        "openwrt-armsr-armv7-generic-ext4-rootfs.img"
                     ]
        }

    @staticmethod
    def _net_lifecycle_cb(conn, net, event, detail, net_changed_event):
        if event == libvirt.VIR_NETWORK_EVENT_STARTED or event == \
           libvirt.VIR_NETWORK_EVENT_STOPPED:
            l.debug("network lifecycle event occured, event: %d, detail: %d",
                    event, detail)
            net_changed_event.set()

    def is_support_arch(self, arch):
        return arch in self.sandbox_registry

    def get_sandbox_config(self, arch, name):
        if arch not in self.sandbox_registry:
            return ""

        with open(self.config_base + os.sep + self.sandbox_registry[arch][0], 'r') as file:
            sandbox_xml = file.read()

        # replace sandbox name
        tree = etree.fromstring(sandbox_xml)
        name_element = tree.xpath("//name")[0]
        name_element.text = f"openwrt-vm-{arch}-{name}"

        # replace kernel name
        kernel_element = tree.xpath("//os/kernel")[0]
        kernel_element.text = self.get_sandbox_kernel(arch)[1]

        # replace fs name
        source_element = tree.xpath("//devices/disk/source")[0]
        source_element.set("file", self.get_sandbox_fs(arch, name)[1])
        return etree.tostring(tree, encoding='unicode')

    def get_sandbox_kernel(self, arch):
        if arch not in self.sandbox_registry:
            return ("", "")

        kernel_file = self.sandbox_registry[arch][1]
        return (self.image_base + os.sep + kernel_file,
                self.image_dir + os.sep + kernel_file)

    def get_sandbox_fs(self, arch, name):
        if arch not in self.sandbox_registry:
            return ("", "")

        fs_src = self.sandbox_registry[arch][2]
        fs_dst = f"openwrt-vm-{arch}-{name}-ext4-rootfs.img"
        return (self.image_base + os.sep + fs_src,
                self.image_dir + os.sep + fs_dst)

    def start(self):
        #  self.event_imp = libvirtaio.virEventRegisterAsyncIOImpl()
        self.conn = libvirt.open("qemu:///system")
        #  net_changed_event = asyncio.Event()

        # if default notwork is running, destroy it firstly
        default_net = self.conn.networkLookupByName("default")
        if default_net is not None and default_net.isActive():
            l.debug("destroy default network...")
            default_net.destroy()

        with open(self.net_conf,'r') as file:
            net_xml = file.read()

        #  async with aiofiles.open(self.net_conf, mode='r') as file:
            #  net_xml = await file.read()

        self.net = self.conn.networkCreateXMLFlags(net_xml)

        #  self.conn.networkEventRegisterAny(self.net,
                                          #  libvirt.VIR_NETWORK_EVENT_ID_LIFECYCLE,
                                          #  self._net_lifecycle_cb, net_changed_event)

        #  if self.net.isActive():
            #  l.debug("network is active....")

        #  await asyncio.wait_for(net_changed_event.wait(), 2)
        if self.net.isActive():
            l.debug("network is active")
            return True
        l.debug("network is not active")
        return False

    def destroy(self):
        #  self.conn.networkEventDeregisterAny(libvirt.VIR_NETWORK_EVENT_ID_LIFECYCLE)
        if self.net is not None and self.net.isActive():
            l.debug("destroying network...")
            self.net.destroy()
        self.conn.close()

