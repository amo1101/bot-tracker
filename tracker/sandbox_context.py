import asyncio
import libvirt
import libvirtaio
import os
import logging
import time
import sys
from enum import Enum
from lxml import etree

l = logging.getLogger(__name__)

CUR_DIR = os.path.dirname(os.path.realpath(__file__))

class SandboxNWFilter(Enum):
    DEFAULT = "sandbox-default-filter"
    CNC = "sandbox-cnc-filter"
    CONN_LIMIT = "sandbox-conn-limit-filter"

class SandboxNWFilterParameter(Enum):
    PORT_DEV = "portdev"
    MAC_ADDR = "mac"
    MAL_REPO_IP = "MAL_REPO_IP"
    CNC_IP = "CNC_IP"
    SCAN_PORT = "SCAN_PORT"
    CONN_LIMIT = "CONN_LIMIT"

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

        self.sandbox_nwfilter_registry = \
        {
            SandboxNWFilter.DEFAULT.value: ["default_filter.xml", "bind_default_filter.xml"],
            SandboxNWFilter.CNC.value: ["cnc_filter.xml", "bind_cnc_filter.xml"],
            SandboxNWFilter.CONN_LIMIT.value: ["conn_limit_filter.xml", "bind_conn_limit_filter.xml"]
        }

        self.nwfilter_objs = []

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

    def _define_nwfilters(self):
        for k, v in self.sandbox_nwfilter_registry.items():
            with open(self.config_base + os.sep + v[0], 'r') as file:
                xml_desc = file.read()
            obj = self.conn.nwfilterDefineXML(xml_desc)
            if obj:
                self.nwfilter_objs.append(obj)
            else:
                l.error("Failed to define nwfilter %s", k)
                return False
        return True

    def _undefine_nwfilters(self):
        for obj in self.nwfilter_objs:
            obj.undefine()
            # TODO do we need to free the obj?

    def _get_nwfilter_binding(self, filter_name, **kwargs):
        if filter_name not in SandboxNWFilter:
            return ""

        para_to_check = [SandboxNWFilterParameter.PORT_DEV.value,
                         SandboxNWFilterParameter.MAC_ADDR.value]

        if filter_name == SandboxNWFilter.DEFAULT:
            para_to_check.append(SandboxNWFilterParameter.MAL_REPO_IP.value)
        elif filter_name == SandboxNWFilter.CNC:
            para_to_check.append(SandboxNWFilterParameter.MAL_REPO_IP.value)
            para_to_check.append(SandboxNWFilterParameter.CNC_IP.value)
        else:
            para_to_check.append(SandboxNWFilterParameter.MAL_REPO_IP.value)
            para_to_check.append(SandboxNWFilterParameter.CNC_IP.value)
            para_to_check.append(SandboxNWFilterParameter.SCAN_PORT.value)
            para_to_check.append(SandboxNWFilterParameter.CONN_LIMIT.value)

        if not all(p in kwargs for p in para_to_check):
            l.error("some parameter is not provided for the nwfilter binding \
                    %s.", filter_name.value)
            return ""

        with open(self.config_base + os.sep +
                  self.sandbox_nwfilter_registry[filter_name.value][1], 'r') as file:
            bind_xml = file.read()

        # set portdev name
        tree = etree.fromstring(bind_xml)
        portdev_element = tree.xpath(f"//portdev")[0]
        portdev_element.set("name",
                            kwargs[SandboxNWFilterParameter.PORT_DEV.value])

        # set mac address
        mac_element = tree.xpath("//mac")[0]
        mac_element.set("address",
                        kwargs[SandboxNWFilterParameter.MAC_ADDR.value])

        # set filter parameters
        for p in para_to_check[2:]:
            if p in kwargs:
                para_element = tree.xpath(f"//filterref/parameter[@name='{p}']")[0]
                if para_element is not None:
                    para_element.set("value", kwargs[p])

        return etree.tostring(tree, encoding='unicode')

    def apply_nwfilter(self, filter_name, **kwargs):
        binding_xml = self._get_nwfilter_binding(filter_name, **kwargs)
        if binding_xml == "":
            return None

        l.debug("binding xml: %s", binding_xml)

        # have to delete existing binding firstly
        #  bo = self.conn.nwfilterBindingLookupByPortDev(\
                #  kwargs[SandboxNWFilterParameter.PORT_DEV.value])
        #  if bo:
            #  bo.delete()

        return self.conn.nwfilterBindingCreateXML(binding_xml)

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
        # TODO is networkCreateXMLFlags synchronous?
        if not self.net.isActive():
            l.error("network is not active")
            return False

        l.debug("network is active")

        # define nwfilters
        if not self._define_nwfilters():
            l.error("failed to define network filters")
            return False

        return False

    def destroy(self):
        # now we should have all domains destroyed
        # undefine nwfilters
        self._undefine_nwfilters()

        #  self.conn.networkEventDeregisterAny(libvirt.VIR_NETWORK_EVENT_ID_LIFECYCLE)
        if self.net is not None and self.net.isActive():
            l.debug("destroying network...")
            self.net.destroy()
        self.conn.close()

