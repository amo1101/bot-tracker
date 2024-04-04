import asyncio
import libvirt
import libvirtaio
import libxml2
import os
import shutil
import logging
import time
import sys
import subprocess
from sandbox_context import *
from log import TaskLogger

l = TaskLogger(__name__)

class Sandbox:
    def __init__(self, context, name, bot_file, arch):
        self.context = context
        self.name = name
        self.bot_file = bot_file
        self.arch = arch
        self.parameter = None
        self.dom = None
        #  self.dom_changed_event = asyncio.Event()
        self.ifinfo = None
        self.port_dev = None
        self.mac_address = ""
        self.ip = ''
        self.fs = None
        self.filter_binding = None

    @staticmethod
    def _life_cycle_cb(conn, dom, event, detail, dom_changed_event):
        if event == libvirt.VIR_DOMAIN_EVENT_STARTED or event == \
           libvirt.VIR_DOMAIN_EVENT_STOPPED:
            l.debug("domain lifecycle event occured, event: %d, detail: %d",
                    event, detail)
            dom_changed_event.set()

    def _prepare_kernel(self):
        src, dst = self.context.get_sandbox_kernel(self.arch)
        l.debug("kernel src %s, dst %s", src, dst)
        if not os.path.exists(dst):
            shutil.copyfile(src, dst)

    def _run_script(self, which, *args):
        try:
            params = []
            script = self.context.get_script(which)
            params.append(script)
            for p in args:
                params.append(p)
            l.debug(f'params: ${params}')
            proc = subprocess.Popen(params, stdout=subprocess.PIPE)
            out, err = proc.communicate()
            if err:
                l.error("failed to run script:{script}, error: {err}")
                return False
            return True
        except Exception as err:
            l.error(f'exception occured: {err}')
            return False

    def _prepare_fs(self):
        src, dst = self.context.get_sandbox_fs(self.arch, self.name)
        l.debug("fs src %s, dst %s", src, dst)

        # TODO: prepare fs
        self.fs = dst

        if not os.path.exists(dst):
            shutil.copyfile(src, dst)

        # copy bot directory to sandbox fs
        bot_dir = self.context.get_bot_dir()
        s = SandboxScript.PREPARE_FS
        self._run_script(s, self.bot_file, bot_dir, dst)

    def _get_config(self):
        return self.context.get_sandbox_config(self.arch, self.name)

    def _destroy_fs(self):
        if os.path.exists(self.fs):
            os.remove(self.fs)

    def fetch_log(self, dst):
        s = SandboxScript.FETCH_LOG
        self._run_script(s, self.fs, dst)

    def start(self):
        self._prepare_kernel()
        self._prepare_fs()
        dom_xml = self._get_config()
        l.debug("dom config:")
        l.debug("%s", dom_xml)

        self.dom = self.context.conn.createXML(dom_xml,
                                               libvirt.VIR_DOMAIN_START_VALIDATE)
        if self.dom is None:
            l.error("create domain %s failed", self.name)
            return

        while True:
            if self.dom.state()[0] != libvirt.VIR_DOMAIN_RUNNING:
                l.debug("domain state %d, reason %d...", self.dom.state()[0],
                        self.dom.state()[1])
                time.sleep(5)
            else:
                break

        l.debug("domain state %d, reason %d...", self.dom.state()[0],
                self.dom.state()[1])

    # TODO: replace with asyncio
    def get_ifinfo(self):
        if self.port_dev is None:
            ifaces = self.dom.interfaceAddresses(libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE)
            while len(ifaces) == 0:
                print("sleep 2 secs...")
                time.sleep(2)
                ifaces = self.dom.interfaceAddresses(libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE)
            print("ifaces are ....")
            for k,v in ifaces.items():
                print(f"{k}:{v}")
            self.port_dev = list(ifaces.keys())[0]
            self.mac_address = ifaces[self.port_dev]['hwaddr']
            self.ip = ifaces[self.port_dev]['addrs'][0]['addr']
            l.debug("get port_dev %s, mac_address: %s, ip: %s", self.port_dev,
                    self.mac_address, self.ip)
        return (self.port_dev, self.mac_address, self.ip)

    def apply_nwfilter(self, filter_name, **kwargs):
        self.get_ifinfo()
        # It's ok to give a superset of parameters, SandboxContext will choose
        #  args = \
        #  {
            #  sandbox_context.SandboxNWFilterParameter.PORT_DEV.value:
                #  self.port_dev,
            #  sandbox_context.SandboxNWFilterParameter.MAC_ADDR.value:
                #  self.mac_address,
            #  sandbox_context.SandboxNWFilterParameter.MAL_REPO_IP.value:
               #  self.mal_repo_ip,
            #  sandbox_context.SandboxNWFilterParameter.CNC_IP.value:
               #  self.cnc_ip,
            #  sandbox_context.SandboxNWFilterParameter.CONN_LIMIT.value:
               #  self.conn_limit,
            #  sandbox_context.SandboxNWFilterParameter.SCAN_PORT.value:
               #  self.scan_port
        #  }

        if self.filter_binding:
            self.filter_binding.delete()
            self.filter_binding = None

        l.debug(f'filter: {filter_name},kwargs: {kwargs}')
        self.filter_binding = self.context.apply_nwfilter(filter_name,
                                                          port_dev=self.port_dev,
                                                          mac_addr=self.mac_address,
                                                          **kwargs)
        if not self.filter_binding:
            l.error("failed to apply nw filter")
            return False

        l.debug("filter %s is applied", filter_name.value)
        return True


    def destroy(self):
        self._destroy_fs()
        if self.filter_binding:
            l.debug("delete filter binding...")
            self.filter_binding.delete()
        self.dom.destroy()
        l.debug("dom destroyed %s", self.name)

