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
    def __init__(self,
                 context,
                 sandbox_vcpu_quota,
                 name, bot_file, arch,
                 bot_repo_ip, bot_repo_user, bot_repo_path):
        self.context = context
        self.sandbox_vcpu_quota = sandbox_vcpu_quota
        self.name = name
        self.bot_file = bot_file
        self.arch = arch
        self.bot_repo_ip = bot_repo_ip
        self.bot_repo_user = bot_repo_user
        self.bot_repo_path = bot_repo_path
        self.dom = None
        #  self.dom_changed_event = asyncio.Event()
        self.ifinfo = None
        self.port_dev = None
        self.mac_address = ""
        self.ip = ''
        self.fs = None
        self.filter_binding = None

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
            l.error(f'exception occurred: {err}')
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
        self._run_script(s, self.bot_file, bot_dir, dst, self.bot_repo_ip,
                         self.bot_repo_user, self.bot_repo_path)

    def _get_config(self):
        return self.context.get_sandbox_config(self.arch, self.name)

    def _destroy_fs(self):
        if os.path.exists(self.fs):
            os.remove(self.fs)

    def redirect_traffic(self):
        pass

    def fetch_log(self, dst):
        s = SandboxScript.FETCH_LOG
        self._run_script(s, self.fs, dst)

    async def start(self):
        self._prepare_kernel()
        self._prepare_fs()
        sandbox_xml = self._get_config()
        l.debug("domain config:\n%s", sandbox_xml)

        self.dom = self.context.create_sandbox(sandbox_xml)
        if self.dom is None:
            l.error("create sandbox %s failed", self.name)
            return

        while True:
            if self.dom.state()[0] != libvirt.VIR_DOMAIN_RUNNING:
                l.debug("domain state %d, reason %d...", self.dom.state()[0],
                        self.dom.state()[1])
                await asyncio.sleep(5)
            else:
                break

        l.debug("domain is running")

        # set schduler info
        if self.sandbox_vcpu_quota > 100:
            self.sandbox_vcpu_quota = 100
        period = 1000000
        quota = int(period * (self.sandbox_vcpu_quota / 100.0))

        params = {
            libvirt.VIR_DOMAIN_SCHEDULER_VCPU_PERIOD: period,
            libvirt.VIR_DOMAIN_SCHEDULER_VCPU_QUOTA: quota
        }

        l.debug(f'domain scheduler params:\n{params}')
        self.dom.setSchedulerParametersFlags(params, libvirt.VIR_DOMAIN_AFFECT_LIVE)
        l.debug(f'domain scheduler params set')

        # wait for interface info
        ifaces = self.dom.interfaceAddresses(libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE)
        while len(ifaces) == 0:
            l.debug("sleep 2 secs for interface info...")
            await asyncio.sleep(2)
            ifaces = self.dom.interfaceAddresses(libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE)

        l.debug("interfaces are:")
        for k, v in ifaces.items():
            l.debug(f"{k}: {v}")

        self.port_dev = list(ifaces.keys())[0]
        self.mac_address = ifaces[self.port_dev]['hwaddr']
        self.ip = ifaces[self.port_dev]['addrs'][0]['addr']
        l.debug("get port_dev %s, mac_address: %s, ip: %s", self.port_dev,
                self.mac_address, self.ip)

        l.debug(f"domain started {self.name}")


    # TODO: replace with asyncio
    def get_ifinfo(self):
       return (self.port_dev, self.mac_address, self.ip)

    def apply_nwfilter(self, filter_name, **kwargs):
        if self.filter_binding:
            self.filter_binding.delete()
            self.filter_binding = None

        l.debug(f'filter: {filter_name},kwargs: {kwargs}')
        self.filter_binding = self.context.apply_nwfilter(filter_name,
                                                          port_dev=self.port_dev,
                                                          mac_addr=self.mac_address,
                                                          mal_repo_ip=self.bot_repo_ip,
                                                          sandbox_ip=self.ip,
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
