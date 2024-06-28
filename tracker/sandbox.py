import asyncio
import shutil
from sandbox_context import *

l: TaskLogger = TaskLogger(__name__)


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
        return self.context.run_script(which, *args)

    def _prepare_fs(self):
        src, dst = self.context.get_sandbox_fs(self.arch, self.name)
        l.debug("fs src %s, dst %s", src, dst)

        self.fs = dst
        if not os.path.exists(dst):
            shutil.copyfile(src, dst)

        # copy bot directory to sandbox fs
        bot_dir = self.context.bot_dir
        dns_server = self.context.dns_server
        s = SandboxScript.PREPARE_FS
        self._run_script(s, self.bot_file, bot_dir, dst, self.bot_repo_ip,
                         self.bot_repo_user, self.bot_repo_path,
                         dns_server)

    def _get_config(self):
        return self.context.get_sandbox_config(self.arch, self.name)

    def _destroy_fs(self):
        if os.path.exists(self.fs):
            os.remove(self.fs)

    def redirectx_traffic(self, switch, cnc_ip_ports):
        if self.context.network_mode == NetworkMode.BLOCK.value:
            s = SandboxScript.REDIRECTX
            cnc_ips = set()
            redirected = self.context.redirected_tcp_ports.split(',')
            for ip, port in cnc_ip_ports:
                if port in redirected:
                    cnc_ips.add(ip)
            if len(cnc_ips) > 0:
                all_ips = ','.join(cnc_ips)
                self._run_script(s, switch, all_ips)

    def fetch_log(self, dst, start_time, end_time):
        s = SandboxScript.FETCH_LOG
        self._run_script(s, self.fs, dst, start_time, end_time)

    async def start(self):
        self._prepare_kernel()
        self._prepare_fs()
        sandbox_xml = self._get_config()
        l.info("domain config:\n%s", sandbox_xml)

        self.dom = self.context.create_sandbox(sandbox_xml)
        if self.dom is None:
            l.error("Create sandbox %s failed", self.name)
            return

        while True:
            if self.dom.state()[0] != libvirt.VIR_DOMAIN_RUNNING:
                l.debug("domain state %d, reason %d...", self.dom.state()[0],
                        self.dom.state()[1])
                await asyncio.sleep(1)
            else:
                break

        # wait for interface info
        ifaces = self.dom.interfaceAddresses(libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE)
        retry = 0
        while len(ifaces) == 0:
            if retry % 6 == 0:
                retry += 1
                l.info("waiting for interface info...")
            await asyncio.sleep(0.5)
            ifaces = self.dom.interfaceAddresses(libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE)

        l.debug("interfaces are:")
        for k, v in ifaces.items():
            l.debug(f"{k}: {v}")

        self.port_dev = list(ifaces.keys())[0]
        self.mac_address = ifaces[self.port_dev]['hwaddr']
        self.ip = ifaces[self.port_dev]['addrs'][0]['addr']
        l.debug("get port_dev %s, mac_address: %s, ip: %s", self.port_dev,
                self.mac_address, self.ip)

        # set scheduler info
        if self.sandbox_vcpu_quota > 100:
            self.sandbox_vcpu_quota = 100
        period = 1000000
        quota = int(period * (self.sandbox_vcpu_quota / 100.0))

        params = {
            libvirt.VIR_DOMAIN_SCHEDULER_VCPU_PERIOD: period,
            libvirt.VIR_DOMAIN_SCHEDULER_VCPU_QUOTA: quota
        }

        l.debug(f'domain scheduler params:\n{params}')
        self.dom.setSchedulerParametersFlags(params,
                                             libvirt.VIR_DOMAIN_AFFECT_CURRENT)
        l.debug(f'domain scheduler params set')

        sandbox_info = f"name: {self.name}, vcpu quota:{self.sandbox_vcpu_quota}, " + \
                       f"arch: {self.arch}, interface: {self.port_dev, self.mac_address, self.ip}"
        l.info(f"Sandbox started: {sandbox_info}")

    def get_ifinfo(self):
        return self.port_dev, self.mac_address, self.ip

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
            l.error("Failed to apply nw filter")
            return False

        l.info("Filter %s is applied", filter_name.value)
        return True

    def destroy(self):
        self._destroy_fs()
        self.dom.destroy()
        l.info("Sandbox destroyed %s", self.name)
        if self.filter_binding:
            l.info("delete filter binding...")
            self.filter_binding.delete()
