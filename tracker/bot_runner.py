import asynciimport libvirt
import libvirtaio
import os
import sys
from functools import partial
from aiomultiprocess import Pool
import analyzer
from sandbox_context import SandboxNWFilter, SandboxContext

l = logging.getLogger(__name__)

# TODO
class BotInfo:
    def __init__(self, sha256, arch):
        self.sha256 = sha256
        self.arch = arch

class BotRunner:

    # use process pool for packet analyzing
    analyzer_pool = Pool(process=1)

    def __init__(self, bot_info, sandbox_ctx, run_base):
        self.bot_info = bot_info
        self.sandbox_ctx = sandbox_ctx
        self.sandbox = None
        self.cnc_analzyer = CnCAnalyzer()
        self.attack_analzyer = None
        self.live_capture = None
        self.cnc_info = None
        self.run_dir = run_base + os.sep + bot_info.sha256
        self.cnc_info = "192.168.1.250"
        self.conn_limit = conn_limit
        self.mal_repo_ip = "192.168.1.200"
        self.scan_ports = "23"  #TODO

    def _report_cnc(self, cnc_info):
        l.debug("cnc info: %s...", cnc_info)

    def _report_attack(self, attack_info):
        l.debug("attack info: %s...", attack_info)

    def _create_run_dir(self):
        if not os.path.exists(self.run_dir):
            os.makedirs(self.run_dir)

    def _init_capture(self, mac_addr):
        if self.live_capture is None:
            iface = "virbr1" #TODO: should be fetched from context
            filter_str = f"ether src {mac_addr} or ether dst {mac_addr}"
            out_file = self.run_dir + os.sep + "capture.pcap"
            self.live_capture = AsyncLiveCapture(interface=iface,
                                                 bpf_filter=filter_str,
                                                 output_file=out_file)

    def _destroy_capture(self):
        pass

    async def _find_cnc(self):
        async for packet in self.live_capture.sniff_continuously():
            await BotRunner.analyzer_pool.map(self.cnc_analzyer.analyze, packet)
            cnc_info = self.cnc_analzyer.get_result()
            if cnc_info is not None:
                self.cnc_info = "cnc"
                self._report_cnc(cnc_info)
                break;

    async def _observe_attack(self):
        async for packet in self.live_capture.sniff_continuously():
            await BotRunner.analyzer_pool.map(self.attack_analzyer.analyze, packet)
            attack_info = self.attack_analzyer.get_result()
            if attack_info is not None:
                self._report_attack(attack_info)

    async def run(self):
        self._create_run_dir()
        self.sandbox = Sandbox(self.sandbox_ctx, self.bot_info.sha256,
                               self.bot_info.arch)
        self.sandbox.start()
        port_dev, mac_addr = self.sandbox.get_ifinfo()

        # set default nwfiter
        self.sandbox.apply_nwfilter(SandboxNWFilter.DEFAULT,
                                    mal_repo_ip=self.mal_repo_ip)
        self._init_capture(mac_addr)

        # find cnc server
        await self._find_cnc()
        if self.cnc_info is None:
            self.destroy()
            return

        # enforce nwfilter
        nwfilter_type = SandboxNWFilter.CNC
        args = {"mal_repo_ip": self.mal_repo_ip,
                "cnc_ip": self.cnc_info}
        if self.conn_limit > 0:
            nwfilter_type = SandboxNWFilter.CONN_LIMIT
            args["conn_limit"] = str(self.conn_limit)
            args["scan_ports"] = self.scan_ports

        self.sandbox.apply_nwfilter(nwfilter_type,**args)

        # observer attacks
        await self._observe_attack()

    def destroy(self):
        self.live_capture.stop()
        self.sandbox.destroy()

