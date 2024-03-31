import asyncio
import libvirt
import libvirtaio
import os
import sys
import signal
from log import TaskLogger
from datetime import datetime
#  from aiomultiprocess import Pool
from concurrent.futures import ProcessPoolExecutor
from packet_analyzer import *
from packet_capture import *
from sandbox import Sandbox
from sandbox_context import SandboxNWFilter, SandboxContext

l = TaskLogger(__name__)

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
DB_MODULE_DIR = os.path.dirname(CUR_DIR) + os.sep + 'db'
sys.path.append(DB_MODULE_DIR)
from db_store import *


def init_worker():
    # suppress SIGINT in worker proecess to cleanly reclaim resource only by
    # main process
    l.debug('ProcessPoolExecutor initialized')
    signal.signal(signal.SIGINT, signal.SIG_IGN)

class BotRunner:

    # use process pool for packet analyzing
    analyzer_executor = ProcessPoolExecutor(max_workers=1,
                                            initializer=init_worker)

    def __init__(self, bot_info, sandbox_ctx, db_store):
        self.bot_info = bot_info
        self.sandbox_ctx = sandbox_ctx
        self.db_store = db_store
        self.sandbox = None
        self.cnc_analzyer = CnCAnalyzer()
        self.attack_analzyer = None
        self.live_capture = None
        self.cnc_info = None
        self.log_base = CUR_DIR + os.sep + "log"
        self.log_dir = self.log_base + os.sep + bot_info.name
        self.cnc_probing_time = 5
        self.conn_limit = 10
        self.mal_repo_ip = "127.0.0.1"
        self.scan_ports = "23"  #TODO
        self.start_time = None
        self.dormant_start_time = None
        self.observe_start_time = None

    def _create_log_dir(self):
        if not os.path.exists(self.log_base):
            os.makedirs(self.log_base)
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

    def _init_capture(self, mac_addr):
        if self.live_capture is None:
            iface = "virbr1" #TODO: should be fetched from context
            bpf_filter = f"ether src {mac_addr} or ether dst {mac_addr}"
            output_file = self.log_dir + os.sep + "capture.pcap"
            self.live_capture = AsyncLiveCapture(interface=iface,
                                                 bpf_filter=bpf_filter,
                                                 output_file=output_file,
                                                 debug=False)

    async def _find_cnc(self):
        loop = asyncio.get_running_loop()
        try:
            async for packet in self.live_capture.sniff_continuously():
                pass
                self.cnc_analzyer.report = await loop.run_in_executor(BotRunner.analyzer_executor,
                                           self.cnc_analzyer.analyze,
                                           packet)
        # let the caller handle all the exceptions
        finally:
            l.debug('_find_cnc finalized')
            pass

    # TODO: now only monitor cnc status
    async def _handle_attack_report(self, report):
        cnc_status = report['cnc_status']
        if cnc_status == BotStatus.ACTIVE.value:
            self.bot_info.dormant_duration = 0
        elif cnc_status == BotStatus.DISCONNECTED.value:
            self.bot_info.dormant_start_time = datetime.now()
        await db_store.update_bot_info(self.bot_info)

    async def _observe_attack(self):
        if self.attack_analzyer is None:
            self.attack_analzyer = AttackAnalyzer(self.cnc_analzyer.report)

        loop = asyncio.get_running_loop()
        try:
            async for packet in self.live_capture.sniff_continuously():
                self.attack_analzyer.report = await loop.run_in_executor(BotRunner.analyzer_executor,
                                              self.attack_analzyer.analyze,
                                              packet)
                if self.attack_analzyer.report.is_ready():
                    await self._handle_attack_report(self.attack_analzyer.report.get())
        finally:
            l.debug('_observe_attack finalized')
            #  pass

    def dormant_duration(self):
        return datetime.now() - self.dormant_start_time

    def observe_duration(self):
        return datetime.now() - self.observe_start_time

    async def run(self):
        try:
            #  self.start_time = datetime.now()
            #  self.dormant_start_time = datetime.now()
            #  self.observe_start_time = datetime.now()
            #  l.debug('testing packet monitoring started')
            #  self._create_log_dir()
            #  iface = 'enp0s3'
            #  output_file = self.log_dir + os.sep + "capture.pcap"
            #  self.live_capture = AsyncLiveCapture(interface=iface,
                                                 #  output_file=output_file,
                                                 #  debug=True)
            #  # find cnc server
            #  try:
                #  await asyncio.wait_for(self._find_cnc(),
                                       #  timeout=self.cnc_probing_time)
            #  except asyncio.TimeoutError:
                #  l.warning("Cnc probing timeout...")
                #  if self.cnc_analzyer.report.is_ready():
                    #  self.cnc_analzyer.report.persist()
                #  else:
                    #  l.warning("Cnc not find, stop bot runner...")
                    #  self.destroy()
                    #  return

            #  await self._observe_attack()
            #  #  return

            #TODO
            self.start_time = datetime.now()
            self.dormant_start_time = datetime.now()
            self.observe_start_time = datetime.now()

            l.debug(f'Bot runner started at {self.start_time}')
            self._create_log_dir()
            self.sandbox = Sandbox(self.sandbox_ctx, self.bot_info.sha256,
                                   self.bot_info.arch)
            self.sandbox.start()
            _, mac_addr = self.sandbox.get_ifinfo()

            # set default nwfiter
            self.sandbox.apply_nwfilter(SandboxNWFilter.DEFAULT,
                                        mal_repo_ip=self.mal_repo_ip)
            self._init_capture(mac_addr)

            # find cnc server
            try:
                await asyncio.wait_for(self._find_cnc(),
                                       timeout=self.cnc_probing_time)
            except asyncio.TimeoutError:
                l.warning("Cnc probing timeout...")
                if self.cnc_analzyer.report.is_ready():
                    self.cnc_analzyer.report.persist()
                    cnc_info = self.cnc_analzyer.report.get()
                    ip_port = cnc_info[0].split(':')
                    self.bot_info.cnc_ip = ip_port[0]
                    self.bot_info.cnc_ip = ip_port[1]
                    await db_store.update_bot_info(self.bot_info)
                else:
                    l.warning("Cnc not find, stop bot runner...")
                    self.bot_info.status = BotStatus.ERROR
                    await db_store.update_bot_info(self.bot_info)
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

        except asyncio.CancelledError:
            l.debug("Bot runner cancelled")
            #  raise asyncio.CancelledError
            await self.destroy()
            #  await self.destroy()

    async def destroy(self):
        try:
            l.debug("Bot runner destroyed")
            self.sanbox.fetch_log(self.log_dir)
            self.sandbox.destroy()
            await self.live_capture.close_async()
        except RuntimeError:
            l.debug('runtime error occured')
        except asyncio.CancelledError:
            l.debug('cancelled error occure')
        finally:
            pass

