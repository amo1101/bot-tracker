import asyncio
import libvirt
import libvirtaio
import os
import sys
import signal
from log import TaskLogger
from datetime import datetime, timedelta
#  from aiomultiprocess import Pool
from concurrent.futures import ProcessPoolExecutor
from cnc_analyzer import *
from attack_analyzer import *
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
        self.cnc_analzyer = None
        self.attack_analzyer = None
        self.live_capture = None
        self.log_base = CUR_DIR + os.sep + "log"
        self.log_dir = self.log_base + os.sep + bot_info.tag
        self.cnc_info = None
        self.cnc_probing_time = 30
        self.conn_limit = 10
        self.mal_repo_ip = "127.0.0.1"
        self.scan_ports = "23"  #TODO
        self.start_time = None
        self.notify_unstage = False
        self.notify_error = False
        self.notify_duplicate = False
        self.dormant_time = INIT_TIME_STAMP
        self.staged_time = INIT_TIME_STAMP

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

    async def _find_cnc(self, own_ip):
        # check if cnc already exist
        # TODO: maybe we should use (ip: port) to identify a unique CnC?
        self.cnc_info = await self.db_store.load_cnc_info(self.bot_info.bot_id)
        if len(self.cnc_info) > 0:
            l.debug('CnC already exist.')
            return

        if self.cnc_analzyer is None:
            self.cnc_analzyer = CnCAnalyzer(own_ip)

        loop = asyncio.get_running_loop()
        try:
            async for packet in self.live_capture.sniff_continuously():
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
        l.debug(f"get cnc status report: {report}")
        attack_time = datetime.now()
        if cnc_status == BotStatus.ACTIVE.value:
            await self.update_bot_info(BotStatus.ACTIVE)
        elif cnc_status == BotStatus.DISCONNECTED.value:
            await self.update_bot_info(BotStatus.DORMANT)

        cnc_stat = CnCStat(report['cnc_ip'], cnc_status, attack_time)
        await db_store.add_cnc_stat(cnc_stat)

    async def _observe_attack(self, cnc_ip, cnc_port, own_ip):
        if self.attack_analzyer is None:
            self.attack_analzyer = AttackAnalyzer(cnc_ip, cnc_port, own_ip)

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
        if self.dormant_time == INIT_TIME_STAMP:
            return INIT_INTERVAL
        return datetime.now() - self.dormant_time

    def observe_duration(self):
        if self.staged_time == INIT_TIME_STAMP:
            return INIT_INTERVAL
        return datetime.now() - self.staged_time

    def notify_unstage(self):
        self.notify_unstage_= True

    def notify_error(self):
        self.notify_error = True

    def notify_dup(self):
        self.notify_dup = True

    async def update_bot_info(self, status=None):
        if status is None:
            # merely update timing info
            self.bot_info.observe_duration += self.observe_duration()
            if self.bot_info.status == BotStatus.DORMANT.value:
                self.bot_info.dormant_duration += self.dormant_duration()

        if status == BotStatus.STAGED:
            self.bot_info.status = BotStatus.STAGED.value
            self.staged_time = datetime.now()
            self.bot_info.observe_at = self.staged_time

        if status == BotStatus.DORMANT:
            self.bot_info.status = BotStatus.DORMANT.value
            self.dormant_time = datetime.now()
            self.bot_info.dormant_at = self.dormant_time

        if status == BotStatus.ACTIVE:
            self.bot_info.status = BotStatus.ACTIVE.value
            self.dormant_time = INIT_TIME_STAMP
            self.bot_info.dormant_at = INIT_TIME_STAMP
            self.bot_info.dormant_duration = INIT_INTERVAL

        if status == BotStatus.INTERRUPTED:
            if self.notify_unstage == True:
                # Finish observing
                self.bot_info.status = BotStatus.UNSTAGED.value
            elif self.notify_error == True:
                # Error occured 
                self.bot_info.status = BotStatus.ERROR.value
            elif self.notify_dup == True:
                # Duplicated
                self.bot_info.status = BotStatus.DUPLICATE.value
            else:
                # Interrupted
                self.bot_info.status = BotStatus.INTERRUPTED.value

        await db_store.update_bot_info(self.bot_info)

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
            l.debug(f'Bot runner {self.bot_info.tag} started')
            self._create_log_dir()
            self.sandbox = Sandbox(self.sandbox_ctx, self.bot_info.tag,
                                   self.bot_info.file_name,
                                   self.bot_info.arch) #TODO: map arch
            self.sandbox.start()

            # transit status to staged
            await self.update_bot_info(BotStatus.STAGED)

            _, mac_addr, own_ip = self.sandbox.get_ifinfo()

            # set default nwfiter
            self.sandbox.apply_nwfilter(SandboxNWFilter.DEFAULT,
                                        mal_repo_ip=self.mal_repo_ip)
            self._init_capture(mac_addr)

            # find cnc server
            try:
                await asyncio.wait_for(self._find_cnc(own_ip),
                                       timeout=self.cnc_probing_time)
            except asyncio.TimeoutError:
                l.warning("Cnc probing timeout...")
                if self.cnc_analzyer.report.is_ready():
                    cnc_info = self.cnc_analzyer.report.get()
                    ip_port = cnc_info[0].split(':')
                    # TODO: skip asn and location here
                    # TODO: we can support multiple CnCs, but now only use 1
                    self.cnc_info.append(CnCInfo(ip_port[0], ip_port[1],
                                                 self.bot_info.bot_id, 0, ''))
                    l.debug(f"Find CnC:{ip_port[0]}:{ip_port[1]}")

                    # Check if CnC already existed
                    exists = await db_store.cnc_exist(ip_port[0])
                    if exists:
                        self.notify_dup()
                        self.destroy()
                        return

                    await db_store.add_cnc_info(cnc_info)
                else:
                    l.warning("Cnc not find, stop bot runner...")
                    self.notify_error()
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

            # Set bot status to dormant before we observer CnC communication
            await self.update_bot_info(BotStatus.DORMANT)

            # observer attacks
            await self._observe_attack(self.cnc_info.ip,
                                       self.cnc_info.port,
                                       own_ip)

        except asyncio.CancelledError:
            l.debug("Bot runner cancelled")
            #  raise asyncio.CancelledError
            await self.destroy()
            #  await self.destroy()

    async def destroy(self):
        try:
            l.debug("Bot runner destroyed")
            await self.update_bot_info(BotStatus.INTERRUPTED)
            self.sanbox.fetch_log(self.log_dir)
            self.sandbox.destroy()
            await self.live_capture.close_async()
        except RuntimeError:
            l.debug('runtime error occured')
        except asyncio.CancelledError:
            l.debug('cancelled error occure')
        finally:
            pass

