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
from db_store import *

l = TaskLogger(__name__)
CUR_DIR = os.path.dirname(os.path.abspath(__file__))


def init_worker():
    # suppress SIGINT in worker process to cleanly reclaim resource only by
    # main process
    l.debug('ProcessPoolExecutor initialized')
    signal.signal(signal.SIGINT, signal.SIG_IGN)


class BotRunner:
    # use process pool for packet analyzing
    analyzer_executor = None

    def __init__(self, bot_info,
                 bot_repo_ip, bot_repo_user, bot_repo_path,
                 sandbox_vcpu_quota,
                 cnc_probing_duration, sandbox_ctx, db_store,
                 max_analyzing_workers):

        if BotRunner.analyzer_executor == None:
            BotRunner.analyzer_executor = \
                ProcessPoolExecutor(max_workers=max_analyzing_workers,
                                    initializer=init_worker)
            l.debug('Initialized analyzer executor with %d workers',
                    max_analyzing_workers)

        self.bot_info = bot_info
        self.bot_repo_ip = bot_repo_ip
        self.bot_repo_user = bot_repo_user
        self.bot_repo_path = bot_repo_path
        self.sandbox_vcpu_quota = sandbox_vcpu_quota
        self.sandbox_ctx = sandbox_ctx
        self.db_store = db_store
        self.sandbox = None
        self.cnc_analyzer = None
        self.attack_analyzer = None
        self.live_capture = None
        self.log_base = CUR_DIR + os.sep + "log"
        self.log_dir = self.log_base + os.sep + bot_info.tag
        self.cnc_info = None
        self.cnc_probing_time = cnc_probing_duration
        self.start_time = None
        self.notify_unstage = False
        self.notify_error = False
        self.notify_dup = False
        self.dormant_time = INIT_TIME_STAMP
        self.staged_time = INIT_TIME_STAMP
        self.destroyed = False

    def _create_log_dir(self):
        if not os.path.exists(self.log_base):
            os.makedirs(self.log_base)
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

    def _init_capture(self, port_dev):
        if self.live_capture is None:
            iface = port_dev
            bpf_filter = None #f"ether src {mac_addr} or ether dst {mac_addr}"
            output_file = self.log_dir + os.sep + "capture.pcap"
            self.live_capture = AsyncLiveCapture(interface=iface,
                                                 bpf_filter=bpf_filter,
                                                 output_file=output_file,
                                                 debug=False)

    async def _find_cnc(self, own_ip, excluded_ips):
        # check if cnc already exist
        # TODO: maybe we should use (ip: port) to identify a unique CnC?
        self.cnc_info = await self.db_store.load_cnc_info(self.bot_info.bot_id)
        if len(self.cnc_info) > 0:
            l.debug('CnC already exist.')
            return

        if self.cnc_analyzer is None:
            self.cnc_analyzer = CnCAnalyzer(own_ip, excluded_ips)

        loop = asyncio.get_running_loop()
        try:
            async for packet in self.live_capture.sniff_continuously():
                #  l.debug(f'packet arrives:\n{packet}')
                l.debug(f'cnc report before:\n{repr(self.cnc_analyzer.report)}')
                self.cnc_analyzer.report = await loop.run_in_executor(BotRunner.analyzer_executor,
                                                                      self.cnc_analyzer.analyze,
                                                                      packet)
                l.debug(f'cnc report after:\n{repr(self.cnc_analyzer.report)}')
        # let the caller handle all the exceptions
        finally:
            l.debug('_find_cnc finalized')
            pass

    async def _find_cnc_task(self, own_ip, excluded_ips):
        task = asyncio.create_task(self._find_cnc(own_ip, excluded_ips),
                                   name="t_find_cnc")
        await task

    # TODO: now only monitor cnc status
    async def _handle_attack_report(self, report):
        cnc_status = report['cnc_status']
        l.debug(f"get cnc status report: {report}")
        attack_time = datetime.now()
        if cnc_status == CnCStatus.ALIVE.value:
            await self.update_bot_info(BotStatus.ACTIVE)
        elif cnc_status == CnCStatus.DISCONNECTED.value:
            await self.update_bot_info(BotStatus.DORMANT)

        cnc_stat = CnCStat(report['cnc_ip'], report['cnc_port'],
                           self.bot_info.bot_id, cnc_status, attack_time)
        await self.db_store.add_cnc_stat(cnc_stat)

    async def _observe_attack(self, cnc_ip, cnc_port, own_ip):
        if self.attack_analyzer is None:
            self.attack_analyzer = AttackAnalyzer(cnc_ip, cnc_port, own_ip)

        loop = asyncio.get_running_loop()
        try:
            async for packet in self.live_capture.sniff_continuously():
                #  l.debug(f'packet arrives:\n{packet}')
                l.debug(f'attack report before:\n{repr(self.attack_analyzer.report)}')
                self.attack_analyzer.report = await loop.run_in_executor(BotRunner.analyzer_executor,
                                                                         self.attack_analyzer.analyze,
                                                                         packet)
                if self.attack_analyzer.report.is_ready():
                    await self._handle_attack_report(self.attack_analyzer.report.get())
                else:
                    l.debug(f'attack report after:\n{repr(self.attack_analyzer.report)}')
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
            if self.notify_unstage:
                # Finish observing
                self.bot_info.status = BotStatus.UNSTAGED.value
            elif self.notify_error:
                # Error occurred
                self.bot_info.status = BotStatus.ERROR.value
            elif self.notify_dup:
                # Duplicated
                self.bot_info.status = BotStatus.DUPLICATE.value
            else:
                # Interrupted
                self.bot_info.status = BotStatus.INTERRUPTED.value

        await self.db_store.update_bot_info(self.bot_info)

    async def run(self):
        try:
            l.info('Starting bot runner...')
            self._create_log_dir()
            self.sandbox = Sandbox(self.sandbox_ctx,
                                   self.sandbox_vcpu_quota,
                                   self.bot_info.tag,
                                   self.bot_info.file_name,
                                   self.bot_info.arch,
                                   self.bot_repo_ip,
                                   self.bot_repo_user,
                                   self.bot_repo_path)  # TODO: map arch
            await self.sandbox.start()

            # transit status to staged
            await self.update_bot_info(BotStatus.STAGED)

            port_dev, _, own_ip = self.sandbox.get_ifinfo()

            # set default nwfiter
            self.sandbox.apply_nwfilter(SandboxNWFilter.DEFAULT)
            self._init_capture(port_dev)

            # find cnc server
            try:
                await asyncio.wait_for(self._find_cnc_task(own_ip, [self.bot_repo_ip]),
                                       timeout=self.cnc_probing_time)
            except asyncio.TimeoutError:
                l.warning("Cnc probing timeout...")

                if self.cnc_analyzer.report.is_ready():
                    cnc_info = self.cnc_analyzer.report.get()
                    ip_port = cnc_info[0].split(':')
                    domain = ''
                    if 'DNS_Name' in cnc_info[1]:
                        domain = cnc_info[1]['DNS_Name']

                    # TODO: skip asn and location here
                    # TODO: we can support multiple CnCs, but now only use 1
                    # TODO: domain should be fetched from cnc_info
                    self.cnc_info.append(CnCInfo(ip_port[0], int(ip_port[1]),
                                                 self.bot_info.bot_id, domain, 0, ''))
                    l.debug(f"Find CnC:{ip_port[0]}:{ip_port[1]}")

                    # Check if CnC already existed
                    #  exists = await self.db_store.cnc_exists(ip_port[0])
                    #  if exists:
                        #  self.notify_dup = True
                        #  await self.destroy()
                        #  return

                    await self.db_store.add_cnc_info(self.cnc_info[0])
                else:
                    l.warning("Cnc not find, stop bot runner...")
                    self.notify_error = True
                    await self.destroy()
                    return

            # enforce nwfilter
            nwfilter_type = SandboxNWFilter.CNC
            args = {"cnc_ip": self.cnc_info[0].ip}
            self.sandbox.apply_nwfilter(nwfilter_type, **args)

            # redirect traffic to simulated server if needed
            self.sandbox.redirect_traffic('ON', self.cnc_info[0].ip)

            # Set bot status to dormant before we observe CnC communication
            await self.update_bot_info(BotStatus.DORMANT)

            # observer attacks
            await self._observe_attack(self.cnc_info[0].ip,
                                       self.cnc_info[0].port,
                                       own_ip)

        except asyncio.CancelledError:
            l.debug("Bot runner cancelled")
            await self.destroy()

    async def destroy(self):
        try:
            if self.destroyed:
                l.debug("Bot runner has been destroyed")
                return
            l.debug("Bot runner destroyed")
            await self.update_bot_info(BotStatus.INTERRUPTED)
            self.sandbox.fetch_log(self.log_dir)

            # Turn off traffic redirection
            self.sandbox.redirect_traffic('OFF', self.cnc_info[0].ip)

            self.sandbox.destroy()
            if self.live_capture is not None:
                await self.live_capture.close_async()
            self.destroyed = True
        except RuntimeError:
            l.debug('runtime error occurred')
        except asyncio.CancelledError:
            l.debug('cancelled error occurred')
        finally:
            pass
