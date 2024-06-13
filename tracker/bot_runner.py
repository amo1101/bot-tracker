import asyncio
import os
from db_store import *
from packet_capture import *
from sandbox import Sandbox
from sandbox_context import SandboxNWFilter
from iface_monitor import IfaceMonitor
from analyzer_executor import *

l: TaskLogger = TaskLogger(__name__)
CUR_DIR = os.path.dirname(os.path.abspath(__file__))


class BotRunner:
    # use process pool for packet analyzing
    analyzer_executor_pool = None

    def __init__(self, bot_info,
                 bot_repo_ip, bot_repo_user, bot_repo_path,
                 sandbox_vcpu_quota,
                 cnc_probing_duration, sandbox_ctx, db_store,
                 max_analyzing_workers,
                 iface_monitor):

        if BotRunner.analyzer_executor_pool is None:
            BotRunner.analyzer_executor_pool = \
                AnalyzerExecutorPool(max_analyzing_workers)
            l.info('Initialized analyzer executor with %d workers',
                    max_analyzing_workers)

        self.bot_info = bot_info
        self.bot_repo_ip = bot_repo_ip
        self.bot_repo_user = bot_repo_user
        self.bot_repo_path = bot_repo_path
        self.sandbox_vcpu_quota = sandbox_vcpu_quota
        self.sandbox_ctx = sandbox_ctx
        self.db_store = db_store
        self.sandbox = None
        self.live_capture = None
        self.log_base = CUR_DIR + os.sep + "log"
        self.log_dir = self.log_base + os.sep + bot_info.tag
        self.cnc_info = []
        self.cnc_probing_time = cnc_probing_duration
        self.notify_unstage = False
        self.notify_error = False
        self.notify_dup = False
        self.dormant_time = INIT_TIME_STAMP
        self.staged_time = INIT_TIME_STAMP
        self.destroyed = False
        self.iface_monitor = iface_monitor
        self.excutor_id = None
        self.cnc_analyzer_id = None
        self.attack_analyzer_id = None

    def _create_log_dir(self):
        if not os.path.exists(self.log_base):
            os.makedirs(self.log_base)
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

    def _init_capture(self, port_dev):
        if self.live_capture is None:
            iface = port_dev
            bpf_filter = "not stp and not arp" # filter out background traffic
            output_file = self.log_dir + os.sep + "capture.pcap"
            self.live_capture = AsyncLiveCapture(interface=iface,
                                                 bpf_filter=bpf_filter,
                                                 output_file=output_file,
                                                 debug=False)

    async def _find_cnc(self, own_ip, excluded_ips):
        # init cnc analyzer
        self.cnc_analyzer_id = await BotRunner.analyzer_executor_pool.init_analyzer(self.excutor_id,
                                                                                    AnalyzerType.ANALYZER_CNC,
                                                                                    own_ip=own_ip,
                                                                                    excluded_ips=excluded_ips,
                                                                                    excluded_ports=None)

        try:
            async for packet in self.live_capture.sniff_continuously():
                #  l.debug(f'packet arrives:\n{packet}')
                l.debug(f'cnc report before: {repr(self.cnc_analyzer.report)}')
                await BotRunner.analyzer_executor_pool.analyze_packet(self.excutor_id,
                                                                      self.cnc_analyzer_id,
                                                                      packet)
                l.debug(f'cnc report after: {repr(self.cnc_analyzer.report)}')
        # let the caller handle all the exceptions
        finally:
            l.debug('_find_cnc finalized')
            pass

    async def _find_cnc_task(self, own_ip, excluded_ips):
        task = asyncio.create_task(self._find_cnc(own_ip, excluded_ips),
                                   name=f"t_find_cnc_{self.bot_info.tag}")
        await task

    # TODO: now only monitor cnc status, will add online attack monitoring
    async def update_attack_report(self):
        report = await BotRunner.analyzer_executor_pool.get_result(self.excutor_id,
                                                                   self.attack_analyzer_id)
        l.debug(f"Get attack report: {report}")

        # update cnc report
        if report['cnc_ready'] is True:
            cnc_status = report['cnc_status']
            if cnc_status == CnCStatus.ALIVE.value:
                await self.update_bot_info(BotStatus.ACTIVE)
            elif cnc_status == CnCStatus.DISCONNECTED.value:
                await self.update_bot_info(BotStatus.DORMANT)

            cnc_stat = CnCStat(report['cnc_ip'], report['cnc_port'],
                               self.bot_info.bot_id, cnc_status,
                               report['cnc_update_at'])
            await self.db_store.add_cnc_stat(cnc_stat)

        # update attack report
        for _, rl in report['attacks'].items():
            for r in rl:
                attack_stat = AttackStat(self.bot_info.bot_id,
                                         self.cnc_info[0].ip,
                                         r['attack_type'],
                                         r['start_time'],
                                         r['duration'],
                                         r['target'],
                                         r['protocol'],
                                         r['src_port'],
                                         r['dst_port'],
                                         r['packet_cnt'],
                                         r['total_bytes'])
                await self.db_store.add_attack_stat(attack_stat)

    async def _observe_attack(self, cnc_ip, cnc_port, own_ip):
        # init attack analyzer
        self.attack_analyzer_id = await BotRunner.analyzer_executor_pool.init_analyzer(self.excutor_id,
                                                                                       AnalyzerType.ANALYZER_ATTACK,
                                                                                       cnc_ip=cnc_ip,
                                                                                       cnc_port=cnc_port,
                                                                                       own_ip=own_ip)

        try:
            async for packet in self.live_capture.sniff_continuously():
                #  l.debug(f'packet arrives:\n{packet}')
                l.debug(f'cnc report before: {repr(self.cnc_analyzer.report)}')
                await BotRunner.analyzer_executor_pool.analyze_packet(self.excutor_id,
                                                                      self.attack_analyzer_id,
                                                                      packet)
                l.debug(f'cnc report after: {repr(self.cnc_analyzer.report)}')
        # let the caller handle all the exceptions
        finally:
            l.debug('_find_cnc finalized')
            pass

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
            self.bot_info.observe_duration = self.observe_duration()
            if self.bot_info.status == BotStatus.DORMANT.value:
                self.bot_info.dormant_duration = self.dormant_duration()

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
                                   self.bot_info.arch_spec,
                                   self.bot_repo_ip,
                                   self.bot_repo_user,
                                   self.bot_repo_path)
            await self.sandbox.start()

            # transit status to staged
            await self.update_bot_info(BotStatus.STAGED)

            port_dev, mac, own_ip = self.sandbox.get_ifinfo()
            self._init_capture(port_dev)

            # set default nwfiter
            self.sandbox.apply_nwfilter(self.sandbox_ctx.default_nwfilter)

            # open packet executor
            self.executor_id = BotRunner.analyzer_executor_pool.open_executor()

            # find cnc server
            try:
                await asyncio.wait_for(self._find_cnc_task(own_ip, [self.bot_repo_ip]),
                                       timeout=self.cnc_probing_time)
            except asyncio.TimeoutError:
                l.warning("Cnc probing timeout...")
                cnc_info = await BotRunner.analyzer_executor_pool.get_result(self.excutor_id,
                                                                             self.cnc_analyzer_id)
                k, v = next(iter(cnc_info.items())) # should have only one key
                ip_port = k.split(':')
                domain = ''
                if 'DNS_Name' in v:
                    domain = v['DNS_Name']

                # TODO: skip asn and location here
                # we can support multiple CnCs, but now only use 1
                self.cnc_info.append(CnCInfo(ip_port[0], int(ip_port[1]),
                                             self.bot_info.bot_id, domain, 0, ''))
                l.info(f"Find CnC:{ip_port[0]}:{ip_port[1]}")

                # check if this cnc already exist for this bot in previous
                # measurement, only insert if new CnC is found
                cnc_info_in_db = await self.db_store.load_cnc_info(None,
                                                                   self.cnc_info[0].ip,
                                                                   self.cnc_info[0].port)
                cnc_dup = False
                for cnc in cnc_info_in_db:
                    if cnc.bot_id != self.bot_info.bot_id:
                        l.warning(f'Bot already exists for the botnet!')
                        self.notify_dup = True;
                        await self.destroy()
                        return
                    else:
                        l.warning(f'This is a previous discovered CnC server!')
                        cnc_dup = True

                # newly discovered cnc server
                if not cnc_dup:
                    l.warning(f'This is a newly discovered CnC server!')
                    await self.db_store.add_cnc_info(self.cnc_info[0])

            if self.cnc_info is None or len(self.cnc_info) == 0:
                l.warning("Cnc not find, stop bot runner...")
                self.notify_error = True
                await self.destroy()
                return

            # register to iface_monitor
            await self.iface_monitor.register(self.cnc_info[0].ip,
                                              self.bot_info.tag)

            # enforce nwfilter
            nwfilter_type = self.sandbox_ctx.cnc_nwfilter
            args = {"cnc_ip": self.cnc_info[0].ip}
            self.sandbox.apply_nwfilter(nwfilter_type, **args)

            # redirect traffic to simulated server in block network mode
            self.sandbox.redirect_traffic('ON', self.cnc_info[0].ip)

            # Set bot status to dormant before we observe CnC communication
            await self.update_bot_info(BotStatus.DORMANT)

            # observer attacks
            await self._observe_attack(self.cnc_info[0].ip,
                                       self.cnc_info[0].port,
                                       own_ip)

        except asyncio.CancelledError:
            l.warning("Bot runner cancelled")
            await self.destroy()

    async def destroy(self):
        try:
            if self.destroyed:
                l.debug("Bot runner has been destroyed")
                return

            l.info("Bot runner destroyed")
            await self.update_bot_info(BotStatus.INTERRUPTED)
            str_start_time = self.staged_time.strftime('%Y-%m-%d-%H-%M-%S')
            str_end_time = datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
            self.sandbox.fetch_log(self.log_dir, str_start_time, str_end_time)

            # turn off traffic redirection
            if self.cnc_info is not None and len(self.cnc_info) > 0:
                self.sandbox.redirect_traffic('OFF', self.cnc_info[0].ip)
                await self.iface_monitor.unregister(self.cnc_info[0].ip)

            self.sandbox.destroy()

            # close all analyzer and executor
            await BotRunner.analyzer_executor_pool.finalize_analyzer(self.excutor_id,
                                                                     self.cnc_analyzer_id)
            await BotRunner.analyzer_executor_pool.finalize_analyzer(self.excutor_id,
                                                                     self.attack_analyzer_id)
            BotRunner.analyzer_executor_pool.close_executor(self.excutor_id)

            if self.live_capture is not None:
                await self.live_capture.close_async()
            self.destroyed = True
        except RuntimeError:
            l.debug('Runtime error occurred')
        except asyncio.CancelledError:
            l.debug('Cancelled error occurred')
        finally:
            pass

    def is_destroyed(self):
        return self.destroyed
