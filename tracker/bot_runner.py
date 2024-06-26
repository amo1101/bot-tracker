import asyncio

import os
from db_store import *
from packet_capture import *
from sandbox import Sandbox
from sandbox_context import *
from iface_monitor import IfaceMonitor
from analyzer_executor import *

l: TaskLogger = TaskLogger(__name__)
CUR_DIR = os.path.dirname(os.path.abspath(__file__))


class BotRunner:
    def __init__(self, bot_info,
                 bot_repo_ip, bot_repo_user, bot_repo_path,
                 sandbox_vcpu_quota,
                 cnc_probing_duration, sandbox_ctx, db_store,
                 analyzer_pool,
                 enable_attack_detection,
                 attack_gap,
                 min_attack_packets,
                 iface_monitor):

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
        self.cnc_stats_file = self.log_dir + os.sep + 'cnc_stats.log'
        self.cnc_info = []
        self.cnc_probing_time = cnc_probing_duration
        self.notify_unstage = False
        self.notify_error = False
        self.notify_dup = False
        self.dormant_time = INIT_TIME_STAMP
        self.staged_time = INIT_TIME_STAMP
        self.last_observe_duration = bot_info.observe_duration  # accumulate observe duration
        self.last_dormant_duration = bot_info.dormant_duration  # accumulate dormant duration
        self.destroyed = False
        self.iface_monitor = iface_monitor
        self.analyzer_pool = analyzer_pool
        self.enable_attack_detection = enable_attack_detection
        self.attack_gap = attack_gap
        self.min_attack_packets = min_attack_packets
        self.executor_id = None
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
            bpf_filter = "not stp and not arp"  # filter out background traffic
            output_file = self.log_dir + os.sep + "capture.pcap"
            self.live_capture = AsyncLiveCapture(interface=iface,
                                                 bpf_filter=bpf_filter,
                                                 output_file=output_file,
                                                 debug=False)

    async def _find_cnc(self, own_ip, excluded_ips):
        try:
            # init cnc analyzer
            l.info(f'cnc analyzer initializing at: {self.executor_id}')
            self.cnc_analyzer_id = await self.analyzer_pool.init_analyzer(self.executor_id,
                                                                          AnalyzerType.ANALYZER_CNC,
                                                                          own_ip=own_ip,
                                                                          excluded_ips=excluded_ips,
                                                                          excluded_ports=None)
            l.info(f'cnc analyzer initialized: {self.cnc_analyzer_id}')
            async for packet in self.live_capture.sniff_continuously():
                await self.analyzer_pool.analyze_packet(self.executor_id,
                                                        self.cnc_analyzer_id,
                                                        packet)
        # let the caller handle all the exceptions
        finally:
            l.debug('_find_cnc finalized')
            pass

    async def _find_cnc_task(self, own_ip, excluded_ips):
        task = asyncio.create_task(self._find_cnc(own_ip, excluded_ips),
                                   name=f"t_find_cnc_{self.bot_info.tag}")
        await task

    async def handle_attack_report(self, flush=False):
        if self.attack_analyzer_id is None:
            return

        report = await self.analyzer_pool.get_result(self.executor_id,
                                                     self.attack_analyzer_id,
                                                     flush)
        l.debug(f"Get attack report: {report}")

        # update cnc status
        cnc_report = report['cnc_status']
        if len(cnc_report) > 0:
            if cnc_report['ready']:
                cnc_status = cnc_report['cnc_status']
                if cnc_status == CnCStatus.ALIVE.value:
                    await self.update_bot_info(BotStatus.ACTIVE)
                elif cnc_status == CnCStatus.DISCONNECTED.value:
                    await self.update_bot_info(BotStatus.DORMANT)

        # update attack report
        for r in report['attacks']:
            total_packets = r['packet_cnt']
            total_bytes = r['total_bytes']
            total_secs = r['duration'].total_seconds()
            pps = total_packets / total_secs
            bandwidth = total_bytes / total_secs
            attack_info = AttackInfo(self.bot_info.bot_id,
                                     cnc_report['cnc_ip'],
                                     r['attack_type'],
                                     r['start_time'],
                                     r['duration'],
                                     r['target'],
                                     r['protocol'],
                                     r['src_port'],
                                     r['dst_port'],
                                     r['spoofed'],
                                     total_packets,
                                     total_bytes,
                                     pps,
                                     bandwidth)
            await self.db_store.add_attack_info(attack_info)
            l.debug(f'attack inserted: {attack_info}')

    async def _observe_attack(self, cnc_ip_ports, own_ip):
        try:
            # init attack analyzer
            excluded_ips = [self.sandbox_ctx.dns_server, self.bot_repo_ip]
            l.info(f'attack analyzer initializing at: {self.executor_id}')
            self.attack_analyzer_id = await self.analyzer_pool.init_analyzer(self.executor_id,
                                                                             AnalyzerType.ANALYZER_ATTACK,
                                                                             cnc_ip_ports=cnc_ip_ports,
                                                                             own_ip=own_ip,
                                                                             excluded_ips=excluded_ips,
                                                                             enable_attack_detection=self.enable_attack_detection,
                                                                             attack_gap=self.attack_gap,
                                                                             min_attack_packets=self.min_attack_packets)
            l.info(f'attack analyzer initialized as: {self.attack_analyzer_id}')

            async for packet in self.live_capture.sniff_continuously():
                report_formed = await self.analyzer_pool.analyze_packet(self.executor_id,
                                                                        self.attack_analyzer_id,
                                                                        packet)
                if report_formed:
                    await self.handle_attack_report()
        finally:
            # flush and get the final report
            l.info('stopping observing attack...')
            await self.handle_attack_report(True)

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
            self.bot_info.observe_duration += self.last_observe_duration
            if self.bot_info.status == BotStatus.DORMANT.value:
                self.bot_info.dormant_duration = self.dormant_duration()
                self.bot_info.dormant_duration += self.last_dormant_duration

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
            self.last_dormant_duration = INIT_INTERVAL

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

            #  open packet executor
            self.executor_id = self.analyzer_pool.open_executor()

            # find cnc server
            try:
                await asyncio.wait_for(self._find_cnc_task(own_ip, [self.bot_repo_ip]),
                                       timeout=self.cnc_probing_time)
            except asyncio.TimeoutError:
                l.warning("Cnc probing timeout...")
                cnc_info = await self.analyzer_pool.get_result(self.executor_id,
                                                               self.cnc_analyzer_id)
                l.info(f"get cnc info {cnc_info}...")

                await self.analyzer_pool.finalize_analyzer(self.executor_id,
                                                           self.cnc_analyzer_id)
                self.cnc_analyzer_id = None

                cnc_dup = False
                if cnc_info is not None and len(cnc_info) > 0:
                    for ci in cnc_info:
                        k, v = ci  # should be a tuple of (ip_port: {})
                        ip_port = k.split(':')
                        if len(ip_port) < 2:
                            l.error(f'invalid ip:port format {k}')
                            continue

                        domain = ''
                        if 'DNS_Name' in v:
                            domain = v['DNS_Name']

                        # check if this cnc already exists for this bot in previous
                        # measurement, only insert if new CnC is found
                        cnc_info_in_db = await self.db_store.load_cnc_info(None,
                                                                           ip_port[0],
                                                                           int(ip_port[1]))
                        cnc_old = False
                        for cnc in cnc_info_in_db:
                            if cnc.bot_id != self.bot_info.bot_id:
                                l.warning(f'Bot already exists for the botnet!')
                                cnc_dup = True
                            else:
                                cnc_dup = False
                                cnc_old = True

                        if not cnc_dup:
                            self.cnc_info.append(CnCInfo(ip_port[0], int(ip_port[1]),
                                                 self.bot_info.bot_id, domain, 0, ''))
                            l.info(f"Find CnC:{ip_port[0]}:{ip_port[1]}")

                            if not cnc_old:
                                l.warning(f'This is a newly discovered CnC server!')
                                await self.db_store.add_cnc_info(self.cnc_info[-1])
                            else:
                                l.warning(f'This is a previous discovered CnC server!')

                if cnc_dup and len(self.cnc_info) == 0:
                    self.notify_dup = True
                    await self.destroy()
                    return

            if len(self.cnc_info) == 0:
                l.warning("Cnc not found, stop bot runner...")
                self.notify_error = True
                await self.destroy()
                return

            # register to iface_monitor
            for ci in self.cnc_info:
                await self.iface_monitor.register(ci.ip, self.bot_info.tag)

            # enforce nwfilter
            nwfilter_type = self.sandbox_ctx.cnc_nwfilter
            cnc_ips = [c.ip for c in self.cnc_info]
            cnc_ip_ports = [(c.ip, c.port) for c in self.cnc_info]
            args = {"cnc_ip": cnc_ips}
            self.sandbox.apply_nwfilter(nwfilter_type, **args)

            # exclude redirecting cnc traffic to simulated server in block network mode
            self.sandbox.redirectx_traffic('ON', cnc_ip_ports)

            # Set bot status to dormant before we observe CnC communication
            await self.update_bot_info(BotStatus.DORMANT)

            # observer attacks
            await self._observe_attack(cnc_ip_ports,
                                       own_ip)

        except asyncio.CancelledError:
            l.warning("Bot runner cancelled")
        except BaseException as e:
            l.error(f"An error occured {e}")
        finally:
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
            cnc_ip_ports = [(c.ip, c.port) for c in self.cnc_info]
            self.sandbox.redirectx_traffic('OFF', cnc_ip_ports)
            for ci in self.cnc_info:
                await self.iface_monitor.unregister(ci.ip)

            self.sandbox.destroy()

            # close all analyzer and executor
            if self.cnc_analyzer_id is not None:
                await self.analyzer_pool.finalize_analyzer(self.executor_id,
                                                           self.cnc_analyzer_id)
                self.cnc_analyzer_id = None
            if self.attack_analyzer_id is not None:
                await self.analyzer_pool.finalize_analyzer(self.executor_id,
                                                           self.attack_analyzer_id)
                self.attack_analyzer_id = None
            self.analyzer_pool.close_executor(self.executor_id)

            if self.live_capture is not None:
                await self.live_capture.close_async()
            self.destroyed = True
        except asyncio.CancelledError:
            l.debug('Cancelled error occurred')
        except BaseException as e:
            l.debug(f'An error occurred {e}')
        finally:
            pass

    def is_destroyed(self):
        return self.destroyed
