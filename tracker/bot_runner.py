import asyncio
import os
import traceback
import csv
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
                 sandbox_ctx, db_store,
                 analyzer_pool,
                 bpf_filter,
                 excluded_ips,
                 max_cnc_candidates,
                 min_cnc_attempts,
                 attack_gap,
                 min_attack_packets,
                 attack_detection_watermark,
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
        self.cnc_stats_log = self.log_dir + os.sep + 'cnc-stats.csv'
        self.cnc_status_log = self.log_dir + os.sep + 'cnc-status.csv'
        self.cnc_info = ('', '')
        self.cnc_candidates = []
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
        self.bpf_filter = bpf_filter
        self.excluded_ips = excluded_ips
        self.min_cnc_attempts = min_cnc_attempts
        self.max_cnc_candidates = max_cnc_candidates
        self.attack_gap = attack_gap
        self.min_attack_packets = min_attack_packets
        self.attack_detection_watermark = attack_detection_watermark
        self.executor_id = None
        self.analyzer_id = None

    @property
    def dormant_duration(self):
        if self.dormant_time == INIT_TIME_STAMP:
            return INIT_INTERVAL
        return datetime.now() - self.dormant_time

    @property
    def observe_duration(self):
        if self.staged_time == INIT_TIME_STAMP:
            return INIT_INTERVAL
        return datetime.now() - self.staged_time

    @property
    def bot_status(self):
        return self.bot_info.status

    def _create_log_dir(self):
        if not os.path.exists(self.log_base):
            os.makedirs(self.log_base)
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

    def _init_capture(self, port_dev, bpf_filter):
        if self.live_capture is None:
            iface = port_dev
            output_file = self.log_dir + os.sep + "capture.pcap"
            self.live_capture = AsyncLiveCapture(interface=iface,
                                                 bpf_filter=bpf_filter,
                                                 output_file=output_file,
                                                 debug=False)

    def _log_to_csv_file(self, csv_file, data):
        if len(data) == 0:
            return
        is_empty = os.stat(csv_file).st_size == 0 if \
                os.path.isfile(file_path) else True
        with open(self.cnc_status_log, 'a', newline='') as file:
            fieldnames = data[0].keys()
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            if is_empty:
                writer.writeheader()
            writer.writerows(data)

    async def _handle_cnc_candidate(self, ip, port):
        if self.cnc_info[0] != '':
            l.warning('Cnc info has been confirmed, reject more candidates!')
            return

        # check if this cnc already exists
        cnc_info_in_db = await self.db_store.load_cnc_info(None, ip, int(port))
        for cnc in cnc_info_in_db:
            if cnc.bot_id != self.bot_info.bot_id:
                l.warning(f'Bot already exists for the botnet!')
                return

        if len(cnc_candidates) > self.max_cnc_candidates:
            l.warning(f'CnC candidate number exceed {self.max_cnc_candidates}')
            return

        self.cnc_candidates.append((ip, port))
        await self.iface_monitor.register(ip, self.bot_info.tag)

        # allow communication with this CnC
        nwfilter_type = self.sandbox_ctx.cnc_nwfilter
        cnc_ips = list({c.ip for c in self.cnc_candidates})
        args = {"cnc_ip": cnc_ips}
        self.sandbox.apply_nwfilter(nwfilter_type, **args)

    async def _handle_cnc_status(self, cnc_status):
        if len(cnc_status) == 0:
            return

        self._log_to_csv_file(self.cnc_status_log, cnc_status)
        if cnc_status['status'] == CnCStatus.CANDIDATE.value:
            if len(self.cnc_candidates) == 0:
                await self.update_bot_info(BotStatus.INITIATING)
            await self._handle_cnc_candidate(cnc_status['ip'], cnc_status['port'])
        elif cnc_status['status'] == CnCStatus.ALIVE.value:
            if self.cnc_info[0] == '':
                # CnC info confirmed
                self.cnc_info[0] = cnc_status['ip']
                self.cnc_info[1] = cnc_status['port']
                # exclude redirecting cnc traffic to simulated server in block network mode
                self.sandbox.redirectx_traffic('ON', [self.cnc_info])
            await self.update_bot_info(BotStatus.ACTIVE)
        else:
            await self.update_bot_info(BotStatus.DORMANT)

    async def handle_analyzer_report(self, flush_attacks=False,
                                     flush_cnc_stats=False):
        if self.analyzer_id is None:
            return

        report = await self.analyzer_pool.get_result(self.executor_id,
                                                     self.analyzer_id,
                                                     flush_attacks,
                                                     flush_cnc_stats)
        l.debug(f"Get report: {report}")

        if 'cnc_status' in report:
            self._handle_cnc_status(report['cnc_status'])

        for s in report['cnc_stats']:
            self._log_to_csv_file(self.cnc_stats_log, s)

        for r in report['attacks']:
            total_packets = r['packet_cnt']
            total_bytes = r['total_bytes']
            total_secs = r['duration'].total_seconds()
            pps = total_packets / total_secs
            bandwidth = total_bytes / total_secs
            attack_info = AttackInfo(self.bot_info.bot_id,
                                     r['cnc_ip'],
                                     int(r['cnc_port']),
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

    async def _observe(self, own_ip):
        try:
            # init analyzer
            l.info(f'Analyzer initializing at: {self.executor_id}')
            self.analyzer_id = await self.analyzer_pool.init_analyzer(self.executor_id,
                                                                      own_ip=own_ip,
                                                                      excluded_ips=self.excluded_ips,
                                                                      min_cnc_attempts=\
                                                                          self.min_cnc_attempts,
                                                                      attack_gap=self.attack_gap,
                                                                      min_attack_packets=\
                                                                          self.min_attack_packets,
                                                                      attack_detection_watermark=\
                                                                          self.attack_detection_watermark)
            l.info(f'Analyzer initialized as: {self.analyzer_id}')

            async for packet in self.live_capture.sniff_continuously():
                report_formed = await self.analyzer_pool.analyze_packet(self.executor_id,
                                                                        self.analyzer_id,
                                                                        packet)
                if report_formed:
                    await self.handle_analyzer_report()
        finally:
            # flush and get the final report
            l.info('stopping observing...')
            await self.handle_analyzer_report(True, True)

    async def update_bot_info(self, status=None):
        if status is None:
            # merely update timing info
            self.bot_info.observe_duration = self.observe_duration
            self.bot_info.observe_duration += self.last_observe_duration
            if self.bot_info.status == BotStatus.DORMANT.value:
                self.bot_info.dormant_duration = self.dormant_duration
                self.bot_info.dormant_duration += self.last_dormant_duration

        if status == BotStatus.STAGED:
            self.bot_info.status = BotStatus.STAGED.value
            self.staged_time = datetime.now()
            self.bot_info.observe_at = self.staged_time

        if status == BotStatus.INITIATING:
            self.bot_info.status = BotStatus.INITIATING.value

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

        if status == BotStatus.SUSPENDED:
            if self.notify_unstage:
                # Complete observing
                self.bot_info.status = BotStatus.UNSTAGED.value
            elif self.notify_error:
                # Error occurred
                self.bot_info.status = BotStatus.ERROR.value
            elif self.notify_dup:
                # Duplicated
                self.bot_info.status = BotStatus.DUPLICATE.value
            else:
                # SUSPENDED
                self.bot_info.status = BotStatus.SUSPENDED.value

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
            await self.update_bot_info(BotStatus.STAGED)

            port_dev, mac, own_ip = self.sandbox.get_ifinfo()
            self._init_capture(port_dev, self.bpf_filter)

            # set default nwfiter
            self.sandbox.apply_nwfilter(self.sandbox_ctx.default_nwfilter)

            # open packet executor
            self.executor_id = self.analyzer_pool.open_executor()

            # observing bot
            await self._observe(own_ip)

        except asyncio.CancelledError:
            l.warning("Bot runner cancelled")
        except Exception as e:
            l.error(f"An error occurred {e}")
            traceback.print_exc()
        finally:
            await self.destroy()

    async def destroy(self):
        try:
            if self.destroyed:
                l.debug("Bot runner has been destroyed")
                return

            l.info("Bot runner destroyed")
            await self.update_bot_info(BotStatus.SUSPENDED)
            str_start_time = self.staged_time.strftime('%Y-%m-%d-%H-%M-%S')
            str_end_time = datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
            self.sandbox.fetch_log(self.log_dir, str_start_time, str_end_time)

            if self.cnc_info[0] != '':
                self.sandbox.redirectx_traffic('OFF', [self.cnc_info])
            for c in self.cnc_candidates:
                await self.iface_monitor.unregister(c.ip)

            self.sandbox.destroy()

            # close all analyzer and executor
            if self.analyzer_id is not None:
                await self.analyzer_pool.finalize_analyzer(self.executor_id,
                                                           self.analyzer_id)
            self.analyzer_pool.close_executor(self.executor_id)

            if self.live_capture is not None:
                await self.live_capture.close_async()
            self.destroyed = True
        except asyncio.CancelledError:
            l.debug('Cancelled error occurred')
        except Exception as e:
            l.debug(f'An error occurred {e}')
            traceback.print_exc()
        finally:
            pass

    def is_destroyed(self):
        return self.destroyed

