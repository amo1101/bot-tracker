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


# data be a list of dicts
def log_to_csv_file(csv_file, data, fieldnames=None):
    if len(data) == 0:
        return
    is_empty = os.stat(csv_file).st_size == 0 if \
        os.path.isfile(csv_file) else True
    with open(csv_file, 'a', newline='') as file:
        if fieldnames is None:
            fieldnames = data[0].keys()
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        if is_empty:
            writer.writeheader()
        writer.writerows(data)


class BotRunnerException(Exception):
    def __init__(self, message):
        super().__init__(message)


class BotRunner:
    def __init__(self, bot_info,
                 bot_repo_ip, bot_repo_user, bot_repo_path,
                 sandbox_vcpu_quota,
                 sandbox_ctx, db_store,
                 analyzer_pool,
                 bpf_filter,
                 excluded_ips,
                 min_cnc_attempts,
                 max_cnc_candidates,
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

    async def _handle_candidate_cnc(self, ip, port):
        l.info(f'New CnC candidate: {ip}:{port}')
        if self.cnc_info[0] != '':
            l.warning('CnC info has been confirmed, reject more candidates!')
            return

        if len(self.cnc_candidates) > self.max_cnc_candidates:
            l.warning(f'Number of CnC candidates exceeds {self.max_cnc_candidates}, will remove the oldest!')
            d_ip, d_port = self.cnc_candidates.pop(0)
            await self.iface_monitor.unregister(d_ip, self.bot_info.tag)
            self.sandbox.redirectx_traffic('OFF', [(d_ip, d_port)])

        self.cnc_candidates.append((ip, port))
        await self.iface_monitor.register(ip, self.bot_info.tag)

        # allow communication with this CnC
        nwfilter_type = self.sandbox_ctx.candidate_cnc_nwfilter
        cnc_ips = list({cip for cip, _ in self.cnc_candidates})
        args = {"cnc_ip": cnc_ips}
        self.sandbox.apply_nwfilter(nwfilter_type, **args)
        l.info(f'Enabled nwfilter policy for Cnc candidate: {ip}:{port}')
        # exclude redirecting cnc traffic to simulated server in block network mode
        self.sandbox.redirectx_traffic('ON', [(ip, port)])

    async def _handle_confirmed_cnc(self, ip, port, domain):
        # check if this cnc already exists
        is_old_cnc = False
        cnc_info_in_db = await self.db_store.load_cnc_info(None, ip, int(port))
        for cnc in cnc_info_in_db:
            if cnc.bot_id != self.bot_info.bot_id:
                l.warning(f'Bot already exists for the botnet!')
                self.notify_dup = True
                raise BotRunnerException('Bot already exist for the botnet!')
            elif cnc.bot_id == self.bot_info.bot_id:
                is_old_cnc = True
                l.warning('This is a previously discovered CnC!')
                break

        l.info(f'Confirmed CnC: {ip}:{port}')
        self.cnc_info = (ip, port)
        # TODO: temp fix
        self.cnc_candidates = list(filter(lambda x: x[0] != ip, self.cnc_candidates))
        for cip, _ in self.cnc_candidates:
                await self.iface_monitor.unregister(cip, self.bot_info.bot_id)

        if len(self.cnc_candidates) != 0:
            self.sandbox.redirectx_traffic('OFF', self.cnc_candidates)

        # allow communication with only this CnC
        nwfilter_type = self.sandbox_ctx.cnc_nwfilter
        args = {"cnc_ip": [ip]}
        self.sandbox.apply_nwfilter(nwfilter_type, **args)

        self.cnc_candidates.clear()

        # store to db
        if not is_old_cnc:
            l.info(f'This is new CnC: {ip}:{port}')
            cnc_info = CnCInfo(ip, int(port), self.bot_info.bot_id, domain)
            await self.db_store.add_cnc_info(cnc_info)

    async def _handle_cnc_status(self, cnc_status):
        if len(cnc_status) == 0:
            return

        fieldnames = ['ip', 'port', 'domain', 'status', 'update_time']
        log_to_csv_file(self.cnc_status_log, [cnc_status], fieldnames)
        if cnc_status['status'] == CnCStatus.CANDIDATE.value:
            if len(self.cnc_candidates) == 0:
                await self.update_bot_info(BotStatus.DORMANT)
            await self._handle_candidate_cnc(cnc_status['ip'], cnc_status['port'])
        elif cnc_status['status'] == CnCStatus.ALIVE.value:
            if self.cnc_info[0] == '':
                await self._handle_confirmed_cnc(cnc_status['ip'], cnc_status['port'], cnc_status['domain'])
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
            await self._handle_cnc_status(report['cnc_status'])

        log_to_csv_file(self.cnc_stats_log, report['cnc_stats'])

        for r in report['attacks']:
            total_packets = r['packet_cnt']
            total_bytes = r['total_bytes']
            total_secs = r['duration'].total_seconds()
            pps = total_packets / total_secs
            bandwidth = total_bytes / total_secs
            attack_info = AttackInfo(self.bot_info.bot_id,
                                     r['cnc_ip'],
                                     int(r['cnc_port']) if r['cnc_port'] != '' else 0,
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
            self.analyzer_id = \
                await self.analyzer_pool.init_analyzer(self.executor_id,
                                                       own_ip=own_ip,
                                                       excluded_ips=self.excluded_ips,
                                                       min_cnc_attempts=self.min_cnc_attempts,
                                                       attack_gap=self.attack_gap,
                                                       min_attack_packets=self.min_attack_packets,
                                                       attack_detection_watermark=self.attack_detection_watermark)
            l.info(f'Analyzer initialized as: {self.analyzer_id}')

            async for packet in self.live_capture.sniff_continuously():
                report_formed = await self.analyzer_pool.analyze_packet(self.executor_id,
                                                                        self.analyzer_id,
                                                                        packet)
                if report_formed:
                    await self.handle_analyzer_report()
            # get the final report
            await self.handle_analyzer_report(True, True)
        except BotRunnerException as e:
            l.info(f'An exception occurred {e}, stop observing...')
        except asyncio.CancelledError:
            # flush and get the final report when cancelled
            await self.handle_analyzer_report(True, True)
        finally:
            l.info('stopping observing...')

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

            # open packet analyzer executor
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

            if len(self.cnc_candidates) != 0:
                self.sandbox.redirectx_traffic('OFF', self.cnc_candidates)
            for cip, _ in self.cnc_candidates:
                await self.iface_monitor.unregister(cip, self.bot_info.bot_id)
            if self.cnc_info[0] != '':
                self.sandbox.redirectx_traffic('OFF',[self.cnc_info])
                await self.iface_monitor.unregister(self.cnc_info[0],
                                                    self.bot_info.bot_id)

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
