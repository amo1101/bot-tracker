from bot_runner import *
from db_store import *
from iface_monitor import *
from sandbox_context import SandboxContext
from analyzer_executor import *

l: TaskLogger = TaskLogger(__name__)

SCHEDULER_MODE_MANUAL = 0
SCHEDULER_MODE_AUTO = 1


class Scheduler:
    def __init__(self,
                 bot_repo_ip,
                 bot_repo_user,
                 bot_repo_path,
                 iface_monitor_iface,
                 iface_monitor_excluded_ips,
                 iface_monitor_action,
                 mute_if_monitor_report,
                 mode,
                 sandbox_vcpu_quota,
                 max_sandbox_num,
                 max_dormant_duration,
                 bot_probing_duration,
                 allow_duplicate_bots,
                 max_cnc_candidates,
                 trace_bot_syscall,
                 ring_capture,
                 ring_file_size,
                 bpf_filter,
                 packet_analyzer_excluded_ips,
                 max_packet_analyzing_workers,
                 min_cnc_attempts,
                 attack_gap,
                 min_attack_packets,
                 attack_detection_watermark,
                 sandbox_ctx,
                 db_store):
        self.tracker_id = 0 # reserved for supporting multiple trackers.
        self.bot_repo_ip = bot_repo_ip
        self.bot_repo_user = bot_repo_user
        self.bot_repo_path = bot_repo_path
        self.iface_monitor_iface = iface_monitor_iface
        self.iface_monitor_excluded_ips = iface_monitor_excluded_ips
        self.iface_monitor_action = iface_monitor_action
        self.mute_if_monitor_report = True if mute_if_monitor_report=='yes' else False
        self.mode = mode
        self.checkpoint_interval = 15
        self.sandbox_vcpu_quota = sandbox_vcpu_quota
        self.max_sandbox_num = max_sandbox_num
        self.max_dormant_duration = timedelta(minutes=max_dormant_duration)
        self.bot_probing_duration = timedelta(seconds=bot_probing_duration)
        self.allow_duplicate_bots = True if allow_duplicate_bots == 'yes' else False
        self.ring_capture = True if ring_capture == 'yes' else False
        self.ring_file_size = ring_file_size
        self.bpf_filter = bpf_filter
        self.packet_analyzer_excluded_ips = packet_analyzer_excluded_ips
        self.max_analyzing_workers = max_packet_analyzing_workers
        self.min_cnc_attempts = min_cnc_attempts
        self.max_cnc_candidates = max_cnc_candidates
        self.trace_bot_syscall = True if trace_bot_syscall == 'yes' else False
        self.attack_gap = attack_gap
        self.min_attack_packets = min_attack_packets
        self.attack_detection_watermark = attack_detection_watermark
        self.sandbox_ctx = sandbox_ctx
        self.db_store = db_store
        self.iface_monitor = None
        self.iface_monitor_task = None
        self.analyzer_pool = None

        # {running_task: bot-runner obj}
        self.bot_runners_lock = asyncio.Lock()
        self.bot_runners = {}

    async def destroy(self):
        async with self.bot_runners_lock:
            for t, r in self.bot_runners.items():
                if not t.cancelled():
                    t.cancel()
                else:
                    l.debug(f'Task {t.get_name()} has been cancelled')
                #  await t.destroy()

        if self.analyzer_pool is not None:
            self.analyzer_pool.destroy()

        if self.iface_monitor_task is not None:
            self.iface_monitor_task.cancel()

    async def _unstage_bots(self):
        async with self.bot_runners_lock:
            for t, r in self.bot_runners.items():
                dd = r.bot_dormant_duration
                l.debug(f"Bot [{r.bot_info.tag}] dormant_duration:{dd}")
                if dd > self.max_dormant_duration:
                    l.info(f"Cancelling running bot [{r.bot_info.tag}] after dormant for {dd} minutes.")
                    r.notify_unstage = True
                    t.cancel()

    async def _schedule_bots(self, status_list=None, bot_id=None, count=None):
        curr_runners_num = len(self.bot_runners)
        l.debug("Num of running bots: %d", curr_runners_num)

        if curr_runners_num >= self.max_sandbox_num:
            l.warning('No available slot for new bot.')
            return

        def task_done_cb(t):
            l.debug('Task done cancelled')

        bots = await self.db_store.load_bot_info(status_list, bot_id, count)
        for bot in bots:
            # skip bot which is already running
            already_running = False
            async with self.bot_runners_lock:
                for _, r in self.bot_runners.items():
                    if r.bot_info.bot_id == bot.bot_id:
                        already_running = True
                        break

            if already_running:
                l.warning('Bot %s already running.', bot.bot_id)
                continue

            if curr_runners_num >= self.max_sandbox_num:
                l.warning('No available slot for new bot.')
                break

            bot_runner = BotRunner(bot,
                                   self.bot_repo_ip,
                                   self.bot_repo_user,
                                   self.bot_repo_path,
                                   self.sandbox_vcpu_quota,
                                   self.sandbox_ctx,
                                   self.db_store,
                                   self.analyzer_pool,
                                   self.allow_duplicate_bots,
                                   self.max_cnc_candidates,
                                   self.trace_bot_syscall,
                                   self.ring_capture,
                                   self.ring_file_size,
                                   self.bpf_filter,
                                   self.packet_analyzer_excluded_ips,
                                   self.min_cnc_attempts,
                                   self.attack_gap,
                                   self.min_attack_packets,
                                   self.attack_detection_watermark,
                                   self.iface_monitor)

            task = asyncio.create_task(bot_runner.run(),
                                       name=f't_{bot.tag}')
            async with self.bot_runners_lock:
                self.bot_runners[task] = bot_runner
            task.add_done_callback(task_done_cb)
            l.info(f"Bot [{bot.tag}] scheduled")
            curr_runners_num += 1

    async def _stage_bots(self):
        await self._schedule_bots([BotStatus.UNKNOWN.value,
                                   BotStatus.SUSPENDED.value,
                                   BotStatus.STAGED.value,
                                   BotStatus.DORMANT.value,
                                   BotStatus.ACTIVE.value])

    async def _update_bot_info(self):
        l.info(f'Scheduler mode: {self.mode}, update bot info, bot count: {len(self.bot_runners)}')
        to_del = []
        async with self.bot_runners_lock:
            for t, r in self.bot_runners.items():
                if r.is_destroyed():
                    to_del.append(t)
                else:
                    if r.bot_status == BotStatus.STAGED.value:
                        l.debug(f'Bot has been staged for {r.observe_duration }...')
                        if r.observe_duration > self.bot_probing_duration:
                            r.notify_error = True
                            t.cancel()  # removed at next checkpoint
                    else:
                        await r.update_bot_info()
            for t in to_del:
                del self.bot_runners[t]
                l.debug(f'remove task {t.get_name()}')

    async def update_attack_report(self, bot_id=None):
        l.info(f'Update attack reports...')
        async with self.bot_runners_lock:
            for _, r in self.bot_runners.items():
                if bot_id is None or \
                   r.bot_info.bot_id == bot_id:
                    if not r.is_destroyed():
                        await r.handle_analyzer_report(True)
                    if bot_id is not None:
                        break

    async def checkpoint(self):
        try:
            self.analyzer_pool = \
                AnalyzerExecutorPool(self.max_analyzing_workers)
            # create the interface monitor task
            iface_monitor_action_type = IfaceMonitorAction.TEAR_DOWN if \
                self.iface_monitor_action == '0' else IfaceMonitorAction.ALARM

            async def iface_monitor_action():
                l.debug(f'Iface monitor action triggered, action={self.iface_monitor_action}!')
                if self.iface_monitor_action != '1':
                    l.warning('Stopping all bots!')
                    await self.stop_bot(None, None, 'no', True)

            self.iface_monitor = IfaceMonitor(self.sandbox_ctx.network_mode,
                                              self.iface_monitor_iface,
                                              self.iface_monitor_excluded_ips,
                                              self.mute_if_monitor_report,
                                              iface_monitor_action_type,
                                              iface_monitor_action)
            self.iface_monitor_task = asyncio.create_task(self.iface_monitor.run(),
                                                          name=f't_iface_monitor')
            while True:
                if self.mode == SCHEDULER_MODE_AUTO:
                    await self._unstage_bots()
                    await self._stage_bots()

                await self._update_bot_info()
                await asyncio.sleep(self.checkpoint_interval)
        except asyncio.CancelledError:
            l.warning("Scheduler cancelled")
        finally:
            pass

    # following APIs are for manual scheduling
    async def start_bot(self, bot_id=None, status_list=None):
        if self.mode == SCHEDULER_MODE_AUTO:
            l.warning('start_bot command not supported in auto mode')
            return False

        await self._schedule_bots(status_list, bot_id)
        return True

    async def stop_bot(self, bot_id=None, status_list=None, unstage='no', force_stop=False):
        if self.mode == SCHEDULER_MODE_AUTO and not force_stop:
            l.warning('stop_bot command not supported in auto mode')
            return False

        async with self.bot_runners_lock:
            for t, r in self.bot_runners.items():
                if (bot_id is None or r.bot_info.bot_id == bot_id) and \
                   (status_list is None or r.bot_info.status in status_list):
                    if not r.is_destroyed():
                        if unstage == 'yes':
                            r.notify_unstage = True
                        t.cancel()
                    if bot_id is not None:
                        break

        return True

    def get_scheduler_info(self):
        return (self.mode,
                self.sandbox_vcpu_quota,
                self.max_sandbox_num,
                self.max_dormant_duration,
                self.bot_probing_duration,
                'yes' if self.mute_if_monitor_report else 'no')

    def set_scheduler_info(self, **kwargs):
        l.debug(f'{kwargs}')
        if 'mode' in kwargs:
            mode = kwargs['mode']
            if mode == 'auto':
                self.mode = SCHEDULER_MODE_AUTO
            else:
                self.mode = SCHEDULER_MODE_MANUAL
        if 'sandbox_vcpu_quota' in kwargs:
            self.sandbox_vcpu_quota = int(kwargs['sandbox_vcpu_quota'])
        if 'max_sandbox_num' in kwargs:
            self.max_sandbox_num = int(kwargs['max_sandbox_num'])
        if 'max_dormant_duration' in kwargs:
            max_dormant_minutes = int(kwargs['max_dormant_duration'])
            self.max_dormant_duration = timedelta(minutes=max_dormant_minutes)
        if 'bot_probing_duration' in kwargs:
            bot_probing_duration = int(kwargs['bot_probing_duration'])
            self.bot_probing_duration = timedelta(seconds=bot_probing_duration)
        if 'mute_if_monitor_report' in kwargs:
            self.mute_if_monitor_report = True if kwargs['mute_if_monitor_report'] == 'yes' else False
            self.iface_monitor.mute_report(self.mute_if_monitor_report)
