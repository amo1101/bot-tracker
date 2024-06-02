from bot_runner import *
from db_store import *

l: TaskLogger = TaskLogger(__name__)

SCHEDULER_MODE_MANUAL = 0
SCHEDULER_MODE_AUTO = 1


class Scheduler:
    def __init__(self,
                 tracker_id,
                 bot_repo_ip,
                 bot_repo_user,
                 bot_repo_path,
                 mode,
                 monitor_on_iface,
                 sandbox_vcpu_quota,
                 max_sandbox_num,
                 max_dormant_duration,
                 max_packet_analyzing_workers,
                 cnc_probing_duration,
                 sandbox_ctx,
                 db_store):
        self.tracker_id = tracker_id  # left for supporting multiple trackers.
        self.bot_repo_ip = bot_repo_ip
        self.bot_repo_user = bot_repo_user
        self.bot_repo_path = bot_repo_path
        self.mode = mode
        self.monitor_on_iface = monitor_on_iface
        self.checkpoint_interval = 10
        self.sandbox_vcpu_quota = sandbox_vcpu_quota
        self.max_sandbox_num = max_sandbox_num
        self.max_dormant_hours = max_dormant_duration
        self.max_dormant_duration = timedelta(hours=self.max_dormant_hours)
        self.max_analyzing_workers = max_packet_analyzing_workers
        self.cnc_probing_duration = cnc_probing_duration
        self.sandbox_cxt = sandbox_ctx
        self.db_store = db_store

        # {running_task: bot-runner obj}
        self.bot_runners = {}

    def destroy(self):
        for t, r in self.bot_runners.items():
            if not t.cancelled():
                t.cancel()
            else:
                l.debug(f'Task {t.get_name()} has been cancelled')
        if BotRunner.analyzer_executor is not None:
            BotRunner.analyzer_executor.shutdown()

    def _unstage_bots(self):
        for t, r in self.bot_runners.items():
            dd = r.dormant_duration()
            od = r.observe_duration()
            l.info(f"Bot [{r.bot_info.tag}]: \ndormant_duration:{dd}\nobserve_duration:{od}")
            if dd > self.max_dormant_duration:
                l.info(f"Cancelling running bot [{r.bot_info.tag}]")
                r.notify_unstage = True
                t.cancel()

    async def _schedule_bots(self, status_list=None, bot_id=None, count=None):
        curr_runners_num = len(self.bot_runners)
        l.info("Num of running bots: %d", curr_runners_num)

        if curr_runners_num >= self.max_sandbox_num:
            l.warning('No available slot for new bot.')
            return

        def task_done_cb(t):
            if t in self.bot_runners:
                del self.bot_runners[t]
                l.debug('Task done removed')

        bots = await self.db_store.load_bot_info(status_list, bot_id, count)
        for bot in bots:
            # skip bot which is already running
            already_running = False
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
                                   self.cnc_probing_duration,
                                   self.sandbox_cxt,
                                   self.db_store,
                                   self.max_analyzing_workers)
            task = asyncio.create_task(bot_runner.run(),
                                       name=f't_{bot.tag}')
            self.bot_runners[task] = bot_runner
            task.add_done_callback(task_done_cb)
            l.info(f"Bot [{bot.tag}] scheduled")
            curr_runners_num += 1

    async def _stage_bots(self):
        await self._schedule_bots([BotStatus.UNKNOWN.value,
                                   BotStatus.INTERRUPTED.value])

    async def _update_bot_info(self):
        for _, r in self.bot_runners.items():
            await r.update_bot_info()

    async def checkpoint(self):
        try:
            while True:
                if self.mode == SCHEDULER_MODE_AUTO:
                    self._unstage_bots()
                    await self._stage_bots()
                    await self._update_bot_info()
                await asyncio.sleep(self.checkpoint_interval)
        except asyncio.CancelledError:
            l.warning("Scheduler cancelled")
        finally:
            pass

    # following APIs are for manual scheduling
    async def start_bot(self, bot_id):
        if self.mode == SCHEDULER_MODE_AUTO:
            l.warning('start_bot command not supported in auto mode')
            return False

        await self._schedule_bots(None, bot_id)
        return True

    def stop_bot(self, bot_id, force_stop=False):
        if self.mode == SCHEDULER_MODE_AUTO:
            l.warning('stop_bot command not supported in auto mode')
            return False

        for t, r in self.bot_runners.items():
            # bot_id is None means stop all bots
            if r.bot_info.bot_id == bot_id or bot_id is None:
                t.cancel()
                if bot_id is not None:
                    break

        return True

    # this API is for separate auto and manual schedule to avoid conflict
    async def manual_update_bot_info(self):
        if self.mode == SCHEDULER_MODE_MANUAL:
            await self._update_bot_info()

    def get_scheduler_info(self):
        return (self.mode,
                self.sandbox_vcpu_quota,
                self.max_sandbox_num,
                self.max_dormant_hours,
                self.cnc_probing_duration)

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
        if 'max_dormant_hours' in kwargs:
            self.max_dormant_hours = int(kwargs['max_dormant_hours'])
            self.max_dormant_duration = timedelta(hours=self.max_dormant_hours)
        if 'cnc_probing_duration' in kwargs:
            self.cnc_probing_duration = int(kwargs['cnc_probing_duration'])
