import asyncio
from enum import Enum
import uuid
from datetime import datetime, timedelta
from bot_runner import *
from log import TaskLogger

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
DB_MODULE_DIR = os.path.dirname(CUR_DIR) + os.sep + 'db'
sys.path.append(DB_MODULE_DIR)
from db_store import *

l = TaskLogger(__name__)
SCHEDULER_MODE_MANNUAL = 0
SCHEDULER_MODE_AUTO = 1

class Scheduler:
    def __init__(self,
                 tracker_id,
                 bot_repo_ip,
                 bot_repo_user,
                 bot_repo_path,
                 mode,
                 checkpoint_interval,
                 sandbox_vcpu_quota,
                 max_sandbox_num,
                 max_dormant_duration,
                 max_packet_analyzing_workers,
                 cnc_probing_duration,
                 sandbox_ctx,
                 db_store):
        self.tracker_id = tracker_id  # TODO: bot migration will be done via CLI
        self.bot_repo_ip = bot_repo_ip
        self.bot_repo_user = bot_repo_user
        self.bot_repo_path = bot_repo_path
        self.mode = mode  # 0 mean manual mode, 1 means auto mode
        self.checkpoint_interval = checkpoint_interval
        self.sandbox_vcpu_quota = sandbox_vcpu_quota
        self.max_sandbox_num = max_sandbox_num
        self.max_dormant_hours = max_dormant_duration
        # TODO
        self.max_dormant_duration = timedelta(days=0, hours=self.max_dormant_hours, minutes=0,
                                              seconds=0)
        self.max_observe_duration = timedelta(days=7, hours=0, minutes=0,
                                              seconds=0)
        BotRunner.max_analyzing_workers = max_packet_analyzing_workers
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
                l.debug(f'task {t.get_name()} has been cancelled')
        BotRunner.analyzer_executor.shutdown()

    def _unstage_bots(self):
        for t, r in self.bot_runners.items():
            dd = r.dormant_duration()
            od = r.observe_duration()
            l.debug(f"bot [{r.bot_info.tag}]: \ndormant_duration:{dd}\nobserve_duration:{od}")
            if dd > self.max_dormant_duration:
                l.debug(f"Cancelling running bot [{r.bot_info.tag}]")
                r.notify_unstage = True
                t.cancel()

    async def _schedule_bots(self, status_list=None, bot_id=None, count=None):
        curr_runners_num = len(self.bot_runners)
        l.debug("Num of running bots: %d", curr_runners_num)

        if curr_runners_num >= self.max_sandbox_num:
            l.warning('No avaiable slot for new bot.')
            return

        def task_done_cb(t):
            if t in self.bot_runners:
                del self.bot_runners[t]
                l.debug('task done removed')

        bots = await self.db_store.load_bot_info(status_list, bot_id, count)
        for bot in bots:
            # skip bot which is already running
            already_running = False
            for _, r in self.bot_runners.items():
                if r.bot_info.bot_id  == bot.bot_id:
                    already_running = True
                    break

            if already_running:
                continue

            if curr_runners_num >= self.max_sandbox_num:
                l.warning('No avaiable slot for new bot.')
                break

            bot_runner = BotRunner(bot,
                                   self.bot_repo_ip,
                                   self.bot_repo_user,
                                   self.bot_repo_path,
                                   self.sandbox_vcpu_quota,
                                   self.cnc_probing_duration,
                                   self.sandbox_cxt,
                                   self.db_store)
            task = asyncio.create_task(bot_runner.run(),
                                       name=f't_{bot.tag}')
            self.bot_runners[task] = bot_runner
            task.add_done_callback(task_done_cb)
            l.debug(f"bot [{bot.tag}] scheduled")
            curr_runners_num += 1

    async def _stage_bots(self):
        await self._schedule_bots([BotStatus.UNKNOWN.value,
                                   BotStatus.INTERRUPTED.value], None, slots)

    async def _update_bot_info(self):
        for _, r in self.bot_runners.items():
            await r.update_bot_info()

    async def checkpoint(self):
        try:
            while True:
                #  l.debug('Scheduler checkpoint...')
                if self.mode == SCHEDULER_MODE_AUTO:
                    self._unstage_bots()
                    await self._stage_bots()
                    await self._update_bot_info()
                await asyncio.sleep(self.checkpoint_interval)
        except asyncio.CancelledError:
            l.warning("Scheduler cancelled")
        finally:
            # TODO: we do not need to cancel tasks when interrupted, asyncio
            # handle it
            #  self.destroy()
            pass

    # following APIs are for manual scheduling
    async def start_bot(self, bot_id):
        if self.mode == SCHEDULER_MODE_AUTO:
            l.debug('start_bot command not supported in auto mode')
            return False

        await self._schedule_bots(None, bot_id)
        return True

    def stop_bot(self, bot_id):
        if self.mode == SCHEDULER_MODE_AUTO:
            l.debug('stop_bot command not supported in auto mode')
            return False

        for t, r in self.bot_runners.items():
            if r.bot_info.bot_id == bot_id or bot_id == None:
                t.cancel()
                if bot_id is not None:
                    break

        return True

    # this API is for seperate auto and manual schedule to avoid conflict
    async def manual_update_bot_info(self):
        if self.mode == SCHEDULER_MODE_MANNUAL:
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
                self.mode = SCHEDULER_MODE_MANNUAL
        if 'sandbox_vcpu_quota' in kwargs:
            self.sandbox_vcpu_quota = int(kwargs['sandbox_vcpu_quota'])
        if 'max_sandbox_num' in kwargs:
            self.max_sandbox_num = int(kwargs['max_sandbox_num'])
        if 'max_dormant_hours' in kwargs:
            self.max_dormant_hours = int(kwargs['max_dormant_hours'])
            # TODO update dormant duration
        if 'cnc_probing_duration' in kwargs:
            self.cnc_probing_duration = int(kwargs['cnc_probing_duration'])

