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

CHECKPOINT_INTERVAL = 10

class SchedulerMode(Enum):
    MANUAL = "manual"
    AUTO = "auto"

class Scheduler:
    def __init__(self, mode, sandbox_ctx, db_store):
        self.tracker_id = None #TODO: bot migration will be done via CLI 
        self.mode = mode # 0 mean manual mode, 1 means auto mode
        self.sandbox_cxt = sandbox_ctx
        self.db_store = db_store
        self.max_sandbox_num = 5
        self.max_dormant_duration = timedelta(days=0, hours=0, minutes=0,
                                              seconds=300)
        self.max_observe_duration = timedelta(days=7, hours=0, minutes=0,
                                              seconds=0)
        # {running_task: botrunner obj}
        self.bot_runners = {}

    async def destroy(self):
        for t, o in self.bot_runners.items():
            if not t.cancelled():
                o = self.bot_runners[t]
                t.cancel()
            else:
                l.debug(f'task {t.get_name()} has been cancelled')
        BotRunner.analyzer_executor.shutdown()

    async def _unstage_bots(self):
        for t, o in self.bot_runners.items():
            dd = o.dormant_duration()
            od = o.observe_duration()
            l.debug(f"bot [{o.bot_info.tag}]: \ndormant_duration:{dd}\nobserve_duration:{od}")
            if dd > self.max_dormant_duration or od > self.max_observe_duration:
                l.debug(f"Cancelling running bot [{o.bot_info.tag}]")
                t.cancel()

    async def _schedule_bots(self, status_list=None, bot_id=None, count=None):
        def task_done_cb(t):
            if t in self.bot_runners:
                del self.bot_runners[t]
                l.debug('task done removed')

        bots = await db_store.load_bot_info(status_list, bot_id, count)
        for bot in bots:
            bot_runner = BotRunner(bot, self.sandbox_cxt, self.db_store)
            task = asyncio.create_task(bot_runner.run(),
                                       name=f'Task-{bot.tag}')
            self.bot_runners[task] = bot_runner
            task.add_done_callback(task_done_cb)
            l.debug(f"bot [{bot.tag}] scheduled")

    async def _stage_bots(self):
        l.debug("Num of running bots: %d", len(self.bot_runners))
        slots = self.max_sandbox_num - len(self.bot_runners)
        if slots <= 0:
            l.warning('no sandbox available for bots')
            return

        await self._schedule_bots([BotStatus.UNKNOWN.value,
                                   BotStatus.INTERRUPTED.value], None, slots)

    async def _update_bot_info(self):
        for _, o in self.bot_runners.items():
            await o.update_bot_info()

    async def checkpoint(self):
        try:
            while True:
                #  l.debug('Scheduler checkpoint...')
                if self.mode == SchedulerMode.AUTO:
                    await self._unstage_bots()
                    await self._stage_bots()
                await self._update_bot_info()
                await asyncio.sleep(CHECKPOINT_INTERVAL)
        except asyncio.CancelledError:
            l.warning("Scheduler cancelled")
        finally:
            #TODO: we do not need to cancel tasks when interrupted, asyncio
            # handle it
            #  self.destroy()
            pass

    async def start_bot(self, bot_id):
        await self._schedule_bots(None, bot_id)

    async def stop_bot(self, bot_id):
        for t, o in self.bot_runners.items():
            if o.bot_info.bot_id == bot_id:
                t.cancel()
                break
