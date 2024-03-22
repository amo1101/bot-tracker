import asyncio
import libvirt
import libvirtaio
import uuid
from datetime import datetime, timedelta
from db import *
from bot_runner import *
from log import TaskLogger

l = TaskLogger(__name__)

CHECKPOINT_INTERVAL = 5

class Scheduler:
    def __init__(self, sandbox_ctx, db_store):
        self.tracker_id = None #TODO: bot migration will be done via CLI 
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
                o.bot_info.status = BotStatus.INTERRUPTED
                await db_store.update_bot_info(o.bot_info)
                t.cancel()
            else:
                l.debug(f'task {t.get_name()} has been cancelled')
        BotRunner.analyzer_executor.shutdown()

    async def _unstage_bots(self):
        for t, o in self.bot_runners.items():
            dd = o.dormant_duration()
            od = o.observe_duration()
            l.debug(f"bot [{o.bot_info.sha256}]: \ndormant_duration:{dd}\nobserve_duration:{od}")
            if dd > self.max_dormant_duration or od > self.max_observe_duration:
                l.debug(f"Cancelling running bot [{o.bot_info.sha256}]")
                o.bot.status = BotStatus.STOPPED.value
                await db_store.update_bot_info(o.bot)
                t.cancel()

    async def _schedule_bots(self):

        def task_done_cb(t):
            if t in self.bot_runners:
                del self.bot_runners[t]
                l.debug('task done removed')

        # run bot
        l.debug("Num of running bots: %d", len(self.bot_runners))
        slots = self.max_sandbox_num - len(self.bot_runners)
        if slots <= 0
            l.warning('no sandbox available for bots')
            return

        # TODO: get botinfo from db
        bots = await db_store.load_bot_info(BotStatus.UNKNOWN, slots)
        for bot in bots:
            bot.status = BotStatus.STARTED.value
            bot_runner = BotRunner(bot, self.sandbox_cxt, self.db_store)
            task = asyncio.create_task(bot_runner.run(), name=f'Task-{bot.sha256}')
            self.bot_runners[task] = bot_runner
            task.add_done_callback(task_done_cb)
            await self.db_store.update_bot_info(bot)
            l.debug(f"bot [{bot.sha256}] scheduled")

    async def checkpoint(self):
        try:
            while True:
                await self._unstage_bots()
                await self._schedule_bots()
                await asyncio.sleep(CHECKPOINT_INTERVAL)
        except asyncio.CancelledError:
            l.warning("Scheduler cancelled")
        finally:
            #TODO: we do not need to cancel tasks when interrupted, asyncio
            # handle it
            #  self.destroy()
            pass

