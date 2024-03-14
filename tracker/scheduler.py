import asyncio
import libvirt
import libvirtaio
import uuid
from datetime import datetime, timedelta
from bot_runner import *
from log import TaskLogger

l = TaskLogger(__name__)

CHECKPOINT_INTERVAL = 5

class Scheduler:
    def __init__(self, sandbox_ctx):
        self.sandbox_cxt = sandbox_ctx
        self.max_sandbox_num = 1
        self.max_dormant_duration = timedelta(days=0, hours=0, minutes=0,
                                              seconds=300)
        self.max_observe_duration = timedelta(days=7, hours=0, minutes=0,
                                              seconds=0)
        # {running_task: botrunner obj}
        self.bot_runners = {}

    async def destroy(self):
        for t, o in self.bot_runners.items():
            t.cancel()
            await o.destroy()
        self.bot_runners.clear()
        BotRunner.analyzer_executor.shutdown()

    async def _unstage_bots(self):
        to_del = []
        for t, o in self.bot_runners.items():
            dd = o.dormant_duration()
            od = o.observe_duration()
            l.debug(f"bot [{o.bot_info.sha256}]: \ndormant_duration:{dd}\nobserve_duration:{od}")
            if dd > self.max_dormant_duration or od > self.max_observe_duration:
                l.debug(f"Cancelling running bot [{o.bot_info.sha256}]")
                t.cancel()
                await o.destroy()
                to_del.append(t)
        for k in to_del:
            del self.bot_runners[k]

    def _schedule_bots(self):
        # TODO: get botinfo from db
        # run bot
        l.debug("Num of running bots: %d", len(self.bot_runners))
        if len(self.bot_runners) >= self.max_sandbox_num:
            return

        botname = f"bot-{uuid.uuid4()}"
        bot = BotInfo(botname,"armv7")
        bot_runner = BotRunner(bot, self.sandbox_cxt)
        task = asyncio.create_task(bot_runner.run(), name=f'Task-{botname}')
        self.bot_runners[task] = bot_runner

        #  def task_done_cb(t):
            #  if t in self.bot_runners:
                #  del self.bot_runners[t]
                #  l.debug('task done removed')

        #  task.add_done_callback(task_done_cb)
        l.debug(f"bot [{bot.sha256}] scheduled")

    async def checkpoint(self):
        try:
            while True:
                await self._unstage_bots()
                self._schedule_bots()
                await asyncio.sleep(CHECKPOINT_INTERVAL)
        except asyncio.CancelledError:
            l.warning("Scheduler catch cancelled")
            raise asyncio.CancelledError
        finally:
            await self.destroy()

