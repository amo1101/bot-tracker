import asyncio
import libvirt
import libvirtaio
import logging
import uuid
from datetime import datetime, timedelta
from bot_runner import *

l = logging.getLogger(__name__)

class Scheduler:
    CHECKPOINT_INTERVAL = 10

    def __init__(self, sandbox_ctx):
        self.sandbox_cxt = sandbox_ctx
        self.max_sandbox_num = 5
        self.max_dormant_duration = timedelta(days=3, hours=0, minutes=0,
                                              seconds=0)
        self.max_observe_duration = timedelta(days=7, hours=0, minute=0,
                                              seconds=0)
        # {running_task: botrunner obj}
        self.bot_runners = {}

    def destroy(self):
        for t, o in self.bot_runners.items():
            t.cancel()

    def _unstage_bots(self):
        for t, o in bot_runners.items():
            dd = o.dormant_duration()
            od = o.observe_duration()
            l.debug(f"bot [{o.bot_info.sha256}]: \ndormant_duration:{dd}\n
                    observe_duration:{od}")
            if dd > self.max_dormant_duration or od > self.max_observe_duration:
                l.debug(f"Cancelling running bot [{o.bot_info.sha256}]")
                t.cancel()

    def _schedule_bots(self):
        # TODO: get botinfo from db
        # run bot
        l.debug("Num of running bots: %d", len(self.bot_runners))
        if len(self.bot_runners) > self.max_sandbox_num:
            return

        botname = f"bot-{uuid.uuid4()}"
        bot = BotInfo(botname,"armv7")
        bot_runner = BotRunner(bot, self.sandbox_cxt)
        task = asyncio.create_task(bot_runner.run())
        self.bot_runners[task] = bot_runner
        task.add_done_callback(lambda t: del self.bot_runners[t])
        l.debug(f"bot [{o.bot_info.sha256}] scheduled")

    async def checkpoint(self):
        try:
            while True:
                await self._unstage_bots()
                await self._schedule_bots()
                await asyncio.sleep(CHECKPOINT_INTERVAL)
        except asyncio.CancelledError:
            l.warning("Scheduler is cancelled")
        finally:
            self.destroy()

