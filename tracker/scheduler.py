import asyncio
import libvirt
import libvirtaio
import logging
from bot_runner import *

l = logging.getLogger(__name__)

class Scheduler:
    CHECKPOINT_INTERVAL = 10

    def __init__(self, sandbox_ctx):
        self.sandbox_cxt = sandbox_ctx
        self.max_sandbox_num = 10
        self.max_dormant_duration = 24
        self.max_observe_duration = 7*24
        # {botname:[running_task, botrunner obj]}
        self.bot_runners = {}

    def destroy(self):
        for t, o in bot_runners.items():
            t.cancel()

    def _unstage_bots(self):
        for t, o in bot_runners.items():
            if o.dormant_duration() > self.max_dormant_duration or \
               o.observe_duration() > self.max_observe_duration:
                t.cancel()

    def _schedule_bots(self):
        # TODO: get botinfo from db
        # run bot
        bot = BotInfo("abcdefg","armv7")
        bot_runner = BotRunner(bot, self.sandbox_cxt)
        task = asyncio.create_task(bot_runner.run())
        self.bot_runners[t] = bot_runner
        task.add_done_callback(lambda t: del self.bot_runners[t])

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

