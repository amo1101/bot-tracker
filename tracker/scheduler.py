import asyncio
import libvirt
import libvirtaio
import libxml2

class Scheduler:
    CHECKPOINT_INTERVAL = 5

    def __init__(self):
        self.sandbox_context = None
        self.max_sandbox_num = 10
        self.max_dormant_duration = 24
        self.max_observe_duration = 7*24
        self.bot_runners = {}

    async def _unstage_bots(self):
        pass

    async def _schedule_bots(self):
        pass

    async def checkpoint(self):
        while True:
            try:
                await self._unstage_bots()
                await self._schedule_bots()
                await asyncio.sleep(CHECKPOINT_INTERVAL)
            except:
                pass
            finally:
                pass

