import asyncio
import libvirt
import libvirtaio
import libxml2

# TODO
class BotInfo:
    pass

class BotRunner:
    def __init__(self, bot_info):
        self.bot_info = bot_info
        self.sandbox = None
        self.cnc_analzyer = None
        self.attack_analzyer = None
        self.live_capture = None
        self.cnc_info = None

    def _report_cnc(self):
        pass

    def _report_attack(self):
        pass

    async def _find_cnc(self):
        async for packet in self.live_capture.capture(300):
            if self.cnc_analzyer.analyze(packet):
                self._report_cnc()

    async def _observe_attack(self):
        async for packet in self.live_capture.capture():
            if self.attack_analzyer.analyze(packet):
                self._report_attack()

    async def run(self):
        self.sandbox = Sandbox()
        self.sandbox.create()

        # find cnc server
        await self._find_cnc()
        if self.cnc_info is None:
            self.destroy()
            return

        # enforce network policy
        self.apply_net_filter()

        # observer attacks
        await self._observe_attack()

    def destroy(self):
        self.live_capture.stop()
        self.sandbox.destroy()

