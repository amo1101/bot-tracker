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

    async def run(self):
        self.sandbox = Sandbox()
        self.sandbox.create()

        # find cnc server, waiting for 300s
        await self.live_capture.capture(self.cnc_analzyer, 300)
        if self.cnc_analzyer.get_state():
            return

        # enforce network policy
        # observer attack
        await self.live_capture.capture(self.attack_analzyer)

    def destroy(self):
        pass

