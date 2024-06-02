from concurrent.futures import ProcessPoolExecutor
import asyncio
import os
from packet_capture import *
from scheduler import Scheduler

l: TaskLogger = TaskLogger(__name__)
CUR_DIR = os.path.dirname(os.path.abspath(__file__))


class IfaceMonitor:
    def __init__(self,
                 scheduler,
                 iface,
                 subnet):
        self.iface = iface
        self.capture = None
        self.excluded_subnet = subnet
        self.bot_reg = {}

    # bots call the api to register monitoring
    def register(self, mac, cnc_ip, bot_id):
        self.bot_reg[mac] = [cnc_ip, bot_id]

    def unregister(self, mac):
        del self.bot_reg[mac]

    def _init_monitor(self):
        if self.capture is None:
            # filter outgoing packets
            output_file = ''
            bpf_filter = 'not (dst net 192.168.122.0 mask 255.255.255.0) and not dst host 8.8.8.8'
            self.capture = AsyncLiveCapture(interface=self.monitor_on_iface,
                                            bpf_filter=bpf_filter,
                                            output_file=output_file)

    def report_incident(self):
        pass

    def traffic_analyze(self, packet):
        dst = packet.ip.dst
        mac = packet.eth.src

        # if this is sent from a bot and dst is not cnc, then this is an
        # incidence, record it and stop the bot immediately
        if mac in self.bot_reg and dst != self.bot_reg[mac][0]:
            self.report_incident()
            self.scheduler.stop_bot(self.bot_reg[mac][1], True)

    async def start_monitor(self):
        loop = asyncio.get_running_loop()
        with ProcessPoolExecutor(max_workers=1) as pool:
            async for packet in self.capture.sniff_continuously():
                await loop.run_in_executor(pool, self.traffic_analyze,
                                           packet)

