from concurrent.futures import ProcessPoolExecutor
import asyncio
import os
from datetime import datetime
from packet_capture import *
from scheduler import Scheduler
from sandbox_ctx import NetworkMode

l: TaskLogger = TaskLogger(__name__)
CUR_DIR = os.path.dirname(os.path.abspath(__file__))


class IfaceMonitor:
    def __init__(self,
                 network_mode,
                 scheduler,
                 iface,
                 subnet,
                 netmask):
        self.network_mode = network_mode
        self.iface = iface
        self.subnet = subnet
        self.netmask = netmask
        self.capture = None
        self.dns_server = '8.8.8.8' # yes hard code it
        self.bot_reg = {}
        self.report_file = CUR_DIR + os.sep + f'iface-monitor-report-{self.iface}.log'

    # bots call the api to register monitoring
    def register(self, mac, cnc_ip, bot_id):
        self.bot_reg[mac] = [cnc_ip, bot_id]

    def unregister(self, mac):
        del self.bot_reg[mac]

    def _init_monitor(self):
        if self.capture is None:
            # filter outgoing packets
            output_file = CUR_DIR + os.sep + f'iface-monitor-{self.iface}.pcap'
            bpf_filter = f'not (dst net {self.subnet} mask {self.netmask}) ' + \
                         f'and not dst host {self.dns_server}'
            self.capture = AsyncLiveCapture(interface=self.monitor_on_iface,
                                            bpf_filter=bpf_filter,
                                            output_file=output_file)

    def report_incident(self, mac, cnc_ip, bot_id, src, src_port, dst, dst_port, prot, action):
        with open(self.report_file, 'a') as file:
            report = f"{'timestamp':<16}:{datetime.now()}\n" + \
                     f"{'network_mode':<16}:{self.network_mode}\n" + \
                     f"{'mac':<16}:{mac}\n" + \
                     f"{'cnc_ip':<16}:{cnc_ip}\n" + \
                     f"{'bot_id':<16}:{bot_id[:16]}\n" + \
                     f"{'src_ip':<16}:{src}\n" + \
                     f"{'src_port':<16}:{src_port}\n" + \
                     f"{'dst_ip':<16}:{dst}\n" + \
                     f"{'dst_port':<16}:{dst_port}\n" + \
                     f"{'protocol':<16}:{prot}\n" + \
                     f"{'action':<16}:{action}\n"
            file.write(report)

    def traffic_analyze(self, pkt):
        dst = pkt.ip.dst
        mac = pkt.eth.src
        src = pkt.ip.src
        src_port = 'NA'
        dst_port = 'NA'
        prot = 'NA'
        if 'tcp' in dir(pkt):
            prot = 'tcp'
            src_port = pkt.tcp.srcport
            dst_port = pkt.tcp.dstport
        elif 'udp' in dir(pkt):
            prot = 'udp'
            src_port = pkt.udp.srcport
            dst_port = pkt.udp.dstport

        # if sent from a bot and dst is not cnc, then this is an
        # incidence, record it and stop the bot immediately
        if mac in self.bot_reg and dst != self.bot_reg[mac][0]:
            self.report_incident()
            if self.network_mode == NetworkMode.BLOCK:
                self.scheduler.stop_bot(self.bot_reg[mac][1], True)

    async def start(self):
        self._init_monitor()
        loop = asyncio.get_running_loop()
        # the monitor should not be busy, suffice to use 1 worker
        with ProcessPoolExecutor(max_workers=1) as pool:
            async for packet in self.capture.sniff_continuously():
                await loop.run_in_executor(pool, self.traffic_analyze,
                                           packet)
    async def destroy(self):
        try:
            l.info("iface monitor destroyed")
            if self.capture is not None:
                await self.capture.close_async()
        finally:
            pass
