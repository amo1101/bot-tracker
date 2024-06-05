import asyncio
import os
from datetime import datetime
from packet_capture import *
from enum import Enum

l: TaskLogger = TaskLogger(__name__)
CUR_DIR = os.path.dirname(os.path.abspath(__file__))


class IfaceMonitorAction(Enum):
    ALARM = "Alarm"
    BLOCK = "Block"

class IfaceMonitor:
    def __init__(self,
                 iface,
                 action_type,
                 action,
                 excluded_ips):
        self.iface = iface
        self.action_type = action_type
        self.action = action
        self.excluded_ips = excluded_ips.split(',')
        self.capture = None
        self.cnc_ips= set()
        self.log_dir = CUR_DIR + os.sep + 'iface_monitor_log'
        self.report_file = self.log_dir + os.sep + f'iface-monitor-report-{self.iface}.log'

    # bots call the api to register monitoring
    def register(self, cnc_ip):
        self.cnc_ips.add(cnc_ip)
        l.debug(f'Registered for monitoring cnc_ip: {cnc_ip}')

    def unregister(self, cnc_ip):
        self.cnc_ips.discard(cnc_ip)
        l.debug(f'Unregistered cnc_ip: {cnc_ip}')

    def _init_monitor(self):
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

        if self.capture is None:
            # filter outgoing packets
            output_file = self.log_dir + os.sep + f'iface-monitor-{self.iface}.pcap'
            bpf_filter = ' and '.join(['not dst host ' + dst for dst in self.excluded_ips])
            l.info(f'Iface monitor bpf filter: {bpf_filter}')
            self.capture = AsyncLiveCapture(interface=self.iface,
                                            bpf_filter=bpf_filter,
                                            output_file=output_file,
                                            debug=False)

    def _get_report(self, pkt):
        dst = pkt.ip.dst
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

        report = f"{'timestamp':<16}:{datetime.now()}\n" + \
                 f"{'src_ip':<16}:{src}\n" + \
                 f"{'src_port':<16}:{src_port}\n" + \
                 f"{'dst_ip':<16}:{dst}\n" + \
                 f"{'dst_port':<16}:{dst_port}\n" + \
                 f"{'protocol':<16}:{prot}\n" + \
                 f"{'action':<16}:{self.action_type.value}\n\n"

        return report

    def report_incidence(self, pkt):
        with open(self.report_file, 'a') as file:
            report = self._get_report(pkt)
            file.write(report)

    def monitoring(self, pkt):
        dst = pkt.ip.dst

        # if sent from a bot and dst is not cnc, then this is an
        # violation, report it and take action
        if dst not in self.cnc_ips:
            return 1
        return 0

    async def run(self):
        try:
            self._init_monitor()
            async for packet in self.capture.sniff_continuously():
                res = self.monitoring(packet)
                if res == 1 and self.action is not None:
                    self.action()
                    self.report_incidence(packet)
        except asyncio.CancelledError:
            l.debug('iface monitor cancelled.')

    async def destroy(self):
        try:
            l.info("iface monitor destroyed")
            if self.capture is not None:
                await self.capture.close_async()
        finally:
            pass
