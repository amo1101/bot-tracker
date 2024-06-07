import asyncio
import os
from datetime import datetime
from enum import Enum
from bcc import BPF
import pyroute2
import re
import socket
import multiprocessing
from log import TaskLogger


l: TaskLogger = TaskLogger(__name__)
CUR_DIR = os.path.dirname(os.path.abspath(__file__))
bpf_program = """
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

int mark_filter(struct __sk_buff *skb) {
    // Parse Ethernet header
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    // Parse IP header
    if (eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;

        // Only process marked packets
        if (skb->mark == 1) {
            // l.debug source and destination IP addresses
            bpf_trace_printk("src_ip=%x, dst_ip=%x, mark=%x\\n", ip->saddr, ip->daddr, skb->mark);
        }
    }

    return TC_ACT_OK;
}

"""

def parse_trace_output(output):
    pattern = re.compile(r'src_ip=(\w+), dst_ip=(\w+), mark=(\w+)')
    match = pattern.search(output)
    if match:
        src_ip = match.group(1)
        dst_ip = match.group(2)
        mark = match.group(3)
        return socket.inet_ntoa(int(src_ip, 16).to_bytes(4, 'little')),\
               socket.inet_ntoa(int(dst_ip, 16).to_bytes(4, 'little')),\
               mark

    return None, None, None

def run_ebpf(queue, stop_event, iface):
    # /sys/kernel/debug/tracing/buffer_size_kb: 1048kb, should be enough
    b = BPF(text=bpf_program)
    fn = b.load_func("mark_filter", BPF.SCHED_CLS)

    ipr = pyroute2.IPRoute()
    idx = ipr.link_lookup(ifname=iface)[0]

    try:
        ipr.tc("del", "clsact", idx)
    except pyroute2.netlink.exceptions.NetlinkError:
        print('pyroute2.netlink.exceptions.NetlinkError occurred, ignored')

    ipr.tc("add", "clsact", idx)
    ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff3", classid=1, direct_action=True)
    print(f"eBPF program loaded and attached to interface {iface}")

    try:
        while not stop_event.is_set():
            line = b.trace_readline()
            if line:
                line = line.decode('utf-8')
                src_ip, dst_ip, mark = parse_trace_output(line)
                print(f'Dubious packet detected from trace pipe: {src_ip} -> {dst_ip}, mark: {mark}')
                if src_ip and dst_ip:
                    queue.put((src_ip, dst_ip, mark))
    except KeyboardInterrupt:
        pass
    finally:
        print("Detaching eBPF program...")
        ipr.tc("del", "clsact", idx)


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
        self.cnc_ips= set()
        self.lock = asyncio.Lock()
        self.log_dir = CUR_DIR + os.sep + 'iface_monitor_log'
        self.report_file = self.log_dir + os.sep + f'iface-monitor-report-{self.iface}.log'

    # bots call the api to register monitoring
    async def register(self, cnc_ip):
        async with self.lock:
            self.cnc_ips.add(cnc_ip)
        l.debug(f'Registered for monitoring cnc_ip: {cnc_ip}')

    async def unregister(self, cnc_ip):
        async with self.lock:
            self.cnc_ips.discard(cnc_ip)
        l.debug(f'Unregistered cnc_ip: {cnc_ip}')

    def _init_monitor(self):
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

    def _get_report(self, src_ip, dst_ip):
        report = f"{'timestamp':<16}:{datetime.now()}\n" + \
                 f"{'src_ip':<16}:{src_ip}\n" + \
                 f"{'dst_ip':<16}:{dst_ip}\n" + \
                 f"{'action':<16}:{self.action_type.value}\n\n"

        return report

    def report_incidence(self, src_ip, dst_ip):
        with open(self.report_file, 'a') as file:
            report = self._get_report(src_ip, dst_ip)
            file.write(report)

    async def fetch_trace_output(self, queue):
        while True:
            while not queue.empty():
                src_ip, dst_ip, mark = queue.get()
                l.debug(f'Dubious packet detected: {src_ip} -> {dst_ip}, mark: {mark}')
                yield src_ip, dst_ip, mark
            await asyncio.sleep(0.5)

    async def run(self):
        l.info('Iface monitor task started...')
        self._init_monitor()
        queue = multiprocessing.Queue()
        stop_event = multiprocessing.Event()
        ebpf_process = multiprocessing.Process(target=run_ebpf,
                                               args=(queue, stop_event, self.iface))
        ebpf_process.start()

        try:
            async for src_ip, dst_ip, mark in self.fetch_trace_output(queue):
                async with self.lock:
                    if dst_ip not in self.cnc_ips and \
                       dst_ip not in self.excluded_ips:
                        if self.action is not None:
                            self.action()
                        self.report_incidence(src_ip, dst_ip)
        except asyncio.CancelledError:
            l.debug('iface monitor cancelled.')
            stop_event.set()
            ebpf_process.join()

