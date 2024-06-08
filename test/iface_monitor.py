import asyncio
import os
from datetime import datetime
from enum import Enum
from bcc import BPF
import pyroute2
import re
import socket
import ctypes as ct
import multiprocessing
import sys

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
bpf_program = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <uapi/linux/pkt_cls.h>

struct packet_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
    u8 mark;
};

BPF_PERF_OUTPUT(skb_events);

int mark_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) > data_end)
            return TC_ACT_OK;

        if (skb->mark == 0xb) {
            struct packet_t pkt = {};
            pkt.src_ip = ip->saddr;
            pkt.dst_ip = ip->daddr;
            pkt.protocol = ip->protocol;
            pkt.mark = skb->mark;
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
                if ((void *)(tcp + 1) > data_end)
                    return TC_ACT_OK;
                pkt.src_port = tcp->source;
                pkt.dst_port = tcp->dest;
            } else if (ip->protocol == IPPROTO_UDP) {
                struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
                if ((void *)(udp + 1) > data_end)
                    return TC_ACT_OK;
                pkt.src_port = udp->source;
                pkt.dst_port = udp->dest;
            } else {
            }
            skb_events.perf_submit_skb(skb, 0, &pkt, sizeof(struct packet_t));
        }
    }

    return TC_ACT_OK;
}
"""

protocols = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    8: "EGP",
    17: "UDP",
    27: "RDP",
    41: "IPv6",
    50: "ESP",
    51: "AH",
    58: "IPv6-ICMP",
    88: "EIGRP",
    89: "OSPF",
    103: "PIM",
    132: "SCTP",
}

g_queue = None

def to_ip_str(ip_int):
    ip = socket.inet_ntoa(ip_int.to_bytes(4, sys.byteorder))
    return ip

def process_skb_event(cpu, data, size):
    global g_queue
    class SkbEvent(ct.Structure):
        _fields_ = [("src_ip", ct.c_uint32),
                    ("dst_ip", ct.c_uint32),
                    ("src_port", ct.c_uint16),
                    ("dst_port", ct.c_uint16),
                    ("protocol", ct.c_uint8),
                    ("mark", ct.c_uint8)]
    print(f'cpu: {cpu}, data: {data}, size: {size}')
    skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents
    print(f'src_port: {socket.ntohs(skb_event.src_port)}, dst_port: {socket.ntohs(skb_event.dst_port)}')
    print(f'dst_ip: {to_ip_str(skb_event.dst_ip)}')
    g_queue.put((to_ip_str(skb_event.src_ip),
                to_ip_str(skb_event.dst_ip),
                ct.c_uint8(skb_event.mark).value,
                protocols.get(skb_event.protocol, str(skb_event.protocol)),
                ct.c_uint16(skb_event.src_port).value,
                ct.c_uint16(skb_event.dst_port).value))

def run_direct(iface):
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
    b["skb_events"].open_perf_buffer(process_skb_event)
    print(f"eBPF program loaded and attached to interface {iface}")

    try:
        while True:
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        pass
    finally:
        print("Detaching eBPF program...")
        ipr.tc("del", "clsact", idx)


def run_ebpf(queue, stop_event, iface):
    global g_queue
    g_queue = queue
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
    b["skb_events"].open_perf_buffer(process_skb_event)
    print(f"eBPF program loaded and attached to interface {iface}")

    try:
        while not stop_event.is_set():
            b.perf_buffer_poll()
    except KeyboardInterrupt:
        pass
    finally:
        print("Detaching eBPF program...")
        ipr.tc("del", "clsact", idx)


class Colors:
    HEADER = '\033[95m'
    OKRED = '\033[91m'
    OKGREEN = '\033[92m'
    OKYELLOW = '\033[93m'
    ENDC = '\033[0m'

class IfaceMonitorAction(Enum):
    ALARM = "Alarm"
    BLOCK = "Block"

class IfaceMonitorTraffic(Enum):
    EXCLUSIVE = "Exclusive"
    C2_COMM = "C2 Communication"
    MALICIOUS = "Malicious"

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
        print(f'Registered for monitoring cnc_ip: {cnc_ip}')

    async def unregister(self, cnc_ip):
        async with self.lock:
            self.cnc_ips.discard(cnc_ip)
        print(f'Unregistered cnc_ip: {cnc_ip}')

    def _init_monitor(self):
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

    def _get_report(self, src_ip, dst_ip, protocol, src_port, dst_port,
                    traffic_type, action):
        report = f"{'timestamp':<16}:{datetime.now()}\n" + \
                 f"{'src_ip':<16}:{src_ip}\n" + \
                 f"{'dst_ip':<16}:{dst_ip}\n" + \
                 f"{'protocol':<16}:{protocol}\n" + \
                 f"{'src_port':<16}:{src_port if protocol in ['TCP','UDP'] else 'NA'}\n" + \
                 f"{'dst_port':<16}:{dst_port if protocol in ['TCP','UDP'] else 'NA'}\n" + \
                 f"{'type':<16}:{traffic_type.value}\n" + \
                 f"{'action':<16}:{action}\n\n"

        color = Colors.OKGREEN
        if traffic_type == IfaceMonitorTraffic.C2_COMM:
            color = Colors.OKYELLOW
        elif traffic_type == IfaceMonitorTraffic.MALICIOUS:
            color = Colors.OKRED
        else:
            pass
        report = f'{color}{report}{Colors.ENDC}'

        return report

    def report_incidence(self, src_ip, dst_ip, protocol, src_port, dst_port,
                         traffic_type):
        with open(self.report_file, 'a') as file:
            action = self.action_type.value \
                    if traffic_type == IfaceMonitorTraffic.MALICIOUS else 'None'
            report = self._get_report(src_ip, dst_ip, protocol, src_port,
                                      dst_port, traffic_type, action)
            file.write(report)

    async def fetch_trace_output(self, queue):
        while True:
            while not queue.empty():
                src_ip, dst_ip, mark, protocol, src_port, dst_port = queue.get()
                print(f'Dubious packet detected: {src_ip} -> {dst_ip}, mark: {mark}')
                yield src_ip, dst_ip, mark, protocol, src_port, dst_port
            await asyncio.sleep(0.5)

    async def run(self):
        print('Iface monitor task started...')
        self._init_monitor()
        queue = multiprocessing.Queue()
        stop_event = multiprocessing.Event()
        ebpf_process = multiprocessing.Process(target=run_ebpf,
                                               args=(queue, stop_event, self.iface))
        ebpf_process.start()

        try:
            async for src_ip, dst_ip, mark, protocol, src_port, dst_port \
                    in self.fetch_trace_output(queue):
                async with self.lock:
                    traffic_type = IfaceMonitorTraffic.MALICIOUS
                    if dst_ip in self.cnc_ips:
                        traffic_type = IfaceMonitorTraffic.C2_COMM
                    elif dst_ip in self.excluded_ips:
                        traffic_type = IfaceMonitorTraffic.EXCLUSIVE
                    else:
                        pass

                    if traffic_type == IfaceMonitorTraffic.MALICIOUS and \
                       self.action is not None:
                        self.action()

                    self.report_incidence(src_ip, dst_ip, protocol, src_port,
                                          dst_port, traffic_type)
        except asyncio.CancelledError:
            print('iface monitor cancelled.')
            stop_event.set()
            ebpf_process.join()

if __name__ == "__main__":
    try:
        #  asyncio.get_event_loop().run_until_complete(main_task())
        ifm = IfaceMonitor('ens160',IfaceMonitorAction.ALARM, None,
                           '')
        asyncio.run(ifm.run(), debug=True)
        #  run_direct('ens160')
    except KeyboardInterrupt:
        print('Interrupted by user')

