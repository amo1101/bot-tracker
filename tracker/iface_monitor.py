import signal
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
from log import TaskLogger

l: TaskLogger = TaskLogger(__name__)
CUR_DIR = os.path.dirname(os.path.abspath(__file__))
bpf_program = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <uapi/linux/pkt_cls.h>

BPF_HASH(policy_table, u32, u32);

struct packet_t {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
    u8 policy;
    u8 mark;
};

BPF_PERF_OUTPUT(skb_events);

int mark_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }

    if (eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) > data_end) {
            return TC_ACT_OK;
        }

        if (skb->mark == 0xb) {
            struct packet_t pkt = {};
            pkt.src_ip = ip->saddr;
            pkt.dst_ip = ip->daddr;
            pkt.protocol = ip->protocol;
            pkt.mark = skb->mark;
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
                if ((void *)(tcp + 1) > data_end) {
                    return TC_ACT_OK;
                }
                pkt.src_port = tcp->source;
                pkt.dst_port = tcp->dest;
            } else if (ip->protocol == IPPROTO_UDP) {
                struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
                if ((void *)(udp + 1) > data_end) {
                    return TC_ACT_OK;
                }
                pkt.src_port = udp->source;
                pkt.dst_port = udp->dest;
            } else {
            }

            u32* policy = NULL;
            u32 default_policy_key = 0;
            policy = policy_table.lookup(&pkt.dst_ip);
            if (policy == NULL) {
                policy = policy_table.lookup(&default_policy_key);
            }

            if (policy == NULL) {
                return TC_ACT_OK;
            }

            pkt.policy = *policy;
            if (pkt.policy == 2) {
                if (pkt.dst_port == 53) {
                    pkt.policy = 1;
                }
                else {
                    pkt.policy = 0;
                }
            }

            skb_events.perf_submit_skb(skb, 0, &pkt, sizeof(struct packet_t));

            if (pkt.policy == 0) {
                return TC_ACT_SHOT;
            }
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

DNS_PORT = 53
DEFAULT_POLICY_BLOCK = 0
DEFAULT_POLICY_ALLOW = 1
DEFAULT_POLICY_BLOCK_ALLOW_DNS = 2

g_trace_pipe = None
g_cnc_queue = None # only for block network mode
g_policy_table = None

def int_ip_to_str(ip_int):
    ip = socket.inet_ntoa(ip_int.to_bytes(4, sys.byteorder))
    return ip

def str_ip_to_int(ip_str):
    ip_int = socket.inet_aton(ip_str)
    return int.from_bytes(ip_int, sys.byteorder)

def process_skb_event(cpu, data, size):
    global g_trace_pipe
    global g_cnc_queue
    global g_policy_table

    class SkbEvent(ct.Structure):
        _fields_ = [("src_ip", ct.c_uint32),
                    ("dst_ip", ct.c_uint32),
                    ("src_port", ct.c_uint16),
                    ("dst_port", ct.c_uint16),
                    ("protocol", ct.c_uint8),
                    ("policy", ct.c_uint8),
                    ("mark", ct.c_uint8)]

    try:
        # should not block
        if g_cnc_queue is not None:
            while not g_cnc_queue.empty():
                ip_str, op = g_cnc_queue.get(False)
                ip_int = str_ip_to_int(ip_str)
                ip_key = ct.c_uint32(ip_int)
                if op == 1:
                    g_policy_table[ip_key] = ct.c_uint32(1)  # allow cnc ip
                    l.info(f'adding policy {ip_str}: 1')
                else:
                    if ip_key in g_policy_table:
                        del g_policy_table[ip_key]
                        l.info(f'deleting policy of {ip_str}')
                g_policy_table.update()
                l.info('policy table updated')

        skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents
        g_trace_pipe.send((int_ip_to_str(skb_event.src_ip),
                          int_ip_to_str(skb_event.dst_ip),
                          ct.c_uint8(skb_event.mark).value,
                          ct.c_uint8(skb_event.policy).value,
                          protocols.get(skb_event.protocol, str(skb_event.protocol)),
                          ct.c_uint16(skb_event.src_port).value,
                          ct.c_uint16(skb_event.dst_port).value))
        del skb_event
    except Exception as e:
        l.error(f'An error occurred {e} in SkbEvent cb')

def run_ebpf(iface,
             default_policy,
             excluded_ips,
             trace_pipe,
             cnc_queue,
             stop_event):
    global g_trace_pipe
    global g_cnc_queue
    global g_policy_table

    signal.signal(signal.SIGINT, signal.SIG_IGN)

    g_trace_pipe = trace_pipe
    g_cnc_queue = cnc_queue

    b = BPF(text=bpf_program)
    fn = b.load_func("mark_filter", BPF.SCHED_CLS)

    g_policy_table = b.get_table("policy_table")

    # default policy
    # 0: block all in block network mode except excluded ips and cnc
    # 1: allow all in rate-limit network mode
    default_policy_key = ct.c_uint32(0)
    l.info('Initializing policy table...')
    g_policy_table[default_policy_key] = ct.c_uint32(default_policy) # allow, 0 is key for default policy
    if default_policy != DEFAULT_POLICY_ALLOW:
        for ip_str in excluded_ips:
            ip_int = str_ip_to_int(ip_str)
            ip_key = ct.c_uint32(ip_int)
            g_policy_table[ip_key] = ct.c_uint32(1) # allow
            l.info(f'adding policy {ip_str}: 1...')
    l.info(f'default policy {g_policy_table[default_policy_key].value}...')

    ipr = pyroute2.IPRoute()
    idx = ipr.link_lookup(ifname=iface)[0]

    try:
        ipr.tc("del", "clsact", idx)
    except pyroute2.netlink.exceptions.NetlinkError:
        pass
        #  l.info('pyroute2.netlink.exceptions.NetlinkError occurred, ignored')

    ipr.tc("add", "clsact", idx)
    ipr.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name, parent="ffff:fff3", classid=1, direct_action=True)
    b["skb_events"].open_perf_buffer(process_skb_event)
    l.info(f"eBPF program loaded and attached to interface {iface}")

    try:
        while not stop_event.is_set():
            b.perf_buffer_poll(100)
        l.info('Stopped by stop event.')
    except Exception as e:
        l.warning(f'An error occured {e} on iface monitor process!')
    finally:
        l.info("Detaching eBPF program...")
        ipr.tc("del", "clsact", idx)


class Colors:
    HEADER = '\033[95m'
    OKRED = '\033[91m'
    OKGREEN = '\033[92m'
    OKYELLOW = '\033[93m'
    ENDC = '\033[0m'

class IfaceMonitorAction(Enum):
    TEAR_DOWN = "Tear Down"
    ALARM = "Alarm"

class IfaceMonitorTraffic(Enum):
    EXCLUSIVE = "Exclusive"
    C2_COMM = "C2 Communication"
    MALICIOUS = "Malicious"

class IfaceMonitor:
    def __init__(self,
                 iface,
                 default_policy,
                 excluded_ips,
                 mute_report,
                 action_type,
                 action):
        self.iface = iface
        self.default_policy = default_policy
        self.excluded_ips = excluded_ips.split(',')
        self._mute_report = mute_report
        self.action_type = action_type
        self.action = action
        self.cnc_queue = None
        self.trace_pipe = None
        self.stop_event = None
        self.ebpf_process = None
        self.lock = asyncio.Lock()
        self.cnc_map = {}
        self.log_dir = CUR_DIR + os.sep + 'iface_monitor_log'
        self.report_file = self.log_dir + os.sep + f'iface-monitor-report-{self.iface}.log'

    # bots call the api to register monitoring
    async def register(self, cnc_ip, bot_id):
        async with self.lock:
            l.info(f'Registered cnc_ip: {cnc_ip} of bot_id: {bot_id}')
            if cnc_ip in self.cnc_map:
                self.cnc_map[cnc_ip].append(bot_id)
                return
            self.cnc_map[cnc_ip] = [bot_id]
            if self.default_policy != DEFAULT_POLICY_ALLOW:
                self.cnc_queue.put((cnc_ip, 1)) # 1 means add

    async def unregister(self, cnc_ip, bot_id):
        async with self.lock:
            if cnc_ip not in self.cnc_map:
                return
            try:
                l.info(f'Unregistered cnc_ip: {cnc_ip} of bot_id: {bot_id}')
                self.cnc_map[cnc_ip].remove(bot_id)
                if len(self.cnc_map[cnc_ip]) == 0:
                    if self.default_policy != DEFAULT_POLICY_ALLOW:
                        self.cnc_queue.put((cnc_ip, 0)) # 0 means delete
                    del self.cnc_map[cnc_ip]
            except ValueError:
                pass

    def mute_report(self, mute=True):
        self._mute_report = mute

    def _init_monitor(self):
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        self.trace_pipe = multiprocessing.Pipe()
        if self.default_policy != DEFAULT_POLICY_ALLOW:
            self.cnc_queue = multiprocessing.Queue()
        self.stop_event = multiprocessing.Event()

    def _get_report(self, src_ip, dst_ip, protocol, src_port, dst_port, policy,
                    traffic_type, action):
        desc = traffic_type.value
        if dst_ip in self.cnc_map:
            desc = f"{desc} (bot_id: {','.join(self.cnc_map[dst_ip])})"

        report = f"{'timestamp':<16}:{datetime.now()}\n" + \
                 f"{'src_ip':<16}:{src_ip}\n" + \
                 f"{'dst_ip':<16}:{dst_ip}\n" + \
                 f"{'protocol':<16}:{protocol}\n" + \
                 f"{'src_port':<16}:{src_port if protocol in ['TCP','UDP'] else 'NA'}\n" + \
                 f"{'dst_port':<16}:{dst_port if protocol in ['TCP','UDP'] else 'NA'}\n" + \
                 f"{'policy':<16}:{'Dropped' if policy == 0 else 'Allowed'}\n" + \
                 f"{'type':<16}:{desc}\n" + \
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

    def report_incidence(self, src_ip, dst_ip,
                         protocol, src_port, dst_port,
                         policy, traffic_type):
        if self._mute_report:
            return
        with open(self.report_file, 'a') as file:
            action = self.action_type.value \
                        if traffic_type == IfaceMonitorTraffic.MALICIOUS else 'None'
            report = self._get_report(src_ip, dst_ip, protocol, src_port,
                                      dst_port, policy, traffic_type, action)
            file.write(report)

    async def fetch_trace_output(self):
        while True:
            while self.trace_pipe[0].poll():
                src_ip, dst_ip, mark, policy, protocol, src_port, dst_port = \
                    self.trace_pipe[0].recv()
                l.debug(f'Dubious packet detected: {src_ip} -> {dst_ip}, mark: {mark}, policy {policy}')
                yield src_ip, dst_ip, mark, policy, protocol, src_port, dst_port
            await asyncio.sleep(0.5)

    async def run(self):
        l.info('Iface monitor task started...')
        self._init_monitor()
        self.ebpf_process = multiprocessing.Process(target=run_ebpf,
                                                    args=(self.iface,
                                                          self.default_policy,
                                                          self.excluded_ips,
                                                          self.trace_pipe[1],
                                                          self.cnc_queue,
                                                          self.stop_event))
        self.ebpf_process.start()

        try:
            async for src_ip, dst_ip, mark, policy, protocol, src_port, dst_port \
                    in self.fetch_trace_output():
                async with self.lock:
                    traffic_type = IfaceMonitorTraffic.MALICIOUS \
                        if self.default_policy != DEFAULT_POLICY_ALLOW \
                        else IfaceMonitorTraffic.EXCLUSIVE
                    if dst_ip in self.cnc_map:
                        traffic_type = IfaceMonitorTraffic.C2_COMM
                    elif dst_ip in self.excluded_ips:
                        traffic_type = IfaceMonitorTraffic.EXCLUSIVE
                    elif dst_port == DNS_PORT and self.default_policy == \
                            DEFAULT_POLICY_BLOCK_ALLOW_DNS:
                        traffic_type = IfaceMonitorTraffic.EXCLUSIVE
                    else:
                        pass

                    if traffic_type == IfaceMonitorTraffic.MALICIOUS and \
                       self.action is not None:
                        await self.action()

                    self.report_incidence(src_ip, dst_ip, protocol, src_port,
                                          dst_port, policy, traffic_type)
        except asyncio.CancelledError:
            l.info('Iface monitor cancelled.')
        except Exception as e:
            l.warning(f'An error occured {e}!')
        finally:
            self.stop_event.set()
            self.ebpf_process.join()
            l.info('Iface monitor process quit')

