import re
import pyshark
from log import TaskLogger

l: TaskLogger = TaskLogger(__name__)


def is_background_traffic(pkt, background_fields):
    for field in background_fields:
        if field in pkt.layers:
            return True
    return False


def validate_ip_format(ip_str):
    ip_param = ip_str
    reg_exp = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if ":" in ip_str:
        li = ip_str.split(":")
        if len(li) >= 2:
            ip_param = li[0]
    res = False
    try:
        m = re.match(reg_exp, ip_param)
        if m:
            res = True
    except:
        res = False
    return res


def parse_dns(pkt):
    if 'dns' in dir(pkt):
        dns_dir = dir(pkt.dns)
        for_test = int(pkt.dns.flags.hex_value) & 0x8001
        reply_status = int(pkt.dns.flags.hex_value) & 0x8003  # this means response and no reply in DNS
        if reply_status == 0x8003 and "qry_name" in dns_dir:
            return pkt.dns.qry_name, None
        elif for_test == 0x8000 and "a" in dns_dir and "qry_name" in dns_dir:  # it's a response and no error
            return pkt.dns.qry_name, pkt.dns.a.all_fields
    return None, None


class PacketSummary:
    def __init__(self):
        self.layers = []
        self.layer_names = []
        self.ip_src = None
        self.ip_dst = None
        self.ip_len = None  # ip payload length for protocol other than tcp and udp
        self.tcp_len = None
        self.tcp_srcport = None
        self.tcp_dstport = None
        self.tcp_flags_syn = None
        self.tcp_flags_ack = None
        self.tcp_flags_fin = None
        self.tcp_flags_reset = None
        self.tcp_retransmission = None
        self.udp_len = None
        self.udp_srcport = None
        self.udp_dstport = None
        self.dns_qry_name = None
        self.dns_a = None
        self.sniff_time = None

    def __repr__(self):
        return 'Summary of packet:\n' + \
            f'layers: {self.layer_names}\n' + \
            f'ip_src: {self.ip_src}\n' + \
            f'ip_dst: {self.ip_dst}\n' + \
            f'ip_len: {self.ip_len}\n' + \
            f'tcp_len: {self.tcp_len}\n' + \
            f'tcp_srcport: {self.tcp_srcport}\n' + \
            f'tcp_dstport: {self.tcp_dstport}\n' + \
            f'tcp_flags_syn: {self.tcp_flags_syn}\n' + \
            f'tcp_flags_ack: {self.tcp_flags_ack}\n' + \
            f'tcp_flags_fin: {self.tcp_flags_fin}\n' + \
            f'tcp_flags_reset: {self.tcp_flags_reset}\n' + \
            f'tcp_retransmission: {self.tcp_retransmission}\n' + \
            f'udp_len: {self.udp_len}\n' + \
            f'udp_srcport: {self.udp_srcport}\n' + \
            f'udp_dstport: {self.udp_dstport}\n' + \
            f'dns_qry_name: {self.dns_qry_name}\n' + \
            f'dns_a: {self.dns_a}\n' + \
            f'sniff_time: {self.sniff_time}\n'

    @property
    def len(self):
        dl = self.tcp_len if self.tcp_len is not None else self.udp_len
        if dl is None:
            dl = self.ip_len
        return dl

    @property
    def srcport(self):
        p = self.tcp_srcport if self.tcp_srcport is not None else self.udp_srcport
        return p

    @property
    def dstport(self):
        p = self.tcp_dstport if self.tcp_dstport is not None else self.udp_dstport
        return p

    @property
    def protocol(self):
        if 'http' in self.layers:
            proto = 'http'
        elif 'ssl' in self.layers:
            proto = 'ssl'
        elif 'ftp' in self.layers:
            proto = 'ftp'
        elif 'dns' in self.layers:
            proto = 'dns'
        elif 'ntp' in self.layers:
            proto = 'ntp'
        elif 'tcp' in self.layers:
            proto = 'tcp'
        elif 'udp' in self.layers:
            proto = 'udp'
        elif 'icmp' in self.layers:
            proto = 'icmp'
        else:
            proto = 'unknown'
        return proto

    @property
    def src_net(self):
        if self.ip_src is None:
            return None
        return '.'.join(self.ip_src.split('.')[:3]) + '.0/24'

    @property
    def dst_net(self):
        if self.ip_dst is None:
            return None
        return '.'.join(self.ip_dst.split('.')[:3]) + '.0/24'

    def extract(self, pkt):
        self.sniff_time = pkt.sniff_time
        self.layers = dir(pkt)
        self.layer_names = [l.layer_name for l in pkt.layers]

        if 'ip' in self.layers:
            self.ip_src = str(pkt.ip.src)
            self.ip_dst = str(pkt.ip.dst)
            self.ip_len = int(pkt.ip.len) - int(pkt.ip.hdr_len)
        if 'dns' in self.layers:
            self.dns_qry_name, self.dns_a = parse_dns(pkt)
        if 'tcp' in self.layers:
            #  print(f'tcp: {dir(pkt.tcp)}')
            self.tcp_len = int(pkt.tcp.len)
            self.tcp_srcport = str(pkt.tcp.srcport)
            self.tcp_dstport = str(pkt.tcp.dstport)
            self.tcp_flags_syn = 'True' if hasattr(pkt.tcp, 'flags_syn') and str(pkt.tcp.flags_syn) in ['1', 'True'] else 'False'
            self.tcp_flags_ack = 'True' if hasattr(pkt.tcp, 'flags_ack') and str(pkt.tcp.flags_ack) in ['1', 'True'] else 'False'
            self.tcp_flags_fin = 'True' if hasattr(pkt.tcp, 'flags_fin') and str(pkt.tcp.flags_fin) in ['1', 'True'] else 'False'
            self.tcp_flags_reset = 'True' if hasattr(pkt.tcp, 'flags_reset') and str(pkt.tcp.flags_reset) in ['1', 'True'] else 'False'
            if hasattr(pkt.tcp, 'analysis_retransmission') or \
               hasattr(pkt.tcp, 'analysis_fast_retransmission'):
                self.tcp_retransmission = 'True'
            else:
                self.tcp_retransmission = 'False'
        if 'udp' in self.layers:
            #  print(f'udp: {dir(pkt.udp)}')
            self.udp_len = int(pkt.udp.length)
            self.udp_srcport = str(pkt.udp.srcport)
            self.udp_dstport = str(pkt.udp.dstport)

