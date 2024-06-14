import re
import pyshark


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
        if reply_status == 0x8003:
            return pkt.dns.qry_name, None
        elif for_test == 0x8000 and "a" in dns_dir and "qry_name" in dns_dir:  # it's a response and no error
            return pkt.dns.qry_name, pkt.dns.a
    return None, None


class PacketSummary:
    def __init__(self):
        self.layers = []
        self.ip_src = None
        self.ip_dst = None
        self.tcp_len = None
        self.tcp_srcport = None
        self.tcp_dstport = None
        self.tcp_flags_syn = None
        self.tcp_flags_ack = None
        self.tcp_flags_fin = None
        self.tcp_flags_reset = None
        self.udp_len = None
        self.udp_srcport = None
        self.udp_dstport = None
        self.dns_qry_name = None
        self.dns_a = None
        self.sniff_time = None

    @property
    def len(self):
        dl = self.tcp_len if self.tcp_len is not None else self.udp_len
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
    @property
    def protocol(self):
        if 'http' in self.layers:
            proto = 'http'
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
        elif 'igmp' in self.layers:
            proto = 'igmp'
        else:
            proto = 'unknown'
        return proto

    def extract(self, pkt):
        self.sniff_time = pkt.sniff_time
        self.layers = dir(pkt)

        if 'ip' in self.layers:
            self.ip_src = pkt.ip.src
            self.ip_dst = pkt.ip.dst
        if 'dns' in self.layers:
            self.dns_qry_name, self.dns_a = parse_dns(pkt)
        if 'tcp' in self.layers:
            self.tcp_len = pkt.tcp.len
            self.tcp_srcport = pkt.tcp.srcport
            self.tcp_dstport = pkt.tcp.dstport
            self.tcp_flags_syn = pkt.tcp.flags_syn
            self.tcp_flags_ack = pkt.tcp.flags_ack
            self.tcp_flags_fin = pkt.tcp.flags_fin
            self.tcp_flags_reset = pkt.tcp.flags_reset
        if 'udp' in self.layers:
            self.udp_len = pkt.udp.len
            self.udp_srcport = pkt.udp.srcport
            self.udp_dstport = pkt.udp.dstport
