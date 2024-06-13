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
        self.udp_srcpport = None
        self.udp_dstport = None
        self.dns_qry_name = None
        self.dns_a = None
        self.sniff_time = None

    @property
    def len(self):
        l = self.tcp_len if self.tcp_len is not None else self.udp_len
        return l

    @property
    def srcport(self):
        p = self.tcp_srcport if self.tcp_srcport is not None else self.udp_srcpport
        return p

    @property
    def dstport(self):
        p = self.tcp_dstport if self.tcp_dstport is not None else self.udp_dstport
        return p

    @property

    @property
    def protocol(self):
        prot = None
        if 'http' in self.layers:
            prot = 'http'
        elif 'ftp' in self.layers:
            prot = 'ftp'
        elif 'dns' in self.layers:
            prot = 'dns'
        elif 'ntp' in self.layers:
            prot = 'ntp'
        elif 'tcp' in self.layers:
            prot = 'tcp'
        elif 'udp' in self.layers:
            prot = 'udp'
        elif 'icmp' in self.layers:
            prot = 'icmp'
        elif 'igmp' in self.layers:
            prot = 'igmp'
        else:
            prot = 'unknown'
        return prot

    def extract(pkt):
        self.sniff_time = pkt.sniff_time
        for l in pkt.layers:
            self.layers.append(l.layer_name)
        if 'ip' in self.layers:
            self.ip_src = pkt.ip.src
            self.ip_dst = pkt.ip.dst
        if 'dns' in self.layers:
            self.dns_qry_name, self.dns_a = parse_dns(pkt)
        if 'tcp' in self.layers:
            self.tcp_len = self.tcp.len
            self.tcp_srcport = self.tcp.srcport
            self.tcp_dstport = self.tcp.dstport
            self.tcp_flags_syn = self.tcp.flags_syn
            self.tcp_flags_ack = self.tcp.flags_ack
            self.tcp_flags_fin = self.tcp.flags_fin
            self.tcp_flags_reset = self.tcp.flags_reset
        if 'udp' in self.layers:
            self.udp_len = self.udp.len
            self.udp_srcport = self.udp.srcport
            self.udp_dstport = self.udp.dstport

