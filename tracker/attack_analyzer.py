import sys
import os
import pyshark
from db_store import CnCStatus


class AttackReport:
    def __init__(self, cnc_ip, cnc_port):
        self.cnc_status = CnCStatus.UNKNOWN.value
        self.cnc_ready = False
        self.attack_ready = False
        self.cnc_ip = cnc_ip
        self.cnc_port = cnc_port

    def is_ready(self):
        return self.cnc_ready

    def get(self):
        self.cnc_ready = False
        return {'cnc_ip': self.cnc_ip,
                'cnc_port': self.cnc_port,
                'cnc_status': self.cnc_status}

    def __repr__(self):
        return f'cnc_status: {self.cnc_status}\n' + \
            f'cnc_ready: {self.cnc_ready}\n' + \
            f'attack_ready: {self.attack_ready}\n' + \
            f'cnc_ip: {self.cnc_ip}\n'


# avoiding logging here cuz this will run in another python intepretor
# don't wanna bother logging to the same file, just use print for debugging
class AttackAnalyzer:
    def __init__(self, cnc_ip, cnc_port, own_ip):
        self.cnc_ip = cnc_ip
        self.cnc_port = cnc_port
        self.own_ip = own_ip
        self.report = AttackReport(cnc_ip, cnc_port)

    def _analyze_cnc_status(self, pkt):
        if 'tcp' in dir(pkt):
            # we only monitor sync_ack or fin_ack from server -> client
            if pkt.ip.src == self.cnc_ip and pkt.ip.dst == self.own_ip:
                if pkt.tcp.flags_fin == '1':
                    # server initiate FIN, connection broken
                    if self.report.cnc_status != CnCStatus.DISCONNECTED.value:
                        self.report.cnc_status = CnCStatus.DISCONNECTED.value
                        self.report.cnc_ready = True
                else:
                    # if sync ack from server, or data exchange from server
                    if (pkt.tcp.flags_syn == '1' and pkt.tcp.flags_ack == '1') \
                       or (pkt.tcp.len != '0'):
                        if self.report.cnc_status != CnCStatus.ALIVE.value:
                            self.report.cnc_status = CnCStatus.ALIVE.value
                            self.report.cnc_ready = True

    def _analyze_attack(self, pkt):
        pass

    def analyze(self, pkt):
        self._analyze_cnc_status(pkt)
        self._analyze_attack(pkt)
        return self.report


att_analyzer = None


def inspect_packet(pkt):
    att_analyzer.analyze(pkt)
    if att_analyzer.report.is_ready():
        print(f'result of att_analyze: {att_analyzer.report.get()}')


def test_att_analyzer(pcap, cnc_ip, cnc_port, own_ip):
    global att_analyzer
    if att_analyzer is not None:
        del att_analyzer
    att_analyzer = AttackAnalyzer(cnc_ip, cnc_port, own_ip)
    cap = pyshark.FileCapture(pcap)
    cap.apply_on_packets(inspect_packet)
