import sys
import os
import pyshark
from log import TaskLogger
from db_store import CnCStatus

CUR_DIR = os.path.dirname(os.path.abspath(__file__))

l = TaskLogger(__name__)


class AttackReport:
    def __init__(self, cnc_ip):
        self.cnc_status = CnCStatus.UNKNOWN.value
        self.cnc_ready = False
        self.attack_ready = False
        self.cnc_ip = cnc_ip

    def is_ready(self):
        return self.cnc_ready

    def get(self):
        self.cnc_ready = False
        return {'cnc_ip': self.cnc_ip,
                'cnc_status': self.cnc_status}

    def __repr__(self):
        return f'cnc_status: {self.cnc_status}\n' + \
            f'cnc_ready: {self.cnc_ready}\n' + \
            f'attack_ready: {self.attack_ready}\n' + \
            f'cnc_ip: {self.cnc_ip}\n'


class AttackAnalyzer:
    def __init__(self, cnc_ip, cnc_port, own_ip):
        self.cnc_ip = cnc_ip
        self.cnc_port = cnc_port
        self.own_ip = own_ip
        self.report = AttackReport(cnc_ip)

    def _analyze_cnc_status(self, pkt):
        if 'tcp' in dir(pkt):
            # we only monitor sync_ack or fin_ack from server -> client
            if pkt.ip.src == self.cnc_ip and pkt.ip.dst == self.own_ip:
                if pkt.tcp.flags_syn == '1' and pkt.tcp.flags_ack == '1':
                    # server ACK the SYN, connection established
                    self.report.cnc_status = CnCStatus.ALIVE.value
                    self.report.cnc_ready = True
                elif pkt.tcp.flags_fin == '1':
                    # server initiate FIN, connection broken
                    self.report.cnc_status = CnCStatus.DISCONNECTED.value
                    self.report.cnc_ready = True
                else:
                    pass

    def _analyze_attack(self, pkt):
        pass

    def analyze(self, pkt):
        l.debug(f'report 0: {self.report}')
        self._analyze_cnc_status(pkt)
        self._analyze_attack(pkt)
        l.debug(f'report 1: {self.report}')
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
