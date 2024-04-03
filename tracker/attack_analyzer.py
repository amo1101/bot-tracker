import sys
import os
from log import TaskLogger

l = TaskLogger(__name__)

class AttackReport():
    def __init__(self, cnc_ip):
        self.cnc_status = None
        self.cnc_ready = False
        self.attack_ready = False
        self.cnc_ip = cnc_ip

    def is_ready(self):
        return self.cnc_ready

    def get(self):
        self.cnc_ready = False
        return {'cnc_ip': cnc_ip,
                'cnc_status': self.cnc_status}

class AttackAnalyzer():
    def __init__(self, cnc_ip, cnc_port, own_ip):
        self.cnc_ip = cnc_ip
        self.cnc_port = cnc_port
        self.own_ip = own_ip
        self.report = AttackReport(cnc_ip)

    def _analyze_cnc_status(self, pkt):
        state = ""
        if 'tcp' in dir(pkt):
            if pkt.ip.src == self.cnc_ip and pkt.ip.dst == self.own_ip:
                self.report.cnc_ready = True
                if pkt.tcp.flags_syn=='1':
                    if pkt.tcp.flags_ack!="1":
                        state = "SYN"
                    else:
                        state = "SYN_ACK"
                else:
                    if pkt.tcp.flags_reset=='1':
                        state = "RST"
                    elif pkt.tcp.flags_fin=="1":
                        state = "FIN"
                    elif pkt.tcp.len!="0":
                        state = "SUC"
                    else:
                        state = "OTHER"

        if state in ["SYN","SYN_ACK",'SUC',"OTHER"]:
            if self.report.cnc_status != CnCStatus.ALIVE.value:
                self.report.cnc_ready = True
                self.report.cnc_status = CnCStatus.ALIVE.value
        elif state in ["RST", "FIN"]:
            if self.report.cnc_status != CnCStatus.DISCONNECTED.value:
                self.report.cnc_ready = True
                self.report.cnc_status = CnCStatus.DISCONNECTED.value

    def _analyze_attack(self, pkt):
        pass

    def analyze(self, pkt):
        self._analyze_cnc_status(pkt)
        self._analyze_attack(pkt)
        return self.report
