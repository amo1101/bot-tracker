import sys
import os
from db import *
from log import TaskLogger

l = TaskLogger(__name__)

class AnalyzerReport:
    def __init__(self):
        self.state = 0 # 1 ready, otherwise not ready

    def is_ready(self):
        return True

    def persist(self):
        pass

class CnCReport(AnalyzerReport):
    def __init__(self):
        self.cnc_ip = None
        self.packet = None

    def persist(self):
        #  l.debug(f'cnc report persisted: {self.packet}')
        pass

class AttackReport(AnalyzerReport):
    def __init__(self):
        self.packet = None

    def persist(self):
        #  l.debug(f'attack report persisted: {self.packet}')
        pass

class PacketAnalyzer:
    def __init__(self):
        pass

    def analyze(self, packet):
        pass

class CnCAnalyzer(PacketAnalyzer):
    def __init__(self):
        self.report = CnCReport()

    def analyze(self, packet):
        #  l.debug('analyzing packet')
        self.report.packet = packet
        return self.report

class AttackAnalyzer(PacketAnalyzer):
    def __init__(self, cnc_report):
        self.cnc_report = cnc_report
        self.report = AttackReport()

    def analyze(self, packet):
        self.report.packet = packet
        return self.report
