import sys
import os

class AnalyzerReport:
    def __init__(self):
        self.state = 0 # 1 ready, otherwise not ready

    def is_ready(self):
        pass

    def persist(self):
        pass

class CnCReport(AnalyzerReport):
    def __init__(self):
        self.cnc_ip = None

class AttackReport(AnalyzerReport):
    def __init__(self):
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
        pass

class AttackAnalyzer(PacketAnalyzer):
    def __init__(self, cnc_report):
        self.cnc_report = cnc_report
        self.report = AttackReport()

    def analyze(self, packet):
        pass
