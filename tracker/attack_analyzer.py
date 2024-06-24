import pyshark
import copy
from db_store import CnCStatus, AttackType
from datetime import datetime, timedelta
from dataclasses import dataclass
from collections import deque
from packet_parser import *
from log import TaskLogger

l: TaskLogger = TaskLogger(__name__)


class AttackStat:
    def __init__(self):
        self.attack_type = None
        self.start_time = None
        self.duration = None
        self.src = set()
        self.target = set()
        self.protocol = set()
        self.src_port = set()
        self.dst_port = set()
        self.spoofed = set()
        self.update_time = None
        self.packet_cnt = 0
        self.total_bytes = 0

    def reset(self):
        self.attack_type = None
        self.start_time = None
        self.duration = None
        self.src.clear()
        self.target.clear()
        self.protocol.clear()
        self.src_port.clear()
        self.dst_port.clear()
        self.spoofed.clear()
        self.update_time = None
        self.packet_cnt = 0
        self.total_bytes = 0

    def update(self, attack_type, pkt, spoofed):
        if self.packet_cnt == 0:
            self.attack_type = attack_type
            self.start_time = pkt.ts

        if attack_type == AttackType.ATTACK_SCAN.value:
            self.src.add(pkt.ip_src)
            self.dst_port.add(pkt.dst_port)
        if attack_type == AttackType.ATTACK_RA.value:
            self.target.add(pkt.ip_src)
            self.dst_port.add(pkt.dst_port)
        if attack_type == AttackType.ATTACK_DP.value:
            self.target.add(pkt.ip_dst)

        self.protocol.add(pkt.protocol)
        self.spoofed.add(spoofed)
        self.packet_cnt += 1
        self.total_bytes += pkt.len
        self.update_time = pkt.ts
        self.duration = self.update_time - self.start_time

    def report(self):
        if len(self.target) > 1:
            first_e = next(iter(self.target))
            target = '.'.join(first_e.split('.')[:3]) + '.0/24'
        else:
            target = ','.join(self.target)

        return {'attack_type': self.attack_type,
                'start_time': self.start_time,
                'duration': self.duration,
                'target': target,
                'protocol': ','.join(self.protocol),
                'src_port': ','.join(self.src_port),
                'dst_port': ','.join(self.dst_port),
                'spoofed': ','.join(self.spoofed),
                'packet_cnt': self.packet_cnt,
                'total_bytes': self.total_bytes}


class AttackDetector:
    def __init__(self, water_mark, attack_gap, min_attack_packets, own_ip):
        self.packet_group = {}
        self.stats = {}
        self.water_mark = water_mark
        self.attack_gap = attack_gap
        self.min_attack_packets = min_attack_packets
        self.own_ip = own_ip
        self.pkey_getter = None
        self.skey_getter = None

    def _set_key_getter(pkey_getter, skey_getter)
        self.pkey_getter = pkey_getter
        self.skey_getter = skey_getter

    def _add_to_group(self, pkt, no_dup=False):
        key = self.pkey_getter(pkt)
        if key not in self.packet_group:
            self.packet_group[key] = [pkt]
        else:
            if no_dup is True:
                skey = self.skey_getter(pkt)
                for p in self.packet_group[key]:
                    if self.skey_getter(p) == skey:
                        return
            self.packet_group[key].append(pkt)

    def _del_from_group(self, pkt):
        key = self.pkey_getter(pkt)
        if key not in self.packet_group:
            return
        try:
            self.packet_group[key].remove(pkt)
            if len(self.packet_group[key]) == 0:
                del self.packet_group[key]
        except ValueError:
            pass

    def _update_stat(self, attack_type, pkt):
        key = self.pkey_getter(pkt)

        if key not in self.stats:
            self.stats[key] = AttackStat()

        stat = self.stats[key]
        report = None
        if stat.update_time is not None and \
           pkt.ts - stat.update_time >= self.attack_gap and \
           stat.min_attack_packets >= self.min_attack_packets:
            report = stat.report()
            stat.reset()

        spoofed = 'yes' if pkt.ip_src != self.own_ip else 'no'
        stat.update(attack_type, pkt, spoofed)

        return report

    def _flush_stat(self, attack_type):
        reports = None
        to_del = []
        for key, stat in self.stat.items():
            if datetime.now() - stat.update_time >= self.attack_gap and \
                stat.min_attack_packets >= self.min_attack_packets:
                r = stat.report()
                reports.append(r)
                to_del.append(key)

        for k in to_del:
            del self.stats[k]

        return reports

    def _detect(self, attack_type):
        reports = None
        confirmed = None
        for k, v in self.packet_group.items():
            if len(v) > self.water_mark:
                for p in v:
                    r = self._update_stat(attack_type, pkt)
                    if r is not None:
                        reports.append(r)
                    confirmed.append(p)
        return reports, confirmed

    def del_confirmed(self, pkts):
        for p in pkts:
            self._del_from_group(p)


class ScanDetector(AttackDetector):
    def __init__(self, water_mark, attack_gap, min_attack_packets, own_ip):
        super().__init__(water_mark, attack_gap, min_attack_packets, own_ip)

        def pkey_getter(pkt):
            return pkt.ip_src

        def skey_getter(pkt):
            return pkt.ip_dst

        self._set_key_getter(pkey_getter, skey_getter)

    def detect(self, pkt):
        self._add_to_group(pkt, True)
        return self._detect(AttackType.ATTACK_SCAN.value)

    def flush(self):
        return self._flush_stat(AttackType.ATTACK_SCAN.value)


class RADetector(AttackDetector):
    def __init__(self, water_mark, attack_gap, min_attack_packets, own_ip):
        super().__init__(water_mark, attack_gap, min_attack_packets, own_ip)

        def pkey_getter(pkt):
            return pkt.src_net

        self._set_key_getter(pkey_getter, None)

    def detect(self, pkt):
        self._add_to_group(pkt)
        return self._detect(AttackType.ATTACK_RA.value)

    def flush(self):
        return self._flush_stat(AttackType.ATTACK_RA.value)


class DPDetector(AttackDetector):
    def __init__(self, water_mark, attack_gap, min_attack_packets, own_ip):
        super().__init__(water_mark, attack_gap, min_attack_packets, own_ip)

        def pkey_getter(pkt):
            return pkt.dst_net

        self._set_key_getter(pkey_getter, None)

    def detect(self, pkt):
        self._add_to_group(pkt)
        return self._detect(AttackType,ATTACK_DP.value)

    def flush(self):
        return self._flush_stat(AttackType.ATTACK_DP.value)


class AttackReport:
    def __init__(self, cnc_ip, cnc_port)
        self.cnc_status = CnCStatus.UNKNOWN.value
        self.cnc_ready = False
        self.cnc_ip = cnc_ip
        self.cnc_port = cnc_port
        self.cnc_update_at = None
        self.attack_reports = []

    def get(self):
        cnc_ready = self.cnc_ready
        if self.cnc_ready:
            self.cnc_ready = False

        return {'cnc_ready': cnc_ready,
                'cnc_ip': self.cnc_ip,
                'cnc_port': self.cnc_port,
                'cnc_status': self.cnc_status,
                'cnc_update_at': self.cnc_update_at,
                'attacks': self.attack_reports}

    def __repr__(self):
        return f'\ncnc_status: {self.cnc_status}\n' + \
            f'cnc_ready: {self.cnc_ready}\n' + \
            f'cnc_ip: {self.cnc_ip}\n' + \
            f'cnc_port: {self.cnc_port}\n' + \
            f'attacks: {self.attack_reports}\n'


# avoiding logging here cuz this will run in another python interpreter
# don't want to bother logging to the same file, just use print for debugging
class AttackAnalyzer:
    def __init__(self, cnc_ip, cnc_port, own_ip, excluded_ips,
                 enable_attack_detection=True, attack_gap=900,
                 min_attack_packets=5):
        self.tag = None
        self.cnc_ip = cnc_ip
        self.cnc_port = cnc_port
        self.own_ip = own_ip
        self.excluded_ips = excluded_ips
        self.enable_attack_detection = enable_attack_detection
        self.attack_detectors = [ScanDetector(3, timedelta(seconds=attack_gap),
                                              min_attack_packets,
                                              owan_ip),
                                 DPDetector(2, timedelta(seconds=attack_gap),
                                            min_attack_packets,
                                            own_ip),
                                 RADetector(2, timedelta(seconds=attack_gap),
                                            min_attack_packets,
                                            own_ip)]
        self.report = AttackReport(cnc_ip, cnc_port)

    def set_tag(self, tag):
        self.tag = tag

    def get_result(self, flush=False):
        l.debug(f'[{self.tag}] getting report, attack detecion enabled: {self.enable_attack_detection}...')
        if self.enable_attack_detection and flush:
            for detector in self.attack_detectors:
                reports = detector.flush()
                if reports is not None:
                    self.report.attack_reports.append(reports)

        return self.report.get()

    def _analyze_cnc_status(self, pkt):
        l.debug(f'[{self.tag}] analyzing cnc status...')
        if 'tcp' in pkt.layers:
            # we only monitor sync_ack or fin_ack from server -> client
            if pkt.ip_src == self.cnc_ip and pkt.ip_dst == self.own_ip:
                if pkt.tcp_flags_fin == 'True':
                    # server initiate FIN, connection broken
                    if self.report.cnc_status != CnCStatus.DISCONNECTED.value:
                        self.report.cnc_status = CnCStatus.DISCONNECTED.value
                        self.report.cnc_ready = True
                        self.report.cnc_update_at = datetime.now()
                else:
                    # if sync ack from server, or data exchange from server
                    if (pkt.tcp_flags_syn == 'True' and pkt.tcp_flags_ack == 'True') \
                            or (pkt.tcp_len != 0):
                        if self.report.cnc_status != CnCStatus.ALIVE.value:
                            self.report.cnc_status = CnCStatus.ALIVE.value
                            self.report.cnc_ready = True
                            self.report.cnc_update_at = datetime.now()
        return self.report.cnc_ready

    def _analyze_attack(self, pkt):
        l.debug(f'[{self.tag}] analyzing attack of packet: {repr(pkt)}')
        if 'tcp' not in pkt.layers and \
                'udp' not in pkt.layers and \
                'ip' not in pkt.layers:
            return False

        background_fields = ["mdns", "dhcpv6", "dhcp", "arp"]
        if is_background_traffic(pkt, background_fields):
            return False

        # only check outgoing packets and ignore c2 traffic
        if pkt.ip_dst == self.cnc_ip or \
                pkt.ip_dst == self.own_ip or \
                pkt.ip_dst in self.excluded_ips:
            return False

        reports = None
        confirmed = None
        for detector in self.attack_detectors:
            reports, confirmed = detector.detect(pkt)
            if reports is not None:
                self.report.attack_reports = reports

        if confirmed is not None:
            for detector in self.attack_detectors:
                detector.del_confirmed(confirmed)

        return reports is not None


    def analyze(self, pkt):
        # TODO: slowlori attack may escape
        cnc_ready = self._analyze_cnc_status(pkt)
        attack_ready = False
        if self.enable_attack_detection:
            attack_ready = self._analyze_attack(pkt)
        return cnc_ready or attack_ready

