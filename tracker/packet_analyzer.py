from db_store import CnCStatus, AttackType
from datetime import datetime, timedelta
from dataclasses import dataclass
from packet_parser import *
from log import TaskLogger
import copy

l: TaskLogger = TaskLogger(__name__)

MAX_STAT_ENTRIES = 50
class AttackStat:
    def __init__(self):
        self.attack_type = None
        self.start_time = None
        self.duration = None
        self.src = set()
        self.target = set()
        self.protocol = set()
        self.layers = set()
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
        self.layers.clear()
        self.src_port.clear()
        self.dst_port.clear()
        self.spoofed.clear()
        self.update_time = None
        self.packet_cnt = 0
        self.total_bytes = 0

    def update(self, attack_type, pkt, spoofed):
        if self.packet_cnt == 0:
            self.attack_type = attack_type
            self.start_time = pkt.sniff_time

        if attack_type == AttackType.ATTACK_SCAN.value:
            if len(self.src) < MAX_STAT_ENTRIES:
                self.src.add(pkt.ip_src)
        if attack_type == AttackType.ATTACK_RA.value:
            if len(self.target) < MAX_STAT_ENTRIES:
                self.target.add(pkt.ip_src)
        if attack_type == AttackType.ATTACK_DP.value:
            if len(self.target) < MAX_STAT_ENTRIES:
                self.target.add(pkt.ip_dst)
        if len(self.dst_port) < MAX_STAT_ENTRIES and pkt.dstport is not None:
            self.dst_port.add(pkt.dstport)

        self.protocol.add(pkt.protocol)
        if len(self.layers) < MAX_STAT_ENTRIES:
            self.layers.update(pkt.layer_names)
        self.spoofed.add(spoofed)
        self.packet_cnt += 1
        self.total_bytes += pkt.len
        self.update_time = pkt.sniff_time
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
                'src': ','.join(self.src),
                'target': target,
                'protocol': ','.join(self.protocol),
                'layers': ','.join(self.layers),
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

    def _pkey_getter(self, pkt):
        pass

    def _skey_getter(self, pkt):
        pass

    def _add_to_group(self, pkt, no_dup=False):
        key = self._pkey_getter(pkt)
        if key not in self.packet_group:
            self.packet_group[key] = [pkt]
        else:
            if no_dup is True:
                skey = self._skey_getter(pkt)
                for p in self.packet_group[key]:
                    if self._skey_getter(p) == skey:
                        return
            self.packet_group[key].append(pkt)

    def _del_from_group(self, pkt):
        key = self._pkey_getter(pkt)
        if key not in self.packet_group:
            return
        try:
            self.packet_group[key].remove(pkt)
            if len(self.packet_group[key]) == 0:
                del self.packet_group[key]
        except ValueError:
            pass

    def _update_stat(self, attack_type, pkt):
        key = self._pkey_getter(pkt)
        if key not in self.stats:
            self.stats[key] = AttackStat()

        stat = self.stats[key]
        r = None
        if stat.update_time is not None and \
                pkt.sniff_time - stat.update_time >= self.attack_gap:
            if stat.packet_cnt >= self.min_attack_packets:
                r = stat.report()
                l.debug(f'new attack report generated: {r}')
            stat.reset()

        spoofed = 'yes' if pkt.ip_src != self.own_ip else 'no'
        stat.update(attack_type, pkt, spoofed)

        return r

    def _flush_stat(self):
        reports = []
        to_del = []
        for key, stat in self.stats.items():
            if datetime.now() - stat.update_time >= self.attack_gap and \
                    stat.packet_cnt >= self.min_attack_packets:
                r = stat.report()
                reports.append(r)
                l.debug(f'new attack report flushed: {r}')
                to_del.append(key)

        for k in to_del:
            del self.stats[k]

        return reports

    def _detect(self, attack_type):
        reports = []
        confirmed = []
        for k, v in self.packet_group.items():
            if len(v) > self.water_mark:
                for p in v:
                    r = self._update_stat(attack_type, p)
                    if r is not None:
                        reports.append(r)
                    confirmed.append(p)
        return reports, confirmed

    def remove(self, pkts):
        for p in pkts:
            self._del_from_group(p)


class ScanDetector(AttackDetector):
    def __init__(self, water_mark, attack_gap, min_attack_packets, own_ip):
        super().__init__(water_mark, attack_gap, min_attack_packets, own_ip)

    def _pkey_getter(self, pkt):
        return pkt.ip_src

    def _skey_getter(self, pkt):
        return pkt.ip_dst

    def detect(self, pkt):
        if pkt.len != 0:
            return [], []
        self._add_to_group(pkt, True)
        return self._detect(AttackType.ATTACK_SCAN.value)

    def flush(self):
        return self._flush_stat()


class RADetector(AttackDetector):
    def __init__(self, water_mark, attack_gap, min_attack_packets, own_ip):
        super().__init__(water_mark, attack_gap, min_attack_packets, own_ip)

    def _pkey_getter(self, pkt):
        return pkt.src_net

    def detect(self, pkt):
        if pkt.ip_src == self.own_ip or pkt.len == 0:
            return [], []
        self._add_to_group(pkt)
        return self._detect(AttackType.ATTACK_RA.value)

    def flush(self):
        return self._flush_stat()


class DPDetector(AttackDetector):
    def __init__(self, water_mark, attack_gap, min_attack_packets, own_ip):
        super().__init__(water_mark, attack_gap, min_attack_packets, own_ip)

    def _pkey_getter(self, pkt):
        return pkt.dst_net

    def detect(self, pkt):
        if pkt.len == 0:
            return [], []
        self._add_to_group(pkt)
        return self._detect(AttackType.ATTACK_DP.value)

    def flush(self):
        return self._flush_stat()


@dataclass
class CnCStat:
    ip: str
    port: str
    packet_cnt: int
    total_bytes: int
    syn_cnt: int
    fin_cnt: int
    rst_cnt: int
    start_time: datetime
    duration: timedelta

    def report(self):
        return {'ip': self.ip,
                'port': self.port,
                'packet_cnt': self.packet_cnt,
                'total_bytes': self.total_bytes,
                'syn_cnt': self.syn_cnt,
                'fin_cnt': self.fin_cnt,
                'rst_cnt': self.rst_cnt,
                'start_time': self.start_time,
                'duration': self.duration}


class CnCDetector:
    def __init__(self, own_ip, excluded_ips, min_cnc_attempts=2):
        self.own_ip = own_ip
        self.excluded_ips = excluded_ips
        self.min_cnc_attempts = min_cnc_attempts
        self.stats = {}
        self.cnc = ''  # cnc_ip:cnc_port
        self.cnc_candidates = set()

    def update(self, key, pkt):
        fin_cnt = 1 if pkt.tcp_flags_fin == 'True' and \
            pkt.ip_dst == self.own_ip else 0
        syn_cnt = 1 if pkt.tcp_flags_syn == 'True' and \
            pkt.tcp_flags_ack == 'False' else 0
        rst_cnt = 1 if pkt.tcp_flags_reset == 'True' and \
            pkt.ip_dst == self.own_ip else 0

        ip_port = key.split(':')
        if key not in self.stats:
            self.stats[key] = CnCStat(ip_port[0],
                                      ip_port[1],
                                      1, pkt.tcp_len,
                                      syn_cnt, fin_cnt, rst_cnt,
                                      pkt.sniff_time,
                                      timedelta(0))
        else:
            self.stats[key].packet_cnt += 1
            self.stats[key].total_bytes += pkt.tcp_len
            self.stats[key].syn_cnt += syn_cnt
            self.stats[key].fin_cnt += fin_cnt
            self.stats[key].rst_cnt += rst_cnt
            self.stats[key].duration = pkt.sniff_time - self.stats[key].start_time

    def detect(self, pkt):
        key = ''

        def get_key(ip, port):
            return f'{ip}:{port}'

        def get_cnc_status(p, is_candidate):
            if is_candidate:
                return {'ip': p.ip_dst, 'port': p.tcp_dstport,
                        'status': CnCStatus.CANDIDATE.value,
                        'update_time': p.sniff_time}

            # cnc communication
            ret = {}
            if p.tcp_len > 0:
                ret['status'] = CnCStatus.ALIVE.value
            if p.tcp_flags_fin == 'True':
                ret['status'] = CnCStatus.DISCONNECTED.value
            else:
                pass

            # cnc should have been confirmed
            ip_port = self.cnc.split(':')
            if 'status' in ret:
                ret['ip'] = ip_port[0]
                ret['port'] = ip_port[1]
                ret['update_time'] = p.sniff_time
            return ret

        if 'tcp' not in pkt.layers:
            return {}
        if pkt.ip_dst in self.excluded_ips or \
                pkt.ip_src in self.excluded_ips:
            return {}

        is_cnc_comm = False
        is_cnc_candidate = False
        key_src = get_key(pkt.ip_src, pkt.tcp_srcport)
        key_dst = get_key(pkt.ip_dst, pkt.tcp_dstport)
        if pkt.ip_dst == self.own_ip:
            # packet from monitored targets
            if key_src in self.stats:
                key = key_src
                # packet from candidate cnc
                if pkt.ip_src in self.cnc_candidates:
                    if pkt.tcp_len > 0 and self.cnc == '':
                        # cnc confirmed
                        self.cnc = key_src
                        l.debug(f'cnc confirmed as: {self.cnc}')
                    if key_src == self.cnc:
                        # reply from cnc
                        is_cnc_comm = True
        elif pkt.ip_src == self.own_ip:
            # potential cnc attempt
            is_syn = False
            background_fields = ["icmpv6", "icmp", "mdns", "dns",
                                 "dhcpv6", "dhcp", "arp", "ntp"]
            if not is_background_traffic(pkt, background_fields) and \
                    pkt.tcp_flags_syn == 'True' and \
                    pkt.tcp_flags_ack != 'True' and \
                    pkt.tcp_len == 0:
                is_syn = True

            # packet to monitored targets
            if key_dst in self.stats:
                key = key_dst
                # packet to candidate cnc
                if pkt.ip_dst in self.cnc_candidates:
                    if pkt.tcp_len > 0 and self.cnc == '':
                        # cnc confirmed
                        self.cnc = key
                        l.debug(f'cnc confirmed as: {self.cnc}')
                    if key == self.cnc:
                        is_cnc_comm = True
                elif is_syn and self.stats[key].syn_cnt + 1 >= self.min_cnc_attempts and \
                        self.cnc == '':
                    is_cnc_candidate = True
                    self.cnc_candidates.add(pkt.ip_dst)
                    l.debug(f'new cnc candidate detected: {key}')
            else:
                if is_syn:
                    key = key_dst

        if key != '':
            self.update(key, pkt)
        if is_cnc_comm or is_cnc_candidate:
            return get_cnc_status(pkt, is_cnc_candidate)
        return {}

    def remove(self, pkts):
        for pkt in pkts:
            if 'tcp' in pkt.layers:
                key = f'{pkt.ip_dst}:{pkt.tcp_dstport}'
                if key in self.stats:
                    del self.stats[key]

    def report(self):
        reports = []
        for k, v in self.stats.items():
            if v.packet_cnt < self.min_cnc_attempts:
                continue
            reports.append(v.report())
        return reports


class PacketAnalyzer:
    def __init__(self, own_ip, excluded_ips,
                 min_cnc_attempts=2,
                 attack_gap=900,
                 min_attack_packets=30,
                 attack_detection_watermark=5):
        self.tag = None
        self.cnc = ('', '')
        self.cnc_status_ready = False
        self.cnc_status = {}
        self.cnc_stats = []
        self.attacks = []
        self.domains = {}
        self.own_ip = own_ip
        self.excluded_ips = excluded_ips.split(',')
        self.attack_detectors = [ScanDetector(attack_detection_watermark,
                                              timedelta(seconds=attack_gap),
                                              min_attack_packets,
                                              own_ip),
                                 DPDetector(attack_detection_watermark,
                                            timedelta(seconds=attack_gap),
                                            min_attack_packets,
                                            own_ip),
                                 RADetector(attack_detection_watermark,
                                            timedelta(seconds=attack_gap),
                                            min_attack_packets,
                                            own_ip)]
        self.cnc_detector = CnCDetector(own_ip, excluded_ips, min_cnc_attempts)

    def set_tag(self, tag):
        self.tag = tag
        l.info(f'[{self.tag}] PacketAnalyzer initialized')

    def get_domains(self, pkt):
        if pkt.dns_a is not None:
            self.domains[pkt.dns_a] = pkt.dns_qry_name

    def _report(self):
        cnc_status = {}
        cnc_stats = []
        attacks = []
        if self.cnc_status_ready:
            self.cnc_status_ready = False
            cnc_status = copy.deepcopy(self.cnc_status)
            cnc_status['domain'] = '' if cnc_status['ip'] not in self.domains \
                else self.domains[cnc_status['ip']]
        if len(self.cnc_stats) > 0:
            cnc_stats = copy.deepcopy(self.cnc_stats)
            self.cnc_stats.clear()
        if len(self.attacks) > 0:
            attacks = copy.deepcopy(self.attacks)
            for a in attacks:
                a['cnc_ip'] = self.cnc[0]
                a['cnc_port'] = self.cnc[1]
            self.attacks.clear()
        return {'cnc_status': cnc_status,
                'cnc_stats': cnc_stats,
                'attacks': attacks}

    def get_result(self, flush_attacks=False, flush_cnc_stats=False):
        l.debug(f'[{self.tag}] getting report, flush_attacks: {flush_attacks}, flush_cnc_stats: {flush_cnc_stats}...')
        if flush_attacks:
            self.attacks.clear()
            for detector in self.attack_detectors:
                reports = detector.flush()
                if len(reports) > 0:
                    self.attacks.extend(reports)
        if flush_cnc_stats:
            self.cnc_stats = self.cnc_detector.report()

        return self._report()

    def analyze(self, pkt):
        l.debug(f'[{self.tag}] analyzing packet: {repr(pkt)}')

        if 'dns' in pkt.layers:
            self.get_domains(pkt)

        # ip layer must present
        if 'ip' not in pkt.layers:
            return False

        # skip retransmission packets
        if 'tcp' in pkt.layers and pkt.tcp_retransmission == 'True':
            return False

        def check_cnc_status(status):
            if len(status) == 0:
                return False

            # cnc status report will be ready when a candidate CnC is available
            if status['status'] == CnCStatus.CANDIDATE.value:
                self.cnc_status = status
                self.cnc_status_ready = True
                return True

            # status of CnC changed, from candidate to alive
            # or between alive <-> disconnected
            if len(self.cnc_status) > 0 and \
                    self.cnc_status['status'] != status['status']:
                self.cnc_status = status
                self.cnc_status_ready = True
                if status['status'] == CnCStatus.ALIVE.value and \
                        self.cnc[0] == '':
                    # confirm the CnC
                    self.cnc = (status['ip'], status['port'])
                return True
            return False

        # analyze cnc stats
        cnc_status = self.cnc_detector.detect(pkt)
        cnc_status_ready = check_cnc_status(cnc_status)

        background_fields = ["dhcpv6", "dhcp", "arp"]
        if is_background_traffic(pkt, background_fields):
            return cnc_status_ready

        # only check outgoing packets and ignore c2 traffic
        if pkt.ip_dst == self.cnc[0] or \
                pkt.ip_dst == self.own_ip or \
                pkt.ip_dst in self.excluded_ips:
            return cnc_status_ready

        # analyzing attacks
        reports = []
        confirmed = []
        for detector in self.attack_detectors:
            reports, confirmed = detector.detect(pkt)
            if len(reports) > 0:
                self.attacks = reports
            if len(confirmed) > 0:
                break

        if len(confirmed) > 0:
            for detector in self.attack_detectors:
                detector.remove(confirmed)
            # also delete noise packet from cnc detector
            self.cnc_detector.remove(confirmed)

        return len(reports) > 0 or cnc_status_ready
