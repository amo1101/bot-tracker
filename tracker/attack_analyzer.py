from db_store import CnCStatus, AttackType
from datetime import datetime, timedelta
from dataclasses import dataclass
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
            self.start_time = pkt.sniff_time

        if attack_type == AttackType.ATTACK_SCAN.value:
            self.src.add(pkt.ip_src)
            self.dst_port.add(pkt.dstport)
        if attack_type == AttackType.ATTACK_RA.value:
            self.target.add(pkt.ip_src)
            self.dst_port.add(pkt.dstport)
        if attack_type == AttackType.ATTACK_DP.value:
            self.target.add(pkt.ip_dst)

        self.protocol.add(pkt.protocol)
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

    def del_confirmed(self, pkts):
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
    start_time: datetime
    end_time: datetime

    def report(self):
        return {'ip': self.ip,
                'port': self.port,
                'packet_cnt': self.packet_cnt,
                'total_bytes': self.total_bytes,
                'syn_cnt': self.syn_cnt,
                'fin_cnt': self.fin_cnt,
                'start_time': self.start_time,
                'end_time': self.end_time}


class CnCStatCollector:
    def __init__(self, cnc_ip_ports, own_ip, min_occurrence=2):
        self.cnc_ip_ports = cnc_ip_ports
        self.own_ip = own_ip
        self.min_occurrence = min_occurrence
        self.stats = {}

    def add(self, pkt):
        key = ''
        cnc_ip = ''
        cnc_port = ''
        if 'tcp' not in pkt.layers:
            return
        # count traffic from both sides
        if (pkt.ip_src, pkt.tcp_srcport) in self.cnc_ip_ports and \
                pkt.ip_dst == self.own_ip:
            cnc_ip = pkt.ip_src
            cnc_port = pkt.tcp_srcport
        elif pkt.ip_src == self.own_ip and \
                (pkt.ip_dst, pkt.tcp_dstport) in self.cnc_ip_ports:
            cnc_ip = pkt.ip_dst
            cnc_port = pkt.tcp_dstport
        elif pkt.ip_src == self.own_ip:
            # potential c2 that is not detected by CnCAnalyzer
            background_fields = ["icmpv6", "icmp", "mdns", "dns", "dhcpv6", "dhcp", "arp", "ntp"]
            if not is_background_traffic(pkt, background_fields) and \
                    pkt.tcp_flags_syn == 'True' and \
                    pkt.tcp_flags_ack != 'True':
                cnc_ip = pkt.ip_dst
                cnc_port = pkt.tcp_dstport
            else:
                return
        else:
            return

        key = f'{cnc_ip}:{cnc_port}'
        fin_cnt = 1 if pkt.tcp_flags_fin == 'True' and \
            pkt.tcp_flags_ack == 'False' else 0
        syn_cnt = 1 if pkt.tcp_flags_syn == 'True' and \
            pkt.tcp_flags_ack == 'False' else 0

        if key not in self.stats:
            self.stats[key] = CnCStat(cnc_ip, cnc_port,
                                      1, pkt.tcp_len,
                                      fin_cnt, syn_cnt,
                                      pkt.sniff_time,
                                      pkt.sniff_time)
        else:
            self.stats[key].packet_cnt += 1
            self.stats[key].total_bytes += pkt.tcp_len
            self.stats[key].syn_cnt += syn_cnt
            self.stats[key].fin_cnt += fin_cnt
            self.stats[key].end_time = pkt.sniff_time

    def remove(self, pkt):
        if 'tcp' in pkt.layers:
            key = f'{pkt.ip_dst}:{pkt.tcp_dstport}'
            if key in self.stats:
                del self.stats[key]

    def report(self):
        reports = []
        for k, v in self.stats.items():
            if v.packet_cnt < self.min_occurrence:
                continue
            reports.append(v.report())
        return reports


class AttackReport:
    def __init__(self, cnc_ip_ports):
        self.curr_cnc = ''
        self.cnc_status = {}
        self.cnc_stats = []
        self.attack_reports = []

        for ip, port in cnc_ip_ports:
            key = f'{ip}:{port}'
            if key not in self.cnc_stats:
                self.cnc_status[key] = {}
            self.cnc_status[key]['ready'] = False
            self.cnc_status[key]['status'] = CnCStatus.UNKNOWN.value
            self.cnc_status[key]['ip'] = ip
            self.cnc_status[key]['port'] = port
            self.cnc_status[key]['update_time'] = None

    def get(self):
        cnc_report = {}
        if self.curr_cnc == '':
            _, cnc_dict = next(iter(self.cnc_status))
        else:
            cnc_dict = self.cnc_status[self.curr_cnc]

        cnc_report = {
            'cnc_ip': cnc_dict['ip'],
            'cnc_ready': cnc_dict['ready'],
            'cnc_port': cnc_dict['port'],
            'cnc_status': cnc_dict['status'],
            'cnc_update_at': cnc_dict['update_time']}

        if cnc_dict['ready']:
            cnc_dict['ready'] = False

        return {'cnc_status': cnc_report,
                'cnc_stats': self.cnc_stats,
                'attacks': self.attack_reports}


class AttackAnalyzer:
    def __init__(self, cnc_ip_ports, own_ip, excluded_ips,
                 enable_attack_detection=True, attack_gap=900,
                 min_attack_packets=30, attack_detection_watermark=5):
        self.tag = None
        self.cnc_ip_ports = cnc_ip_ports
        self.own_ip = own_ip
        self.excluded_ips = excluded_ips
        self.enable_attack_detection = enable_attack_detection
        self.attack_gap = attack_gap
        self.min_attack_packets = min_attack_packets
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
        self.cnc_stat_collector = CnCStatCollector(self.cnc_ip_ports, own_ip)
        self.report = AttackReport(cnc_ip_ports)

    def set_tag(self, tag):
        self.tag = tag
        l.info(f'[{self.tag}] AttackAnalyzer initialized')
        l.info(f'[{self.tag}] attack detection enabled: {self.enable_attack_detection}')
        l.info(f'[{self.tag}] attack_gap: {self.attack_gap}')
        l.info(f'[{self.tag}] min_attack_packets: {self.min_attack_packets}')

    def get_result(self, flush=False):
        l.debug(f'[{self.tag}] getting report...')
        if self.enable_attack_detection and flush:
            self.report.attack_reports.clear()
            for detector in self.attack_detectors:
                reports = detector.flush()
                if len(reports) > 0:
                    self.report.attack_reports.extend(reports)
            self.report.cnc_stats = self.cnc_stat_collector.report()

        return self.report.get()

    def _analyze_cnc_status(self, pkt):
        l.debug(f'[{self.tag}] analyzing cnc status...')
        cnc_ready = False
        if 'tcp' in pkt.layers:
            # we only monitor sync_ack or fin_ack from server -> client
            if (pkt.ip_src, pkt.tcp_srcport) in self.cnc_ip_ports and \
               pkt.ip_dst == self.own_ip:
                cnc = f'{pkt.ip_src}:{pkt.tcp_srcport}'
                cnc_dict = self.report.cnc_status[cnc]
                self.report.curr_cnc = cnc
                if pkt.tcp_flags_fin == 'True':
                    # server initiate FIN, connection broken
                    if cnc_dict['status'] != CnCStatus.DISCONNECTED.value:
                        cnc_dict['status'] = CnCStatus.DISCONNECTED.value
                        cnc_dict['update_time'] = datetime.now()
                        cnc_dict['ready'] = True
                        cnc_ready = True
                else:
                    # if sync ack from server, or data exchange from server
                    if (pkt.tcp_flags_syn == 'True' and pkt.tcp_flags_ack == 'True') \
                            or (pkt.tcp_len != 0):
                        if cnc_dict['status'] != CnCStatus.ALIVE.value:
                            cnc_dict['status'] = CnCStatus.ALIVE.value
                            cnc_dict['update_time'] = datetime.now()
                            cnc_dict['ready'] = True
                            cnc_ready = True
        return cnc_ready

    def _analyze_attack(self, pkt):
        l.debug(f'[{self.tag}] analyzing attack of packet: {repr(pkt)}')

        if 'tcp' not in pkt.layers and \
                'udp' not in pkt.layers and \
                'ip' not in pkt.layers:
            return False

        # collect cnc stats
        self.cnc_stat_collector.add(pkt)

        background_fields = ["mdns", "dhcpv6", "dhcp", "arp"]
        if is_background_traffic(pkt, background_fields):
            return False

        # only check outgoing packets and ignore c2 traffic
        if (pkt.ip_dst, pkt.tcp_dstport) in self.cnc_ip_ports or \
                pkt.ip_dst == self.own_ip or \
                pkt.ip_dst in self.excluded_ips:
            return False

        reports = []
        confirmed = []
        for detector in self.attack_detectors:
            reports, confirmed = detector.detect(pkt)
            if len(reports) > 0:
                self.report.attack_reports = reports
            if len(confirmed) > 0:
                break

        if len(confirmed) > 0:
            for detector in self.attack_detectors:
                detector.del_confirmed(confirmed)
            # also delete noises packet from cnc stat collector
            for p in confirmed:
                self.cnc_stat_collector.remove(p)

        return len(reports) > 0

    def analyze(self, pkt):
        cnc_ready = self._analyze_cnc_status(pkt)
        attack_ready = False
        if self.enable_attack_detection:
            attack_ready = self._analyze_attack(pkt)
        return cnc_ready or attack_ready

