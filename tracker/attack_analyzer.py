import pyshark
import copy
from db_store import CnCStatus, AttackType
from datetime import datetime, timedelta
from dataclasses import dataclass
from collections import deque
from packet_parser import *
from log import TaskLogger

l: TaskLogger = TaskLogger(__name__)


@dataclass
class PacketAttackInfo:
    attack_type: str
    target: str
    protocol: str
    src_port: str
    dst_port: str
    spoofed: str
    ts: int
    packet_cnt: int
    total_bytes: int


class AttackStat:
    def __init__(self):
        self.attack_type = None
        self.start_time = None
        self.duration = None
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
        self.target.clear()
        self.protocol.clear()
        self.src_port.clear()
        self.dst_port.clear()
        self.spoofed.clear()
        self.update_time = None
        self.packet_cnt = 0
        self.total_bytes = 0

    def update(self, attack):
        if self.packet_cnt == 0:
            self.attack_type = attack.attack_type
            self.start_time = attack.ts

        self.target.add(attack.target)
        self.protocol.add(attack.protocol)
        self.src_port.add(attack.src_port)
        self.dst_port.add(attack.dst_port)
        self.spoofed.add(attack.spoofed)
        self.packet_cnt += attack.packet_cnt
        self.total_bytes += attack.total_bytes
        self.update_time = attack.ts
        self.duration = self.update_time - self.start_time

    def report(self):
        return {'attack_type': self.attack_type,
                'start_time': self.start_time,
                'duration': self.duration,
                'target': ','.join(self.target),
                'protocol': ','.join(self.protocol),
                'src_port': ','.join(self.src_port),
                'dst_port': ','.join(self.dst_port),
                'spoofed': ','.join(self.spoofed),
                'packet_cnt': self.packet_cnt,
                'total_bytes': self.total_bytes}


class PacketSlidingWindow:
    def __init__(self, win_size):
        self.win_size = win_size
        self.pps = 0
        self.purity_src = 0
        self.purity_src_net = 0
        self.purity_dst = 0
        self.purity_dst_net = 0
        self.total_bytes = 0
        self.residual = True
        self.packet_win = deque()
        self.src_dict = {}
        self.dst_dict = {}
        self.src_net_dict = {}
        self.dst_net_dict = {}

    def reset(self):
        self.pps = 0
        self.purity_src = 0
        self.purity_src_net = 0
        self.purity_dst = 0
        self.purity_dst_net = 0
        self.total_bytes = 0
        self.residual = False
        self.packet_win.clear()
        self.src_dict.clear()
        self.dst_dict.clear()
        self.src_net_dict.clear()
        self.dst_net_dict.clear()

    def __repr__(self):
        return f'\npps: {self.pps}\n' + \
            f'purity_src: {self.purity_src}\n' + \
            f'purity_dst: {self.purity_dst}\n' + \
            f'purity_src_net: {self.purity_src_net}\n' + \
            f'purity_dst_net: {self.purity_dst_net}\n' + \
            f'residual: {self.residual}\n' + \
            f'total_bytes: {self.total_bytes}\n' + \
            f'packet_win: {self.packet_win}\n'

    def residual_packets(self):
        if not self.residual:
            return 0, 0
        else:
            return self.win_size, self.total_bytes

    def _update_stat(self, op, src=None, dst=None, pkt_len=None, ts=None):
        def _update_dict(d, key, delta, default=1, del_when=0):
            if key in d:
                d[key] += delta
            else:
                d[key] = default

            if d[key] == del_when:
                del d[key]

        def _update_purity(d, old):
            new = 1.0 * (self.win_size + 1 - len(d)) / self.win_size
            # residual available if stat turn pure
            self.residual |= (True if (old < 1 and new == 1) else False)
            return new

        if op == 0:
            # reset residual first for this round of stat update
            self.residual = False
            # update purities and residual
            self.purity_src = _update_purity(self.src_dict, self.purity_src)
            self.purity_src_net = _update_purity(self.src_net_dict, self.purity_src_net)
            self.purity_dst = _update_purity(self.dst_dict, self.purity_dst)
            self.purity_dst_net = _update_purity(self.dst_net_dict, self.purity_dst_net)
            # update pps: moving average
            td = (self.packet_win[-1][3] - self.packet_win[0][3]).total_seconds()
            self.pps = 1.0 * self.win_size / td
        else:
            dt = 1 if op == 1 else -1
            _update_dict(self.src_dict, src, dt)
            _update_dict(self.dst_dict, dst, dt)
            src_net = '.'.join(src.split('.')[:3])
            _update_dict(self.src_net_dict, src_net, dt)
            dst_net = '.'.join(dst.split('.')[:3])
            _update_dict(self.dst_net_dict, dst_net, dt)
            # update total_bytes in the window
            self.total_bytes = self.total_bytes + pkt_len if op == 1 \
                else self.total_bytes - pkt_len

    def push(self, packet):
        src = packet.ip_src
        dst = packet.ip_dst
        pkt_len = packet.len
        ts = packet.sniff_time

        self.packet_win.append((src, dst, pkt_len, ts))
        self._update_stat(1, src, dst, pkt_len)
        if len(self.packet_win) > self.win_size:
            d_src, d_dst, d_pkt_len, _ = self.packet_win.popleft()
            self._update_stat(-1, d_src, d_dst, d_pkt_len)

        if len(self.packet_win) == self.win_size:
            self._update_stat(0, None, None, None, ts)


class AttackReport:
    def __init__(self, cnc_ip, cnc_port,
                 attack_interval,
                 min_attack_packets):
        self.cnc_status = CnCStatus.UNKNOWN.value
        self.cnc_ready = False
        self.cnc_ip = cnc_ip
        self.cnc_port = cnc_port
        self.cnc_update_at = None
        # 3 attack info for each attack type
        self.attack_stat = [AttackStat(), AttackStat(), AttackStat()]
        self.attack_stat_ready = [AttackStat(), AttackStat(), AttackStat()]
        self.attack_interval = attack_interval
        self.min_attack_packets = min_attack_packets

    def _attack_stat_idx(self, attack_type):
        if attack_type == AttackType.ATTACK_RA.value:
            return 0
        elif attack_type == AttackType.ATTACK_DP.value:
            return 1
        else:
            return 2

    def get_latest_attack_time(self, attack_type):
        i = self._attack_stat_idx(attack_type)
        return self.attack_stat[i].update_time

    def update_attack_stat(self, attack):
        i = self._attack_stat_idx(attack.attack_type)
        l.debug(f'update attack: from {self.attack_stat[i].report()}')
        self.attack_stat[i].update(attack)
        l.debug(f'update attack: to {self.attack_stat[i].report()}')

    def commit_attack_stat(self, attack_type, flush=False):
        i = self._attack_stat_idx(attack_type)
        if self.attack_stat[i].packet_cnt >= self.min_attack_packets:
            if flush:
                iv = datetime.now() - self.get_latest_attack_time(attack_type)
                if iv < self.attack_interval:
                    l.warning('commit attack: interval too short, not committed!')
                    return
            self.attack_stat_ready[i] = copy.deepcopy(self.attack_stat[i])
            l.info(f'commit attack: {self.attack_stat[i].report()}')
        else:
            l.warning(f'commit attack: too few packets, discard: {self.attack_stat[i].report()}')
        self.attack_stat[i].reset()

    def attack_ready(self, attack_type):
        i = self._attack_stat_idx(attack_type)
        return self.attack_stat_ready[i].update_time is not None

    def get(self, flush=False):
        cnc_ready = self.cnc_ready
        if self.cnc_ready:
            self.cnc_ready = False

        attack_report = {}  # {attack_type: {}}
        k = [AttackType.ATTACK_RA.value,
             AttackType.ATTACK_DP.value,
             AttackType.ATTACK_SCAN.value]

        for i in range(3):
            if not self.attack_ready(k[i]):
                if flush:
                    self.commit_attack_stat(k[i], flush)
                if not self.attack_ready(k[i]):
                    continue
            attack_report[k[i]] = self.attack_stat_ready[i].report()
            self.attack_stat_ready[i].reset()

        return {'cnc_ready': cnc_ready,
                'cnc_ip': self.cnc_ip,
                'cnc_port': self.cnc_port,
                'cnc_status': self.cnc_status,
                'cnc_update_at': self.cnc_update_at,
                'attacks': attack_report}

    def __repr__(self):
        return f'\ncnc_status: {self.cnc_status}\n' + \
            f'cnc_ready: {self.cnc_ready}\n' + \
            f'cnc_ip: {self.cnc_ip}\n' + \
            f'cnc_port: {self.cnc_port}\n' + \
            f'attacks[0]: {self.attack_stat[0].report()}\n' + \
            f'attacks[1]: {self.attack_stat[1].report()}\n' + \
            f'attacks[2]: {self.attack_stat[2].report()}\n' + \
            f'attacks_ready[0]: {self.attack_stat_ready[0].report()}\n' + \
            f'attacks_ready[1]: {self.attack_stat_ready[1].report()}\n' + \
            f'attacks_ready[2]: {self.attack_stat_ready[2].report()}\n'


# avoiding logging here cuz this will run in another python interpreter
# don't want to bother logging to the same file, just use print for debugging
class AttackAnalyzer:
    def __init__(self, cnc_ip, cnc_port, own_ip, excluded_ips,
                 enable_attack_detection=True):
        self.tag = None
        self.cnc_ip = cnc_ip
        self.cnc_port = cnc_port
        self.own_ip = own_ip
        self.excluded_ips = excluded_ips
        self.enable_attack_detection = enable_attack_detection
        self.packet_win_size = 5
        self.pps_threshold = 0.01  # packets per second indicating an attack
        self.attack_interval = timedelta(seconds=30)  # attack interval in seconds
        self.min_attack_packets = 30  # minimum packets count as an attack
        self.packet_win = PacketSlidingWindow(self.packet_win_size)
        self.report = AttackReport(cnc_ip, cnc_port,
                                   self.attack_interval,
                                   self.min_attack_packets)

    def set_tag(self, tag):
        self.tag = tag

    def get_result(self, flush=False):
        l.debug(f'[{self.tag}] getting report, attack detecion enabled: {self.enable_attack_detection}...')
        return self.report.get(flush)

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

    def _detect_ra(self, pkt):
        attack_type = AttackType.ATTACK_RA.value
        attack_target = None
        # should be spoofed
        if pkt.ip_src == self.own_ip:
            return None
        if pkt.len == 0:
            return None
        if self.packet_win.purity_src > \
                1.0 * (self.packet_win_size - 1) / self.packet_win_size:
            attack_target = pkt.ip_src
        elif self.packet_win.purity_src_net > \
                1.0 * (self.packet_win_size - 1) / self.packet_win_size:
            attack_target = '.'.join(pkt.ip_src.split('.')[:3]) + '/-'
        else:
            return None
        l.debug(f'[{self.tag}] detected ra...')
        return PacketAttackInfo(attack_type, attack_target, pkt.protocol, '-',
                                pkt.dstport, 'yes', pkt.sniff_time, 1, pkt.len)

    def _detect_dp(self, pkt):
        attack_type = AttackType.ATTACK_DP.value
        attack_target = None
        proto = pkt.protocol
        spoofed = 'no'
        if pkt.len == 0:
            return None
        if self.packet_win.purity_dst > \
                1.0 * (self.packet_win_size - 1) / self.packet_win_size:
            attack_target = pkt.ip_dst
        elif self.packet_win.purity_dst_net > \
                1.0 * (self.packet_win_size - 1) / self.packet_win_size:
            attack_target = '.'.join(pkt.ip_dst.split('.')[:3]) + '/-'
        else:
            return None
        if pkt.ip_src != self.own_ip:
            spoofed = 'yes'

        l.debug(f'[{self.tag}] detected dp...')
        return PacketAttackInfo(attack_type, attack_target, proto, '-',
                                '-', spoofed, pkt.sniff_time, 1, pkt.len)

    def _detect_scan(self, pkt):
        attack_type = AttackType.ATTACK_SCAN.value
        spoofed = 'no'
        # src should be identical
        if self.packet_win.purity_src <= \
                1.0 * (self.packet_win_size - 1) / self.packet_win_size:
            return None
        # even src could be spoofed?
        if pkt.ip_src != self.own_ip:
            spoofed = 'yes'
        # payload should be 0 ?
        if pkt.len != 0:
            return None
        if self.packet_win.purity_dst < 2.0 / self.packet_win_size:  # all unique
            pass
        else:
            return None
        l.debug(f'[{self.tag}] detected scan...')
        return PacketAttackInfo(attack_type, '-', pkt.protocol, '-',
                                pkt.dstport, spoofed, pkt.sniff_time, 1, pkt.len)

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

        self.packet_win.push(pkt)
        l.debug(f'[{self.tag}] packet window stat updated:{repr(self.packet_win)}')
        attack = None
        if self.packet_win.pps > self.pps_threshold:
            attack = self._detect_ra(pkt)
            if attack is None:
                attack = self._detect_dp(pkt)
                if attack is None:
                    attack = self._detect_scan(pkt)
        if attack is None:
            return False

        # new attack, add residual stat from the sliding window
        res_packets, res_bytes = self.packet_win.residual_packets()
        attack.packet_cnt = max(attack.packet_cnt, res_packets)
        attack.total_bytes = max(attack.total_bytes, res_bytes)

        report_formed = 0
        latest_ts = self.report.get_latest_attack_time(attack.attack_type)
        if latest_ts is not None:
            interval = attack.ts - latest_ts
            if interval < self.attack_interval:
                l.debug(f'[{self.tag}] update attack: to latest report {attack}')
                self.report.update_attack_stat(attack)
                return False
            else:
                report_formed = 1
                l.debug(f'[{self.tag}] update attack: commit {attack.attack_type}')
                self.report.commit_attack_stat(attack.attack_type)

        if report_formed == 0:
            l.debug(f'[{self.tag}] update attack: a new attack added {attack}')
        else:
            l.debug(f'[{self.tag}] update attack: a new attack added after commit old one {attack}')
        self.report.update_attack_stat(attack)

        return report_formed == 1

    def analyze(self, pkt):
        # TODO: slowlori attack may escape
        cnc_ready = self._analyze_cnc_status(pkt)
        attack_ready = False
        if self.enable_attack_detection:
            attack_ready = self._analyze_attack(pkt)
        return cnc_ready or attack_ready
