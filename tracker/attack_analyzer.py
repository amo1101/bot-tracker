import pyshark
from db_store import CnCStatus, AttackType
from datetime import datetime, timedelta
from collections import deque
from packet_parser import *

@dataclass
class PacketAttackInfo:
    attack_type: str
    targt: str
    protocol: str
    src_port: str
    dst_port: str
    pkt_len: int
    ts: int

class AttackInfo:
    def __init__(self):
        self.attack_type = None
        self.start_time = None
        self.duration = None
        self.target = set()
        self.protocol = set()
        self.src_port = set()
        self.dst_port = set()
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
        self.packet_cnt += 1
        self.total_bytes += attack.pkt_len
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
        self.packet_win = deque()
        self.src_dict = {}
        self.dst_dict ={}
        self.src_net_dict = {}
        self.dst_net_dict = {}

    def _update_stat(self, op, src=None, dst=None):
        def _update_dict(d, key, delta, default=1, del_when=0):
            if key in d:
                d[key] += delta
            else:
                d[key] = default

            if d[key] == del_when:
                del d[key]

        if op == 1: # add stat
            _update_dict(self.src_dict, src, 1)
            _update_dict(self.dst_dict, dst, 1)
            src_net = '.'.join(src.split('.')[:3])
            _update_dict(self.src_net_dict, src_net, 1)
            dst_net = '.'.join(dst.split('.')[:3])
            _update_dict(self.dst_net_dict, dst_net, 1)
        elif op == -1: # delelte stat
            _update_dict(self.src_dict, src, -1)
            _update_dict(self.dst_dict, dst, -1)
            src_net = '.'.join(src.split('.')[:3])
            _update_dict(self.src_net_dict, src_net, -1)
            dst_net = '.'.join(dst.split('.')[:3])
            _update_dict(self.dst_net_dict, dst_net, -1)
        else:
            # update purities
            self.purity_src = 1.0 * (self.win_size + 1 - len(self.src_dict)) / self.win_size
            self.purity_src_net = 1.0 * (self.win_size + 1 - len(self.src_net_dict)) / self.win_size
            self.purity_dst = 1.0 * (self.win_size + 1 - len(self.dst_dict)) / self.win_size
            self.purity_dst_net = 1.0 * (self.win_size + 1 - len(self.dst_net_dict)) / self.win_size
            # update pps: moving average
            td = (self.packet_win[-1][2] - self.packet_win[0][2])
            self.pps = 1.0 * self.win_size / td

    def push(packet):
        src = packet.ip.src
        dst = packet.ip.dst
        ts = packet.sniff_time

        self.packet_win.append((src, dst, ts))
        self._update_stat(1, src, dst)
        if len(self.packet_win) > self.win_size:
            d_src, d_dst, _ = self.packet_win.popleft()
            self._update_stat(-1, d_src, d_dst)

        if len(self.packet_win) == self.win_size:
            self._update_stat(0)

class AttackReport:
    def __init__(self, cnc_ip, cnc_port, attack_interval):
        self.cnc_status = CnCStatus.UNKNOWN.value
        self.cnc_ready = False
        self.attack_ready = False
        self.cnc_ip = cnc_ip
        self.cnc_port = cnc_port
        self.cnc_update_at = None
        # 3 deques for each attack type
        self.attack_info = [deque(),deque(),deque()]
        self.attack_interval = attack_interval

    def is_ready(self):
        return self.cnc_ready

    def _attack_info_idx(attack_type):
        if attack_type == AttackType.RA.value:
            return 0
        elif attack_type == AttackType.DP.value:
            return 1
        else:
            return 2

    def get_latest_attack_time(self, attack_type):
        i = _attack_info_idx(attack_type)
        if len(self.attack_info[i]) == 0:
            return None
        else:
            return self.attack_info[i][-1].update_time

    def add_attack_info(self, attack):
        i = _attack_info_idx(attack.attack_type)
        self.attack_info[i].append(AttackInfo())
        self.attack_info[i][-1].update(attack)

    def update_attack_info(self, attack):
        i = _attack_info_idx(attack.attack_type)
        self.attack_info[i][-1].update(attack)

    def get(self):
        if self.cnc_ready:
            self.cnc_ready = False

        attack_report = {}  # {attack_type: [{},{},{}]}
        k = [AttackType.RA.value,
             AttackType.ATTACK_DP.value,
             AttackType.ATTACK_SCAN.value]

        for i in range(3):
            if len(self.attack_info[i]) == 0:
                continue

            r = []
            latest = self.attack_info[i].pop()
            can_del_latest = False
            # the latest attack is done
            if datetime.now() - latest.update_time > self.attack_interval:
                r.append(latest.report())
                can_del_latest = True
            try:
                a = self.attack_info[i].pop()
                r.append(a.report())
            except IndexError:
                # restore the latest attack info since it is not done
                if can_del_latest is False:
                     self.attack_info[i].append(latest)

            if len(r) > 0:
                attack_report[k[i]] = r

        return {'cnc_ready': self.cnc_ready,
                'cnc_ip': self.cnc_ip,
                'cnc_port': self.cnc_port,
                'cnc_status': self.cnc_status,
                'cnc_update_at': self.cnc_update_at,
                'attacks': attack_report}

    def __repr__(self):
        return f'cnc_status: {self.cnc_status}, ' + \
            f'cnc_ready: {self.cnc_ready}, ' + \
            f'attack_ready: {self.attack_ready}, ' + \
            f'cnc_ip: {self.cnc_ip}'


# avoiding logging here cuz this will run in another python interpreter
# don't want to bother logging to the same file, just use print for debugging
class AttackAnalyzer:
    def __init__(self, cnc_ip, cnc_port, own_ip):
        self.cnc_ip = cnc_ip
        self.cnc_port = cnc_port
        self.own_ip = own_ip
        self.packet_win_size = 5
        self.pps_threshold = 25  # 25 packets per second indicating an attack
        self.attack_interval = 30 # in seconds
        self.packet_win = PacketSlidingWindow(self.packet_win_size)
        self.report = AttackReport(cnc_ip, cnc_port, self.attack_interval)

    def get_result(self):
        return self.report.get()

    def _analyze_cnc_status(self, pkt):
        if 'tcp' in dir(pkt):
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
                       or (pkt.tcp_len != '0'):
                        if self.report.cnc_status != CnCStatus.ALIVE.value:
                            self.report.cnc_status = CnCStatus.ALIVE.value
                            self.report.cnc_ready = True
                            self.report.cnc_update_at = datetime.now()

    def _detect_ra(self, pkt):
        attack_type = AttackType.ATTACK_RA.value
        attack_target = None
        # should be spoofed
        if pkt.ip_src == self.own_ip:
            return None
        if pkt.len == 0:
            return None
        if self.packet_win.purity_src > 0.99:
            attack_target = pkt.ip_src
        elif self.packet_win.purity_src_net > 0.99:
            attack_target = '.'.join(pkt.ip_src.split('.')[:3]) + '/-'
        else:
            return None
        return PacketAttackInfo(attack_type, attack_target, pkt.protocol, '-',
                               pkt.dstport, pkt.sniff_time, pkt.len)

    def _detect_dp(self, pkt):
        attack_type = AttackType.ATTACK_DP.value
        attack_target = None
        if pkt.len == 0:
            return None
        if self.packet_win.purity_dst > 0.99:
            attack_target = pkt.ip_dst
        elif self.packet_win.purity_dst_net > 0.99:
            attack_target = '.'.join(pkt.ip_dst.split('.')[:3]) + '/-'
        else:
            return None
        return PacketAttackInfo(attack_type, attack_target, pkt.protocol, '-',
                                '-', pkt.sniff_time, pkt.len)

    def _detect_scan(self, pkt):
        attack_type = AttackType.ATTACK_SCAN.value
        if pkt.ip_src != self.own_ip:
            return None
        if pkt.len != 0:
            return None
        if self.packet_win.purity_dst < 0.01:
            pass
        else:
            return None
        return PacketAttackInfo(attack_type, '-', pkt.protocol, '-',
                                pkg.dstport, pkt.sniff_time, pkt.len)

    def _analyze_attack(self, pkt):
        background_fields = ["mdns", "dhcpv6", "dhcp", "arp"]
        if is_background_traffic(pkt, background_fields):
            return
        # only check outgoing packets
        if pkt.ip_dst == self.cnc_ip or pkt.ip_dst == self.own_ip:
            return

        self.packet_win.push(pkt)
        attack = None
        if self.packet_win.pps > self.pps_threshold:
            attack = self._detect_ra(pkt)
            if attack is None:
                attack = self._detect_dp(pkt)
                if attack is None:
                    attack = self._detect_scan(pkt)
        if attack is None:
            return

        latest_ts = self.report.get_latest_attack_time(attack.attack_type)
        if latest_ts is not None:
            interval = attack.ts - latest_attack.ts
            if interval > self.attack_interval:
                self.report.add_attack_info(attack)
            else:
                self.report.update_attack_info(attack)
        else:
            self.report.add_attack_info(attack)

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
