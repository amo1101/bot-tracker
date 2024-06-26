import re
import pyshark
from packet_parser import *
from log import TaskLogger

l: TaskLogger = TaskLogger(__name__)
MIN_OCCURRENCE = 1  # Not interested in scanning or similar activities

background_fields = ["icmpv6", "icmp", "mdns", "dns", "dhcpv6", "dhcp", "arp", "ntp"]


class CnCReport:
    def __init__(self, max_cnc_candidates):
        self.ip_dict = {}
        self.port_dict = {}
        self.DNS_Mappings = {}
        self.count = 0
        self.Alexa_ranking = 0
        self.cnc_info = []
        self.max_cnc_candidates = max_cnc_candidates

    def is_ready(self):
        if len(self.cnc_info) == 0:
            self.get()
        return len(self.cnc_info) > 0

    def __repr__(self):
        return f'ip_dict: {self.ip_dict}, ' + \
            f'port_dict: {self.port_dict}, ' + \
            f'DNS_Mappings: {self.DNS_Mappings}, ' + \
            f'count: {self.count}, ' + \
            f'Alexa_ranking: {self.Alexa_ranking}, ' + \
            f'cnc_info: {self.cnc_info}'

    def rank(self, domain):
        return 0

    # return a list of tuples of potential C2
    def get(self, flush=False):
        if len(self.cnc_info) > 0:
            return self.cnc_info[:self.max_cnc_candidates]

        #  ports_added = []
        dict_all = {}

        for ip in self.ip_dict:
            should_be_added = False
            examined_stats = ["RST", "SYN", "SUC", "OTHER"]
            for stat in examined_stats:
                if stat in self.ip_dict[ip] and self.ip_dict[ip][stat] > MIN_OCCURRENCE:
                    should_be_added = True
            # Single use of DNS could be indicative because activities like scanning are not based on DNS
            if "DNS_QUERIES" in self.ip_dict[ip]:
                should_be_added = True
            if should_be_added:
                ip_port = ip.split(":")
                if len(ip_port) > 1:  # it's not a DNS address
                    #  if ip_port[1] not in ports_added:
                    #  ports_added.append(ip_port[1])
                    self.ip_dict[ip]["Score"] = (1.0 *
                                                 self.ip_dict[ip]["Total"]) / self.port_dict[ip_port[1]]
                    #  else:
                        #  should_be_added = True  # different from orignal algo,we count this as candidate C2 
                else:  # there's no port to consider
                    self.ip_dict[ip]["Score"] = (1.0 * self.ip_dict[ip]["Total"])
                ip_key = ip_port[0]
                if ip_key in self.DNS_Mappings:
                    self.ip_dict[ip]["DNS_Name"] = self.DNS_Mappings[ip_key]
                elif not validate_ip_format(ip_key):  # it's a not found DNS
                    self.ip_dict[ip]["DNS_Name"] = ip_key
                if self.Alexa_ranking > 0 and "DNS_Name" in self.ip_dict[ip]:
                    ranking = self.rank(self.ip_dict[ip]["DNS_Name"])
                    if ranking and ranking < self.Alexa_ranking:
                        should_be_added = False
                if should_be_added:
                    dict_all[ip] = self.ip_dict[ip]

        self.cnc_info = sorted(dict_all.items(), key=lambda kv: kv[1]['Score'], reverse=True)
        return self.cnc_info[:self.max_cnc_candidates]


# avoiding logging here cuz this will run in another python interpreter
# don't want to bother logging to the same file, just use l.debug for debugging
class CnCAnalyzer:
    def __init__(self, own_ip, excluded_ips=None, excluded_ports=None,
                 max_cnc_candidates=100):
        self.tag = None
        self.report = CnCReport(max_cnc_candidates)
        self.own_ip = own_ip
        self.excluded_ports = excluded_ports
        self.excluded_ips = excluded_ips

    def set_tag(self, tag):
        self.tag = tag

    def check_dns_address(self, pkt):  # Exception for DNS packets
        if 'dns' in pkt.layers:
            if pkt.dns_a is None:
                return pkt.dns_qry_name
            else:
                self.report.DNS_Mappings[pkt.dns_a] = pkt.dns_qry_name
        return None

    def get_result(self, flush=False):
        return self.report.get(flush)

    def analyze(self, pkt):
        l.debug(f'[{self.tag}] new packet: {repr(pkt)}\n')
        l.debug(f'[{self.tag}] cnc analyzer params -> own_ip: {self.own_ip}, excluded_ips: ' + \
                f'{self.excluded_ips}, excluded_ports: {self.excluded_ports}\n')
        self.report.count += 1
        not_found_dns_addr = self.check_dns_address(pkt)
        if not_found_dns_addr:
            if not_found_dns_addr in self.report.ip_dict:
                self.report.ip_dict[not_found_dns_addr]["Total"] += 1
                self.report.ip_dict[not_found_dns_addr]["DNS_QUERIES"] += 1
            else:
                self.report.ip_dict[not_found_dns_addr] = {"Total": 1, "DNS_QUERIES": 1}

        bg_pkt = is_background_traffic(pkt, background_fields)
        if not bg_pkt:
            if 'tcp' in pkt.layers:
                if self.own_ip and pkt.ip_dst == self.own_ip:
                    target = pkt.ip_src + ":" + pkt.tcp_srcport  # the response should be also considered.
                else:
                    target = pkt.ip_dst + ":" + pkt.tcp_dstport
                state = ""
                port_num = target.split(":")[1]
                dst_ip = target.split(":")[0]
                if (self.excluded_ports and port_num in self.excluded_ports) or \
                        (self.excluded_ips and dst_ip in self.excluded_ips):
                    return False
                if target not in self.report.ip_dict:  # this is a new IP address contacted by port port_num
                    if port_num in self.report.port_dict:
                        self.report.port_dict[port_num] += 1  # a new host of this port was contacted
                    else:
                        self.report.port_dict[port_num] = 1  # the only host, we favor these
                if pkt.tcp_flags_syn == 'True':
                    if pkt.tcp_flags_ack != "True":
                        state = "SYN"
                    else:
                        return False
                        #  return self.report # don't need to take into account SYN ACK
                else:
                    if self.own_ip and pkt.ip_dst == self.own_ip or "192.168" not in pkt.ip_src:  # server response
                        if pkt.tcp_flags_reset == 'True':
                            # l.debug(dir(pkt.tcp))
                            state = "RST"
                        elif pkt.tcp_flags_fin == "True":
                            state = "FIN"  # FIN will later tell us if the connection was really a success
                        elif pkt.tcp_len != 0:
                            state = "SUC"  # We are interested in server exchanging data
                        else:
                            state = "OTHER"
                    else:  # otherwise, we don't care about the client behaviors
                        if not self.own_ip:
                            pass
                            #  l.debug("Determining state is not accurate, own_ip is missing")
                        state = "OTHER"

                if target in self.report.ip_dict:
                    self.report.ip_dict[target]["Total"] += 1
                    if state in self.report.ip_dict[target]:
                        self.report.ip_dict[target][state] += 1
                    else:
                        self.report.ip_dict[target][state] = 1
                else:
                    self.report.ip_dict[target] = {"Total": 1, state: 1}
        l.debug(f'[{self.tag}] current cnc report: {repr(self.report)}')
        return False # always return false, result will be decided by calling get_result


cc_analyzer = None


def inspect_packet(pkt):
    l.debug(f'pkt: {pkt}\n')
    pkt_summary = PacketSummary()
    pkt_summary.extract(pkt)
    l.debug(f'pkt_summary: {repr(pkt_summary)}\n')
    cc_analyzer.analyze(pkt_summary)


def test_cnc_analyzer(pcap, own_ip, excluded_ips, packet_count):
    global cc_analyzer
    if cc_analyzer is not None:
        del cc_analyzer
    cc_analyzer = CnCAnalyzer(own_ip, excluded_ips)
    cap = pyshark.FileCapture(pcap)
    cap.apply_on_packets(inspect_packet, packet_count=packet_count)
    result = cc_analyzer.report.get()
    l.debug(f'result of cnc_analyze: {result}')
    l.debug(f'report: {repr(cc_analyzer.report)}')

#  if __name__ == "__main__":
    #  try:
        #  test_cnc_analyzer('./capture.pcap','192.168.122.42',['192.168.100.4'],
                         #  1000)
    #  except KeyboardInterrupt:
        #  l.info('Interrupted by user')
