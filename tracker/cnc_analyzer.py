import re
import pyshark


def validate_ip_format(ip_str):
    ip_param = ip_str
    reg_exp = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if ":" in ip_str:
        li = ip_str.split(":")
        if len(li) >= 2:
            ip_param = li[0]
    res = False
    try:
        m = re.match(reg_exp, ip_param)
        if m:
            res = True
    except:
        res = False
    return res


MIN_OCCURRENCE = 1  # Not interested in scanning or similar activities


class CnCReport:
    def __init__(self):
        self.ip_dict = {}
        self.port_dict = {}
        self.DNS_Mappings = {}
        self.count = 0
        self.Alexa_ranking = 0
        self.cnc_info = []

    def is_ready(self):
        if len(self.cnc_info) == 0:
            self.get()
        return len(self.cnc_info) > 0

    def __repr__(self):
        return f'ip_dict: {self.ip_dict}\n' + \
            f'port_dict: {self.port_dict}\n' + \
            f'DNS_Mappings: {self.DNS_Mappings}\n' + \
            f'count: {self.count}\n' + \
            f'Alexa_ranking: {self.Alexa_ranking}\n' + \
            f'cnc_info: {self.cnc_info}\n'

    def rank(self, domain):
        return 0

    def get(self):
        if len(self.cnc_info) > 0:
            return self.cnc_info[0]  # return the first tuple with the highest Score

        ports_added = []
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
                    if ip_port[1] not in ports_added:
                        ports_added.append(ip_port[1])
                        self.ip_dict[ip]["Score"] = (1.0 *
                                                     self.ip_dict[ip]["Total"]) / self.port_dict[ip_port[1]]
                    else:
                        should_be_added = False
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
        if len(self.cnc_info) > 0:
            return self.cnc_info[0]


# avoiding logging here cuz this will run in another python interpreter
# don't want to bother logging to the same file, just use print for debugging
class CnCAnalyzer:
    def __init__(self, own_ip, excluded_ips=None, excluded_ports=None):
        self.report = CnCReport()
        self.own_ip = own_ip
        self.excluded_ports = excluded_ports
        self.excluded_ips = excluded_ips
        self.background_fields = ["icmpv6", "icmp", "mdns", "dns", "dhcpv6", "dhcp", "arp", "ntp"]

    def is_background_traffic(self, pkt):
        pkt_fields = dir(pkt)
        for field in self.background_fields:
            if field in pkt_fields:
                #  background_traffic.append(pkt)
                return True
        return False

    def check_dns_address(self, pkt):  # Exception for DNS packets
        if 'dns' in dir(pkt):
            dns_dir = dir(pkt.dns)
            for_test = int(pkt.dns.flags.hex_value) & 0x8001
            reply_status = int(pkt.dns.flags.hex_value) & 0x8003  # this means response and no reply in DNS
            if reply_status == 0x8003:
                return pkt.dns.qry_name
            elif for_test == 0x8000 and "a" in dns_dir and "qry_name" in dns_dir:  # it's a response and no error
                # print(dir(pkt.dns))
                self.report.DNS_Mappings[pkt.dns.a] = pkt.dns.qry_name
                # print("qry_name",pkt.dns.qry_name,":",pkt.dns.a)    
        return None

    def analyze(self, pkt):
        self.report.count += 1
        not_found_dns_addr = self.check_dns_address(pkt)
        if not_found_dns_addr:
            if not_found_dns_addr in self.report.ip_dict:
                self.report.ip_dict[not_found_dns_addr]["Total"] += 1
                self.report.ip_dict[not_found_dns_addr]["DNS_QUERIES"] += 1
            else:
                self.report.ip_dict[not_found_dns_addr] = {"Total": 1, "DNS_QUERIES": 1}

        bg_pkt = self.is_background_traffic(pkt)
        if not bg_pkt:
            if 'tcp' in dir(pkt):
                if self.own_ip and pkt.ip.dst == self.own_ip:
                    target = pkt.ip.src + ":" + pkt.tcp.srcport  # the response should be also considered.
                else:
                    target = pkt.ip.dst + ":" + pkt.tcp.dstport
                state = ""
                port_num = target.split(":")[1]
                dst_ip = target.split(":")[0]
                if (self.excluded_ports and port_num in self.excluded_ports) or \
                        (self.excluded_ips and dst_ip in self.excluded_ips):
                    return self.report
                if target not in self.report.ip_dict:  # this is a new IP address contacted by port port_num
                    if port_num in self.report.port_dict:
                        self.report.port_dict[port_num] += 1  # a new host of this port was contacted
                    else:
                        self.report.port_dict[port_num] = 1  # the only host, we favor these
                if pkt.tcp.flags_syn == '1':
                    if pkt.tcp.flags_ack != "1":
                        state = "SYN"
                    else:
                        return self.report
                        #  return self.report # don't need to take into account SYN ACK
                else:
                    if self.own_ip and pkt.ip.dst == self.own_ip or "192.168" not in pkt.ip.src:  # server response
                        if pkt.tcp.flags_reset == '1':
                            # print(dir(pkt.tcp))
                            state = "RST"
                        elif pkt.tcp.flags_fin == "1":
                            state = "FIN"  # FIN will later tell us if the connection was really a success
                        elif pkt.tcp.len != "0":
                            state = "SUC"  # We are interested in server exchanging data
                        else:
                            state = "OTHER"
                    else:  # otherwise, we don't care about the client behaviors
                        if not self.own_ip:
                            pass
                            #  print("Determining state is not accurate, own_ip is missing")
                        state = "OTHER"

                if target in self.report.ip_dict:
                    self.report.ip_dict[target]["Total"] += 1
                    if state in self.report.ip_dict[target]:
                        self.report.ip_dict[target][state] += 1
                    else:
                        self.report.ip_dict[target][state] = 1
                else:
                    self.report.ip_dict[target] = {"Total": 1, state: 1}
        return self.report


cc_analyzer = None


def inspect_packet(pkt):
    cc_analyzer.analyze(pkt)


def test_cnc_analyzer(pcap, own_ip):
    global cc_analyzer
    if cc_analyzer is not None:
        del cc_analyzer
    cc_analyzer = CnCAnalyzer(own_ip)
    cap = pyshark.FileCapture(pcap)
    cap.apply_on_packets(inspect_packet)
    if cc_analyzer.report.is_ready():
        result = cc_analyzer.report.get()
        print(f'result of cnc_analyze: {result}')
    else:
        print(f'result of cnc_analyze not ready')
