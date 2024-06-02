import os
import subprocess
from enum import Enum
import libvirt
from lxml import etree
from log import TaskLogger

l: TaskLogger = TaskLogger(__name__)
CUR_DIR = os.path.dirname(os.path.realpath(__file__))


class NetworkMode(Enum):
    BLOCK = 0
    RATE_LIMIT = 1

class SandboxNWFilter(Enum):
    DEFAULT = "sandbox-default-filter"
    DEFAULT_RATE_LIMIT = "sandbox-default-filter-rate-limit"
    CNC = "sandbox-cnc-filter"
    CNC_RATE_LIMIT = "sandbox-cnc-filter-rate-limit"


class SandboxScript(Enum):
    PREPARE_FS = "prepare_fs.sh"
    FETCH_LOG = "fetch_log.sh"
    REDIRECT = "redirect.sh"
    DEFAULT_RULE = "default_rule.sh"



class SandboxContext:
    def __init__(self,
                 network_mode,
                 dns_rate_limit,
                 https_proxy_port,
                 allowed_tcp_ports,
                 simulated_server,
                 network_peak,
                 network_average,
                 network_burst,
                 port_peak,
                 port_average,
                 port_burst,
                 port_max_conn):
        self.conn = None
        self.net = None
        self.image_dir = "/var/lib/libvirt/images"
        self.config_base = CUR_DIR + os.sep + "config"
        self.image_base = CUR_DIR + os.sep + "image"
        self.scripts_base = CUR_DIR + os.sep + "scripts"
        self.bot_dir = CUR_DIR + os.sep + "bot"
        self.net_conf = self.config_base + os.sep + "network.xml"
        self.subnet = ''
        self.netmask = ''
        self.network_mode = network_mode
        self.dns_rate_limit = dns_rate_limit
        self.https_proxy_port = https_proxy_port
        self.allowed_tcp_ports = allowed_tcp_ports
        self.simulated_server = simulated_server
        self.network_peak = network_peak
        self.network_average = network_average
        self.network_burst = network_burst
        self.port_peak = port_peak
        self.port_average = port_average
        self.port_burst = port_burst
        self.port_max_conn = port_max_conn
        self.sandbox_registry = \
            {
                "ARM_32_L": [
                    "sandbox_armv7.xml",
                    "openwrt-armsr-armv7-generic-kernel.bin",
                    "openwrt-armsr-armv7-generic-ext4-rootfs.img"
                ]
            }

        self.sandbox_nwfilter_registry = \
            {
                SandboxNWFilter.DEFAULT.value:
                    ["default_filter.xml", "bind_default_filter.xml"],
                SandboxNWFilter.DEFAULT_RATE_LIMIT.value:
                    ["default_filter_rate_limit.xml", "bind_default_filter_rate_limit.xml"],
                SandboxNWFilter.CNC.value:
                    ["cnc_filter.xml", "bind_cnc_filter.xml"],
                SandboxNWFilter.CNC_RATE_LIMIT.value:
                    ["cnc_filter_rate_limit.xml", "bind_cnc_filter_rate_limit.xml"],
            }

        self.nwfilter_objs = []

    def get_subnet(self):
        return self.subnet, self.netmask

    def _get_net_config(self):
        with open(self.net_conf, 'r') as file:
            net_xml = file.read()

        tree = etree.fromstring(net_xml)
        ip_node = tree.xpath("//ip")[0]
        ip_addr = ip_node.get('address')

        self.netmask = ip_node.get('netmask')
        if self.netmask != '255.255.255.0':
            l.warning('Wrong network configuration, only support /24 prefix.')
        segs = ip_addr.split('.')
        self.subnet = '.'.join(segs[:3]) + '.0'
        l.debug(f'subnet: {self.subnet}, netmask: {self.netmask}')

        # block mode do not rate limit bandwidth
        if self.network_mode == NetworkMode.BLOCK:
            return net_xml

        net_bandwidth_node = tree.xpath("//bandwidth/outbound")[0]
        net_bandwidth_node.set('average', self.network_average)
        net_bandwidth_node.set('peak', self.network_peak)
        net_bandwidth_node.set('burst', self.network_burst)

        port_bandwidth_node = tree.xpath("//portgroup/bandwidth/outbound")[0]
        port_bandwidth_node.set('average', self.port_average)
        port_bandwidth_node.set('peak', self.port_peak)
        port_bandwidth_node.set('burst', self.port_burst)

        return etree.tostring(tree, encoding='unicode')

    @property
    def network_mode(self):
        return self.network_mode

    @property
    def default_nwfilter(self):
        if self.network_mode == NetworkMode.BLOCK:
            return SandboxNWFilter.DEFAULT
        return SandboxNWFilter.DEFAULT_RATE_LIMIT

    @property
    def cnc_nwfilter(self):
        if self.network_mode == NetworkMode.BLOCK:
            return SandboxNWFilter.CNC
        return SandboxNWFilter.CNC_RATE_LIMIT

    @property
    def allowed_tcp_ports(self):
        return self.allowed_tcp_ports

    @property
    def simulated_server(self):
        return self.simulated_server

    def is_supported_arch(self, arch):
        return arch in self.sandbox_registry

    def get_sandbox_config(self, arch, name):
        if arch not in self.sandbox_registry:
            return ""

        with open(self.config_base + os.sep + self.sandbox_registry[arch][0], 'r') as file:
            sandbox_xml = file.read()

        # replace sandbox name
        tree = etree.fromstring(sandbox_xml)
        name_element = tree.xpath("//name")[0]
        name_element.text = f"openwrt-vm-{arch}-{name}"

        # replace kernel name
        kernel_element = tree.xpath("//os/kernel")[0]
        kernel_element.text = self.get_sandbox_kernel(arch)[1]

        # replace fs name
        source_element = tree.xpath("//devices/disk/source")[0]
        source_element.set("file", self.get_sandbox_fs(arch, name)[1])
        return etree.tostring(tree, encoding='unicode')

    def get_sandbox_kernel(self, arch):
        if arch not in self.sandbox_registry:
            return "", ""

        kernel_file = self.sandbox_registry[arch][1]
        return (self.image_base + os.sep + kernel_file,
                self.image_dir + os.sep + kernel_file)

    def get_sandbox_fs(self, arch, name):
        if arch not in self.sandbox_registry:
            return "", ""

        fs_src = self.sandbox_registry[arch][2]
        fs_dst = f"openwrt-vm-{arch}-{name}-ext4-rootfs.img"
        return (self.image_base + os.sep + fs_src,
                self.image_dir + os.sep + fs_dst)

    def get_script(self, name):
        if name == SandboxScript.PREPARE_FS:
            return self.scripts_base + os.sep + SandboxScript.PREPARE_FS.value
        elif name == SandboxScript.REDIRECT:
            return self.scripts_base + os.sep + SandboxScript.REDIRECT.value
        elif name == SandboxScript.FETCH_LOG:
            return self.scripts_base + os.sep + SandboxScript.FETCH_LOG.value
        else:
            return ""

    def run_script(self, which, *args):
        try:
            params = []
            script = self.get_script(which)
            params.append(script)
            for p in args:
                params.append(p)
            l.debug(f'params: ${params}')
            proc = subprocess.Popen(params, stdout=subprocess.PIPE)
            out, err = proc.communicate()
            if err:
                l.error("Failed to run script:{script}, error: {err}")
                return False
            return True
        except Exception as err:
            l.error(f'Exception occurred: {err}')
            return False

    def get_bot_dir(self):
        return self.bot_dir

    def _define_nwfilters(self):
        for k, v in self.sandbox_nwfilter_registry.items():
            with open(self.config_base + os.sep + v[0], 'r') as file:
                xml_desc = file.read()
            obj = self.conn.nwfilterDefineXML(xml_desc)
            if obj:
                self.nwfilter_objs.append(obj)
                l.debug(f'nwfilter defined:\n{xml_desc}')
            else:
                l.error("Failed to define nwfilter %s", k)
                return False
        return True

    def _undefine_nwfilters(self):
        for obj in self.nwfilter_objs:
            obj.undefine()

    def _get_nwfilter_binding(self, filter_name, **kwargs):
        if filter_name not in SandboxNWFilter:
            return ""

        l.debug(f'filter: {filter_name}, kwargs: {kwargs}')

        if 'port_dev' not in kwargs or 'mac_addr' not in kwargs:
            l.error('port_dev or mac_adr not specified')
            return ''

        # key: key of input parameter
        # value: [xpath, attr_to_match, atrr_to_set]
        para_to_check = \
            {
                "mal_repo_ip": ["//filterref/parameter[@name='MAL_REPO_IP']", "value"],
                "sandbox_ip": ["//filterref/parameter[@name='SANDBOX_IP']", "value"],
                "cnc_ip": ["//filterref/parameter[@name='CNC_IP']", "value"],
                "allowed_tcp_ports": ["//filterref/parameter[@name='TCP_PORT']", "value"],
                "simulated_server": ["//filterref/parameter[@name='SIM_SERVER']", "value"],
                "conn_limit": ["//filterref/parameter[@name='CONN_LIMIT']", "value"]
            }

        if (filter_name == SandboxNWFilter.DEFAULT or
            filter_name == SandboxNWFilter.DEFAULT_DEFAULT_RATE_LIMIT):
            del para_to_check["cnc_ip"]
            del para_to_check["allowed_tcp_ports"]
            del para_to_check["simulated_server"]
            del para_to_check["conn_limit"]
        elif filter_name == SandboxNWFilter.CNC:
            del para_to_check["conn_limit"]
        else:
            del para_to_check["allowed_tcp_ports"]
            del para_to_check["simulated_server"]

        if not all(p in kwargs for p in para_to_check):
            l.error("some parameter is not provided for the nwfilter binding \
                    %s.", filter_name.value)
            return ""

        with open(self.config_base + os.sep +
                  self.sandbox_nwfilter_registry[filter_name.value][1], 'r') as file:
            bind_xml = file.read()

        l.debug(f'para_to_check: {para_to_check}')
        # set parameters
        tree = etree.fromstring(bind_xml)
        # set portdev and mac
        tree.xpath("//portdev")[0].set("name", kwargs['port_dev'])
        tree.xpath("//mac")[0].set("address", kwargs['mac_addr'])
        # set parameters
        parent = tree.xpath("//filterref")[0]
        for k, v in para_to_check.items():
            l.debug(f'-->k:{k}, v:{v}')
            if k in kwargs:
                para_element = tree.xpath(v[0])[0]
                if para_element is not None:
                    val = kwargs[k]
                    if isinstance(val, list):
                        for e in val:
                            para_copied = etree.Element(para_element.tag, para_element.attrib)
                            para_copied.set(v[1], e)
                            parent.append(para_copied)
                        parent.remove(para_element)
                    else:
                        para_element.set(v[1], val)

        return etree.tostring(tree, encoding='unicode')

    def _default_rule(self, switch='ON'):
        s = SandboxScript.DEFAULT_RULE
        self.run_script(s, switch,
                        self.subnet + '/24',
                        self.dns_rate_limit,
                        self.https_proxy_port)

    def create_sandbox(self, sandbox_xml):
        return self.conn.createXML(sandbox_xml, libvirt.VIR_DOMAIN_START_VALIDATE)

    def apply_nwfilter(self, filter_name, **kwargs):
        tcp_ports = self.allowed_tcp_ports.split(',')
        binding_xml = self._get_nwfilter_binding(filter_name,
                                                 allowed_tcp_ports=tcp_ports,
                                                 simulated_server=self.simulated_server,
                                                 conn_limit=self.port_max_conn,
                                                 **kwargs)
        if binding_xml == "":
            return None

        l.debug("binding xml:\n%s", binding_xml)

        return self.conn.nwfilterBindingCreateXML(binding_xml)

    def start(self):
        self.conn = libvirt.open("qemu:///system")

        # if default notwork is running, destroy it firstly
        try:
            default_net = self.conn.networkLookupByName("default")
            if default_net is not None and default_net.isActive():
                l.debug("destroy default network...")
                default_net.destroy()
        except libvirt.libvirtError as e:
            l.debug(f'libvirt exception occured: {e}')

        net_xml = self._get_net_config()
        l.debug(f'net_xml:\n{net_xml}')
        self.net = self.conn.networkCreateXMLFlags(net_xml)

        if not self.net.isActive():
            l.error("network is not active")
            return False

        l.info("network is active")

        self._default_rule('ON')

        # define nwfilters
        if not self._define_nwfilters():
            l.error("failed to define network filters")
            return False

        l.info("nwfilters are defined")
        return True

    def destroy(self):
        # now we should have all domains destroyed
        # undefine nwfilters
        self._undefine_nwfilters()

        self._default_rule('OFF')

        if self.net is not None and self.net.isActive():
            l.debug("destroying network...")
            self.net.destroy()
        self.conn.close()
