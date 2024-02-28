import asyncio
import libvirt
import libvirtaio
import libxml2

class Sandbox:
    def __init__(self, context, arch, parameter):
        self.context = context
        self.arch = arch
        self.parameter = parameter
        self.dom = None
        self.dom_changed_event = asyncio.Event()

    def _life_cycle_cb(conn, dom, event, detail, dom_changed_event):
        if (event == libvirt.VIR_DOMAIN_EVENT_STARTED or event ==
            libvirt.VIR_DOMAIN_EVENT_STOPPED):
            dom_changed_event.set()

    def _parepare_fs(self):
        pass

    def _gen_config(self):
        pass

    def _destroy_fs(self):
        pass

    def _fetch_log(self):
        pass

    def create(self):
        self._prepare_fs()
        dom_xml = self._gen_config()
        self.dom = self.context.conn.createXML(dom_xml)

    def destroy(self):
        self._fetch_log()
        self._destroy_fs()
        self.dom.destroy()

