import asyncio
import libvirt
import libvirtaio
import libxml2

class SandboxContext:
    def __init__(self, loop):
        self.loop = loop
        self.event_imp = libvirtaio.virEventRegisterAsyncIOImpl()
        self.conn = libvirt.open("qemu:///system")

    def gen_config(self, arch, name):
        pass

    def create_fs(self, arch, name):
        pass

    def destroy_fs(self, arch, name):
        pass


class Sandbox:
    def __init__(self, context, arch, name):
        self.context = context
        self.arch = arch
        self.name = name
        self.dom = None
        self.dom_changed_event = asyncio.Event()

    def _conn(self):
        return self.context.conn

    def _life_cycle_cb(conn, dom, event, detail, dom_changed_event):
        if (event == libvirt.VIR_DOMAIN_EVENT_STARTED or event ==
            libvirt.VIR_DOMAIN_EVENT_STOPPED):
            dom_changed_event.set()

    def create(self):
        self.context.create_fs(self.arch, self.name)
        config = self.context.gen_config()
        self.dom = self._conn().createXML(config)

    def fetch_log(self):
        pass

    def destroy(self):
        self.dom.destroy()

