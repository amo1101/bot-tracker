import asyncio
import libvirt
import libvirtaio
import libxml2
import aiofiles
import os
import logging
import time
import sys

#  now = datetime.now()
#  current_time = now.strftime("%m-%d-%Y-%H_%M_%S")
logging.basicConfig(format='%(asctime)s-%(name)s-%(levelname)s-%(message)s',
                    datefmt='%d-%b-%y %H:%M:%S', level = logging.DEBUG)
l = logging.getLogger(__name__)

CUR_DIR = os.path.dirname(os.path.realpath(__file__))

class SandboxContext:
    def __init__(self):
        #  self.loop = loop
        self.event_imp = None
        self.conn = None
        self.net = None
        self.net_conf = CUR_DIR + "/config/network.xml"


    @staticmethod
    def _net_lifecycle_cb(conn, net, event, detail, net_changed_event):
        if event == libvirt.VIR_NETWORK_EVENT_STARTED or event == \
        libvirt.VIR_NETWORK_EVENT_STOPPED:
            l.debug("network lifecycle event occured, event: %d, detail: %d",
                    event, detail)
            net_changed_event.set()

    async def create(self):
        #  self.event_imp = libvirtaio.virEventRegisterAsyncIOImpl()
        self.conn = libvirt.open("qemu:///system")
        #  net_changed_event = asyncio.Event()

        # if default notwork is running, destroy it firstly
        default_net = self.conn.networkLookupByName("default")
        if default_net is not None and default_net.isActive():
            l.debug("destroy default network...")
            default_net.destroy()

        async with aiofiles.open(self.net_conf, mode='r') as file:
            net_xml = await file.read()

        self.net = self.conn.networkCreateXMLFlags(net_xml)

        #  self.conn.networkEventRegisterAny(self.net,
                                          #  libvirt.VIR_NETWORK_EVENT_ID_LIFECYCLE,
                                          #  self._net_lifecycle_cb, net_changed_event)

        #  if self.net.isActive():
            #  l.debug("network is active....")

        #  await asyncio.wait_for(net_changed_event.wait(), 2)
        if self.net.isActive():
            l.debug("network is active")
            return True
        l.debug("network is not active")
        return False


    def destroy(self):
        #  self.conn.networkEventDeregisterAny(libvirt.VIR_NETWORK_EVENT_ID_LIFECYCLE)
        if self.net is not None and self.net.isActive():
            l.debug("destroying network...")
            self.net.destroy()
        self.conn.close()


async def test():
    context = SandboxContext()
    await context.create()
    context.destroy()

if __name__ == "__main__":
    asyncio.run(test())

