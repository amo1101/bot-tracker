import asyncio
import libvirt
import libvirtaio
import libxml2
import aiofiles

class SandboxContext:
    def __init__(self, loop, net_conf):
        self.loop = loop
        self.event_imp = None
        self.conn = None
        self.net = None
        self.net_conf = net_conf

    async def create(self):
        self.event_imp = libvirtaio.virEventRegisterAsyncIOImpl()
        self.conn = libvirt.open("qemu:///system")

        async with aiofiles.open(file_path, mode='r') as file:
            net_xml = await file.read()

        self.net = self.conn.networkCreateXML(net_xml)

    def destroy(self):
        self.net.destroy()
        self.conn.close()

