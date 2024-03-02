import asyncio
import libvirt
import libvirtaio
import libxml2
import os
import shutil
import logging
import time
import sys
import sandbox_context

l = logging.getLogger(__name__)

class Sandbox:
    def __init__(self, context, name, arch):
        self.context = context
        self.name = name
        self.arch = arch
        self.parameter = None
        self.dom = None
        #  self.dom_changed_event = asyncio.Event()
        self.fs = None

    @staticmethod
    def _life_cycle_cb(conn, dom, event, detail, dom_changed_event):
        if event == libvirt.VIR_DOMAIN_EVENT_STARTED or event == \
           libvirt.VIR_DOMAIN_EVENT_STOPPED:
            l.debug("domain lifecycle event occured, event: %d, detail: %d",
                    event, detail)
            dom_changed_event.set()

    def _prepare_kernel(self):
        src, dst = self.context.get_sandbox_kernel(self.arch)
        l.debug("kernel src %s, dst %s", src, dst)
        if not os.path.exists(dst):
            shutil.copyfile(src, dst)

    def _prepare_fs(self):
        src, dst = self.context.get_sandbox_fs(self.arch, self.name)
        l.debug("fs src %s, dst %s", src, dst)

        # TODO: prepare fs
        self.fs = dst

        if not os.path.exists(dst):
            shutil.copyfile(src, dst)

    def _get_config(self):
        return self.context.get_sandbox_config(self.arch, self.name)

    def _destroy_fs(self):
        if os.path.exists(self.fs):
            os.remove(self.fs)

    def _fetch_log(self):
        pass

    def start(self):
        self._prepare_kernel()
        self._prepare_fs()
        dom_xml = self._get_config()
        l.debug("dom config:")
        l.debug("%s", dom_xml)

        self.dom = self.context.conn.createXML(dom_xml,
                                               libvirt.VIR_DOMAIN_START_VALIDATE)
        if self.dom is None:
            l.error("create domain %s failed", self.name)
            return

        while True:
            if self.dom.state()[0] != libvirt.VIR_DOMAIN_RUNNING:
                l.debug("domain state %d, reason %d...", self.dom.state()[0],
                        self.dom.state()[1])
                time.sleep(5)
            else:
                break

        l.debug("domain state %d, reason %d...", self.dom.state()[0],
                self.dom.state()[1])

    def apply_net_filter(self, fid, **kwargs):
        pass

    def destroy(self):
        self._fetch_log()
        self._destroy_fs()
        self.dom.destroy()
        l.debug("dom destroyed %s", self.name)

