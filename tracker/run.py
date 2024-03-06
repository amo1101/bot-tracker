import asyncio
import libvirt
import libvirtaio
import libxml2
import os
import logging
import time
import sys
from sandbox_context import SandboxContext
from sandbox_context import SandboxNWFilter
from sandbox import Sandbox

#  now = datetime.now()
#  current_time = now.strftime("%m-%d-%Y-%H_%M_%S")
logging.basicConfig(format='%(asctime)s-%(name)s-%(levelname)s-%(message)s',
                    datefmt='%d-%b-%y %H:%M:%S', level = logging.DEBUG)
l = logging.getLogger(__name__)

async def main(arguments = None):
    sandbox_context = SandboxContext()
    bot_scheduler = Scheduler()
    await bot_scheduler.checkpoint()

def test():
    ctx = SandboxContext()
    ctx.start()
    sbx = Sandbox(ctx, "bot", "armv7")
    sbx.start()
    sbx.apply_nwfilter(SandboxNWFilter.DEFAULT)
    sbx.apply_nwfilter(SandboxNWFilter.CNC)
    sbx.apply_nwfilter(SandboxNWFilter.CONN_LIMIT)
    sbx.destroy()
    ctx.destroy()

if __name__ == "__main__":
    #  asyncio.run(main())
    test()

