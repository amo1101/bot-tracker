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
from scheduler import Scheduler

CUR_DIR = os.path.dirname(os.path.realpath(__file__))

#  now = datetime.now()
#  current_time = now.strftime("%m-%d-%Y-%H_%M_%S")
logging.basicConfig(format='%(asctime)s-%(name)s-%(levelname)s-%(message)s',
                    datefmt='%d-%b-%y %H:%M:%S', level = logging.DEBUG)
l = logging.getLogger(__name__)

async def async_main(arguments = None):
    sandbox_ctx = SandboxContext()
    sandbox_ctx.start()
    scheduler = Scheduler(sandbox_ctx)
    await scheduler.checkpoint()

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
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        l.debug('Interrupted by user')
    #  test()

