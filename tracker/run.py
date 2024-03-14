import asyncio
import libvirt
import libvirtaio
import libxml2
import os
from log import TaskLogger
import time
import sys
from sandbox_context import SandboxContext
from sandbox_context import SandboxNWFilter
from sandbox import Sandbox
from scheduler import Scheduler

CUR_DIR = os.path.dirname(os.path.realpath(__file__))

l = TaskLogger(__name__)

async def async_main(arguments = None):
    sandbox_ctx = SandboxContext()
    sandbox_ctx.start()
    scheduler = Scheduler(sandbox_ctx)
    try:
        await scheduler.checkpoint()
    except asyncio.CancelledError:
        l.debug('async main cancelled')

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
        asyncio.run(async_main(),debug=True)
    except KeyboardInterrupt:
        l.debug('Interrupted by user')
    #  test()

