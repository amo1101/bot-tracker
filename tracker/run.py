import asyncio
import libvirt
import libvirtaio
import libxml2
import os
from log import TaskLogger
import time
import sys
from db import *
from sandbox_context import SandboxContext
from sandbox_context import SandboxNWFilter
from sandbox import Sandbox
from scheduler import Scheduler
import cmd_handler

CUR_DIR = os.path.dirname(os.path.realpath(__file__))

l = TaskLogger(__name__)

async def async_main(arguments = None):
    # start the server task
    sandbox_ctx = SandboxContext()
    sandbox_ctx.start()
    db_store = DBStore()
    await db_store.open()
    scheduler = Scheduler(sandbox_ctx, db_store)
    cmd_handler.start_cmd_handler(scheduler, db_store)
    await scheduler.checkpoint()
    await db_store.close()
    sandbox_ctx.destroy()

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

