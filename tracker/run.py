import asyncio
import libvirt
import libvirtaio
import os
from log import TaskLogger
import time
import sys
import configparser
from sandbox_context import SandboxContext
from sandbox import Sandbox
from scheduler import Scheduler
import cmd_handler
from db_store import *
from cnc_analyzer import *
from attack_analyzer import *

CUR_DIR = os.path.dirname(os.path.abspath(__file__))

l = TaskLogger(__name__)


async def async_main(arguments=None):
    # start the server task
    config = configparser.ConfigParser()
    ini_file = CUR_DIR + os.sep + 'config' + os.sep + 'config.ini'
    if not os.path.exists(ini_file):
        l.error('ini file not exist!')
        return

    config.read(ini_file)
    sandbox_ctx = SandboxContext(config['rate_limit']['network_peak'],
                                 config['rate_limit']['network_average'],
                                 config['rate_limit']['network_burst'],
                                 config['rate_limit']['port_peak'],
                                 config['rate_limit']['port_average'],
                                 config['rate_limit']['port_burst'],
                                 config['network_control']['max_conn'],
                                 config['network_control']['allowed_tcp_ports'],
                                 config['network_control']['allowed_server_ip'])
    sandbox_ctx.start()

    db_store = DBStore(config['database']['host'],
                       config['database']['port'],
                       config['database']['dbname'],
                       config['database']['user'],
                       config['database']['password'])
    await db_store.open()

    scheduler = Scheduler(config['tracker']['id'],
                          config['local_bot_repo']['ip'],
                          config['local_bot_repo']['user'],
                          config['local_bot_repo']['path'],
                          config['scheduler']['mode'],
                          int(config['scheduler']['checkpoint_interval']),
                          int(config['scheduler']['sandbox_vcpu_quota']),
                          int(config['scheduler']['max_sandbox_num']),
                          int(config['scheduler']['max_dormant_duration']),
                          int(config['scheduler']['max_packet_analyzing_workers']),
                          int(config['scheduler']['cnc_probing_duration']),
                          sandbox_ctx,
                          db_store)

    cmd_handler.start_cmd_handler(scheduler, db_store)
    await scheduler.checkpoint()
    scheduler.destroy()
    await db_store.close()
    sandbox_ctx.destroy()


async def main_task():
    task = asyncio.create_task(async_main(), name="t_async_main")
    await task

if __name__ == "__main__":
    try:
        asyncio.run(main_task(), debug=True)
    except KeyboardInterrupt:
        l.info('Interrupted by user')
