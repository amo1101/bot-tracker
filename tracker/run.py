import asyncio
import configparser
import cmd_handler
import os
from db_store import *
from sandbox_context import SandboxContext
from scheduler import Scheduler

CUR_DIR = os.path.dirname(os.path.abspath(__file__))

l: TaskLogger = TaskLogger(__name__)


async def async_main(arguments=None):
    # start the server task
    config = configparser.ConfigParser()
    ini_file = CUR_DIR + os.sep + 'config' + os.sep + 'config.ini'
    if not os.path.exists(ini_file):
        l.error('ini file not exist!')
        return

    config.read(ini_file)
    sandbox_ctx = SandboxContext(config['network_control']['subnet'],
                                 config['network_control']['dns_server'],
                                 int(config['network_control']['mode']),
                                 config['network_control']['redirected_tcp_ports'],
                                 config['network_control']['simulated_server'],
                                 config['network_control']['network_peak'],
                                 config['network_control']['network_average'],
                                 config['network_control']['network_burst'],
                                 config['network_control']['port_peak'],
                                 config['network_control']['port_average'],
                                 config['network_control']['port_burst'],
                                 config['network_control']['port_max_conn'])
    sandbox_ctx.start()

    db_store = DBStore(config['database']['host'],
                       config['database']['port'],
                       config['database']['dbname'],
                       config['database']['user'],
                       config['database']['password'])
    await db_store.open()

    scheduler = Scheduler(config['local_bot_repo']['ip'],
                          config['local_bot_repo']['user'],
                          config['local_bot_repo']['path'],
                          config['interface_monitor']['iface'],
                          config['interface_monitor']['excluded_ips'],
                          config['interface_monitor']['action'],
                          config['interface_monitor']['mute_report'],
                          int(config['scheduler']['mode']),
                          int(config['scheduler']['sandbox_vcpu_quota']),
                          int(config['scheduler']['max_sandbox_num']),
                          int(config['scheduler']['max_dormant_duration']),
                          int(config['scheduler']['bot_probing_duration']),
                          config['scheduler']['allow_duplicate_bots'],
                          int(config['scheduler']['max_cnc_candidates']),
                          config['scheduler']['trace_bot_syscall'],
                          config['packet_analyzer']['ring_capture'],
                          int(config['packet_analyzer']['ring_file_size']),
                          config['packet_analyzer']['bpf_filter'],
                          config['packet_analyzer']['excluded_ips'],
                          int(config['packet_analyzer']['max_analyzing_workers']),
                          int(config['packet_analyzer']['min_cnc_attempts']),
                          int(config['packet_analyzer']['attack_gap']),
                          int(config['packet_analyzer']['min_attack_packets']),
                          int(config['packet_analyzer']['attack_detection_watermark']),
                          sandbox_ctx,
                          db_store)

    cmd_handler.start_cmd_handler(scheduler, db_store)
    await scheduler.checkpoint()
    await scheduler.destroy()
    await db_store.close()
    sandbox_ctx.destroy()


async def main_task():
    task = asyncio.create_task(async_main(), name="t_async_main")
    await task

if __name__ == "__main__":
    try:
        #  asyncio.get_event_loop().run_until_complete(main_task())
        asyncio.run(main_task(), debug=True)
    except KeyboardInterrupt:
        l.info('Interrupted by user')
