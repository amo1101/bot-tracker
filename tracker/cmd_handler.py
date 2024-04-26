import asyncio
import os
from log import TaskLogger
import time
import sys
from sandbox_context import SandboxContext
from scheduler import Scheduler
from db_store import *
from cli import parse_cmd

CUR_DIR = os.path.dirname(os.path.abspath(__file__))

l = TaskLogger(__name__)

server_task = None
bot_scheduler = None
bot_db_store = None


async def handle_list_bot(args):
    l.debug(f'handle_list_bot: {args}')
    resp = ""
    argc = len(args)
    status = []
    bot_id = None
    if '_' in args:
        bot_id = args['_']
    elif 'status' in args:
        s = args['status']
        if s != 'all':
            status = [s]
    else:
        status = [BotStatus.STAGED.value,
                  BotStatus.ACTIVE.value,
                  BotStatus.DORMANT.value]

    await bot_scheduler.manual_update_bot_info()
    bots = await bot_db_store.load_bot_info(status, bot_id)

    if len(bots) == 1:
        resp = repr(bots[0])
        return resp

    head = f"{'bot_id':<68}{'family':<16}{'status':<12}"
    body = '\n' + len(head) * '-'
    if len(bots) == 0:
        return head + body

    foot = f"\n{'count:':>{len(head) - 10}} {len(bots)}"
    for b in bots:
        body += f"\n{b.bot_id:<68}{b.family:<16}{b.status:<12}"
    body += '\n' + len(head) * '-'
    resp = head + body + foot
    return resp


async def handle_start_bot(args):
    l.debug(f'handle_start_bot: {args}')
    resp = ""
    bot_id = args['_']
    ret = await bot_scheduler.start_bot(bot_id)
    if ret:
        resp = "Bot started"
    else:
        resp = "Bot cannot be started manually in auto scheduler mode"
    return resp


async def handle_stop_bot(args):
    l.debug(f'handle_stop_bot: {args}')
    resp = ""
    bot_id = args['_']
    ret = bot_scheduler.stop_bot(bot_id)
    if ret:
        resp = "Bot stopped"
    else:
        resp = "Bot cannot be stopped manually in auto scheduler mode"
    return resp

async def handle_list_cnc(args):
    l.debug(f'handle_list_cnc: {args}')
    resp = ""
    ip = None
    bot_id = None

    if 'ip' in args:
        ip = args['ip']
    elif 'bot_id' in args:
        bot_id = args['bot_id']
    else:
        pass

    cncs = await bot_db_store.load_cnc_info(bot_id, ip)

    if len(cncs) == 1:
        resp = repr(cncs[0])
        return resp

    head = f"{'ip':<20}{'port':<12}{'bot_id':<64}"
    body = '\n' + len(head) * '-'
    if len(cncs) == 0:
        return head + body

    foot = f"\n{'count:':>{len(head) - 10}} {len(cncs)}"
    for c in cncs:
        body += f"\n{c.ip:<20}" +\
                f"{c.port:<12}" +\
                f"{c.bot_id:<64}"
    body += '\n' + len(head) * '-'
    resp = head + body + foot
    return resp

async def handle_list_cnc_stat(args):
    l.debug(f'handle_list_cnc_stat: {args}')
    resp = ""
    ip = None
    bot_id = None

    if 'ip' in args:
        ip = args['ip']
    elif 'bot_id' in args:
        bot_id = args['bot_id']
    else:
        pass

    cnc_stats = await bot_db_store.load_cnc_stat(bot_id, ip)

    if len(cnc_stats) == 1:
        resp = repr(cnc_stats[0])
        return resp

    head = f"{'ip':<20}{'port':<12}{'bot_id':<24}{'status':<20}{'update_at':<20}"
    body = '\n' + len(head) * '-'
    if len(cnc_stats) == 0:
        return head + body

    foot = f"\n{'count:':>{len(head) - 10}} {len(cnc_stats)}\n"
    for c in cnc_stats:
        body += f"\n{c.ip:<20}" +\
                f"{c.port:<12}" +\
                f"{c.bot_id[:16] + '...':<24}" +\
                f"{c.status:<20}" +\
                f"{c.update_at.strftime('%Y-%m-%d %H:%M:%S'):<20}"
    body += '\n' + len(head) * '-'
    resp = head + body + foot
    return resp

async def handle_schedinfo(args):
    l.debug(f'handle_schedinfo: {args}')
    schedinfo = bot_scheduler.get_scheduler_info()
    resp = f'{"mode":<20}: {schedinfo[0]}\n' +\
            f'{"sandbox_vcpu_quota":<20}: {schedinfo[1]}\n' +\
            f'{"max_sandbox_num":<20}: {schedinfo[2]}\n' +\
            f'{"max_dormant_duration":<20}: {schedinfo[3]}\n' +\
            f'{"cnc_probing_duration":<20}: {schedinfo[4]}'
    return resp

async def handle_set_sched(args):
    l.debug(f'handle_set_sched: {args}')
    bot_scheduler.set_scheduler_info(**args)
    return 'schedule parameters changed'


cmd_registry = {
    'list-bot': handle_list_bot,
    'start-bot': handle_start_bot,
    'stop-bot': handle_stop_bot,
    'list-cnc': handle_list_cnc,
    'list-cnc-stat': handle_list_cnc_stat,
    'schedinfo': handle_schedinfo,
    'set-sched': handle_set_sched
}


async def handle_client(reader, writer):
    while True:
        data = await reader.read(8192)
        l.debug(f'received command: {data}')
        if not data:
            break

        command = data.decode()
        cmd, params = parse_cmd(command)
        l.debug(f'{cmd} : {params}')
        resp = ""
        if cmd not in cmd_registry:
            resp = f"command {cmd} not supported"
        else:
            handler = cmd_registry[cmd]
            resp = await handler(params)

        writer.write(resp.encode())
        await writer.drain()

    writer.close()
    await writer.wait_closed()

async def handle_client_task(reader, writer):
    task = asyncio.create_task(handle_client(reader, writer), name="t_handle_client")
    await task

async def start_server():
    server = await asyncio.start_server(
        handle_client_task, '127.0.0.1', 8888)

    addr = server.sockets[0].getsockname()
    l.debug(f'Command server on {addr}...')

    async with server:
        await server.serve_forever()


def start_cmd_handler(scheduler, db_store):
    global bot_db_store, bot_scheduler
    bot_db_store = db_store
    bot_scheduler = scheduler
    asyncio.create_task(start_server(), name='t_cmd_handler')
