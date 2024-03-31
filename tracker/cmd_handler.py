import asyncio
import os
from log import TaskLogger
import time
import sys
from sandbox_context import SandboxContext
from scheduler import Scheduler

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
DB_MODULE_DIR = os.path.dirname(CUR_DIR) + os.sep + 'db'
sys.path.append(DB_MODULE_DIR)
from db_store import *

l = TaskLogger(__name__)

server_task = None
bot_scheduler = None
bot_db_store = None

cmd_registry = {
    'list_bot': handle_list_bot,
    'start_bot': handle_start_bot,
    'stop_bot': handle_stop_bot,
    'list_tracker': handle_list_tracker,
    'balance_load': handle_balance_load
}

# command: list_bot [--all] [bot_id]
# without args: list all running bots
# --all: list all bots
# bot_id: list bot specified by bot_id
async def handle_list_bot(args):
    resp = ""
    argc = len(args)
    if argc > 3 or argc < 1:
        resp = "Error arguments"
    else:
        status = None
        bot_id = None
        if argc == 1:
            status = [BotStatus.STARTED.value,
                      BotStatus.ACTIVE.value,
                      BotStatus.DORMANT.value]
        elif args[1] == '--all':
            status = None
        else:
            bot_id = args[1]
    bots = await bot_db_store.load_bot_info(status, bot_id)
    resp = 'List of bots:\n'
    for b in bots:
        resp += repr(b)
        resp += '\n'
    return resp


async def handle_start_bot(args):
    resp = ""
    argc = len(args)
    if argc != 2:
        resp = "Error arguments"
    else:
        status = None
        bot_id = args[1]
        await bot_scheduler.start_bot(bot_id)
        resp = "Bot started"
    return resp

async def handle_stop_bot(args):
    resp = ""
    argc = len(args)
    if argc != 2:
        resp = "Error arguments"
    else:
        status = None
        bot_id = args[1]
        await bot_scheduler.stop_bot(bot_id)
        resp = "Bot stopped"
    return resp

#TODO
async def handle_list_tracker(args):
    pass

#TODO
async def handle_balance_load(args):
    pass

async def handle_client(reader, writer):
    while True:
        data = await reader.read(100)
        if not data:
            break

        message = data.decode()
        para = message.split(' ',2)
        cmd = para[0]
        resp = ""
        if cmd not in cmd_registry:
            resp = f"command {cmd} not supported"
        else:
            handler = cmd_registry[cmd]
            resp = await handler(para)

        writer.write(resp.encode())
        await writer.drain()

    writer.close()
    await writer.wait_closed()


async def start_server():
    server = await asyncio.start_server(
        handle_client, '127.0.0.1', 8888)

    addr = server.sockets[0].getsockname()
    l.debug(f'Command server on {addr}...')

    async with server:
        await server.serve_forever()

def start_cmd_handler(scheduler, db_store):
    global bot_db_store, bot_scheduler
    bot_db_store = db_store
    bot_scheduler = scheduler
    asyncio.create_task(start_server(), name='cmd_handler')


