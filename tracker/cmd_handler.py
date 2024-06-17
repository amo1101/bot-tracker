import asyncio
from cli import parse_cmd, cmd_buffer_len
from db_store import *

l: TaskLogger = TaskLogger(__name__)

server_task = None
bot_scheduler = None
bot_db_store = None


async def handle_list_bot(args):
    l.debug(f'handle_list_bot: {args}')
    status = []
    bot_id = None
    if '_' in args:
        bot_id = args['_']
    elif 'status' in args:
        status = [args['status']]
    elif 'all' in args:
        status = None
    else:
        status = [BotStatus.STAGED.value,
                  BotStatus.ACTIVE.value,
                  BotStatus.DORMANT.value]

    bots = await bot_db_store.load_bot_info(status, bot_id)

    if len(bots) == 1:
        return repr(bots[0])

    head = f"{'bot_id':<68}{'family':<16}{'arch':<16}{'upload_at':<24}{'status':<12}"
    body = '\n' + len(head) * '-'
    if len(bots) == 0:
        return head + body

    foot = f"\n{'count:':>{len(head) - 10}} {len(bots)}"
    for b in bots:
        body += f"\n{b.bot_id:<68}{b.family:<16}{b.arch_spec:<16}{b.upload_at:<24}{b.status:<12}"
    body += '\n' + len(head) * '-'
    return head + body + foot


async def handle_start_bot(args):
    l.debug(f'handle_start_bot: {args}')
    resp = ""
    status = None
    bot_id = None
    if '_' in args:
        bot_id = args['_']
    if 'status' in args:
        status = [args['status']]
    else:
        status = [BotStatus.UNKNOWN.value,
                  BotStatus.INTERRUPTED.value,
                  BotStatus.STAGED.value,
                  BotStatus.DORMANT.value,
                  BotStatus.ACTIVE.value]

    ret = await bot_scheduler.start_bot(bot_id, status)
    if ret:
        resp = "Bot started"
    else:
        resp = "Bot cannot be started manually in auto scheduler mode"
    return resp


async def handle_stop_bot(args):
    l.debug(f'handle_stop_bot: {args}')
    resp = ""
    bot_id = None
    status = None
    unstage = None
    if '_' in args:
        bot_id = args['_']
    if 'status' in args:
        status = [args['status']]
    if 'unstage' in args:
        unstage = args['unstage']
    else:
        unstage = 'no'

    ret = await bot_scheduler.stop_bot(bot_id, status, unstage)
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
        body += f"\n{c.ip:<20}" + \
                f"{c.port:<12}" + \
                f"{c.bot_id:<64}"
    body += '\n' + len(head) * '-'
    resp = head + body + foot
    return resp


async def handle_list_attack(args):
    l.debug(f'handle_list_attack: {args}')
    resp = ""
    time_range = None
    cnc_ip = None
    bot_id = None

    if 'time' in args:
        t_str = args['time'].split(',')
        time_range = (t_str[0], t_str[1])
    elif 'cnc_ip' in args:
        cnc_ip = args['cnc_ip']
    elif 'bot_id' in args:
        bot_id = args['bot_id']
    else:
        pass

    # update attack report first
    await bot_scheduler.update_attack_report(bot_id)
    attack_info = await bot_db_store.load_attack_info(bot_id, cnc_ip,
                                                      time_range)

    if len(attack_info) == 1:
        resp = repr(attack_info[0])
        return resp

    head = f"{'bot_id':<24}{'cnc_ip':<20}{'attack_type':<20}{'time':<24}{'duration':<16}{'pps':<12}{'bandwidth':<12}"
    body = '\n' + len(head) * '-'
    if len(attack_info) == 0:
        return head + body

    foot = f"\n{'count:':>{len(head) - 10}} {len(attack_info)}\n"
    for a in attack_info:
        if len(a.bot_id) <= 16:
            body += f"\n{a.bot_id[:16]:<24}"
        else:
            body += f"\n{a.bot_id[:16] + '...':<24}"
        body += f"{a.cnc_ip:<20}{a.attack_type:<20}"
        body += f"{a.time.strftime('%Y-%m-%d %H:%M:%S'):<24}"
        body += f"{str(a.duration):<16}"
        bw = "{:.3f}".format(a.bandwidth / 1000.0) + ' KB/s'
        body += f"{str(a.pps):<12}{bw:<12}"
    body += '\n' + len(head) * '-'
    resp = head + body + foot
    return resp


async def handle_schedinfo(args):
    l.debug(f'handle_schedinfo: {args}')
    schedinfo = bot_scheduler.get_scheduler_info()
    resp = f'{"mode":<20}: {schedinfo[0]}\n' + \
           f'{"sandbox_vcpu_quota":<20}: {schedinfo[1]}\n' + \
           f'{"max_sandbox_num":<20}: {schedinfo[2]}\n' + \
           f'{"max_dormant_duration":<20}: {schedinfo[3]}\n' + \
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
    'list-attack': handle_list_attack,
    'schedinfo': handle_schedinfo,
    'set-sched': handle_set_sched
}


async def handle_client(reader, writer):
    while True:
        data = await reader.read(cmd_buffer_len)
        l.debug(f'received command: {data}')
        if not data:
            break

        command = data.decode()
        cmd, params = parse_cmd(command)
        l.debug(f'{cmd} : {params}')
        resp = ""
        if cmd not in cmd_registry:
            resp = f"Command {cmd} not supported"
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
    l.info(f'Command server on {addr}...')

    async with server:
        await server.serve_forever()


def start_cmd_handler(scheduler, db_store):
    global bot_db_store, bot_scheduler
    bot_db_store = db_store
    bot_scheduler = scheduler
    asyncio.create_task(start_server(), name='t_cmd_handler')
