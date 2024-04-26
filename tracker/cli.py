import asyncio
import time

welcome_ui = "Welcome to bot-tracker command line.\n\n" +\
    "Type:  'help' for help with commands\n" +\
    "       'quit' to exit\n"
help_outline = "Bot management commands:\n" +\
    "    list-bot                   list bot information.\n" +\
    "    start-bot                  start running bot.\n" +\
    "    stop-bot                   stop running bot.\n\n" +\
    "CnC information query:\n" +\
    "    list-cnc                   list cnc information.\n" +\
    "    list-cnc-stat              list cnc status information.\n\n" +\
    "Bot scheduler setting commands:\n" +\
    "    schedinfo                  show bot scheduler information.\n" +\
    "    set-sched                  set scheduler parameters.\n"

help_list_bot = "NAME\n" +\
    "  list-bot - list bot information.\n" +\
    "\nSYNOPSIS\n" +\
    "  list-bot [bot_id] [--status]\n" +\
    "\nDESCRIPTION\n" +\
    "  List bot information with specified bot_id or bot status.\n" +\
    "  If no option specified, list all 'staged','active' and 'dormant' bots.\n" +\
    "\nOPTIONS\n" +\
    "  [bot_id]: bot id\n" +\
    "  [--all]: list all bots\n" +\
    "  [--status]=<string>: bot status, could be \
'unknown','staged','dormant','active','interrupted','unstaged','error', or 'duplicate'\n"

help_start_bot = "NAME\n" +\
    "  start-bot - start running bot.\n" +\
    "\nSYNOPSIS\n" +\
    "  start-bot <bot_id>\n" +\
    "\nDESCRIPTION\n" +\
    "  Start running bot with specified bot_id in sandbox, supported in manual scheduler mode.\n"

help_stop_bot = "NAME\n" +\
    "  stop-bot - stop running bot.\n" +\
    "\nSYNOPSIS\n" +\
    "  stop-bot <bot_id>\n" +\
    "\nDESCRIPTION\n" +\
    "  Stop running bot with specified bot_id in sandbox, supported in manual scheduler mode.\n"

help_list_cnc = "NAME\n" +\
    "  list-cnc - list CnC information.\n" +\
    "\nSYNOPSIS\n" +\
    "  list-cnc [--ip] [--bot_id]\n" +\
    "\nDESCRIPTION\n" +\
    "  List CnC information with specified bot_id or CnC IP.\n" +\
    "  If no option specified, list all CnC information.\n" +\
    "\nOPTIONS\n" +\
    "  [--bot_id]=<string>: bot id\n" +\
    "  [--ip]=<string>: CnC IP\n"

help_list_cnc_stat = "NAME\n" +\
    "  list-cnc-stat - list CnC status.\n" +\
    "\nSYNOPSIS\n" +\
    "  list-cnc-stat [--ip] [--bot_id]\n" +\
    "\nDESCRIPTION\n" +\
    "  List CnC status information with specified bot_id or CnC IP.\n" +\
    "  If no option specified, list all CnC status information.\n" +\
    "\nOPTIONS\n" +\
    "  [--bot_id]=<string>: bot id\n" +\
    "  [--ip]=<string>: CnC IP\n"

help_schedinfo = "NAME\n" +\
    "  schedinfo - show bot scheduler information.\n" +\
    "\nSYNOPSIS\n" +\
    "  schedinfo\n" +\
    "\nDESCRIPTION\n" +\
    "  Show bot scheduler information.\n"

help_set_sched = "NAME\n" +\
    "  set-sched - set bot scheduler parameters.\n" +\
    "\nSYNOPSIS\n" +\
    "  set-sched [--mode] [--sandbox_vcpu_quota] [--max_sandbox_num]\
[--max_dormant_duration] [--cnc_probing_duration]\n" +\
    "\nDESCRIPTION\n" +\
    "  Set bot scheduler parameters, changes will apply immediately.\n" +\
    "  Multiple parameters can be set at the same time.\n" +\
    "\nOPTIONS\n" +\
    "  [--mode]=<string>: bot scheduler mode, could be 'auto' or 'manual'\n" +\
    "  [--sandbox_vcpu_quota]=<int>: sandbox vcpu quota of [1,100] % of 1 cpu core a vcpu could use.\n" +\
    "  [--max_sandbox_num]=<int>: max number of sandboxes the scheduler can run.\n" +\
    "  [--max_dormant_duration]=<int>: max dormant hours allowed before a bot is unstaged.\n" +\
    "  [--cnc_probing_duration]=<int>: time in seconds for probing CnC server.\n"

cmd_help = {'list-bot': help_list_bot,
            'start-bot': help_start_bot,
            'stop-bot': help_stop_bot,
            'list-cnc': help_list_cnc,
            'list-cnc-stat': help_list_cnc_stat,
            'schedinfo': help_schedinfo,
            'set-sched': help_set_sched}

cmd_config = {
    'help': ([0, 1], {
        '_': lambda v: v in ['list-bot',
            'start-bot',
            'stop-bot',
            'list-cnc',
            'list-cnc-stat',
            'schedinfo',
            'set-sched']}),

    'list-bot': ([0, 1], {
        '_': lambda v: True,
        'status': lambda v: v in ['unknown',
            'staged',
            'dormant',
            'active',
            'interrupted',
            'unstaged',
            'error',
            'duplicate',
            'all']}),

    'start-bot': ([1, 1], {'_': lambda v: True}),
    'stop-bot': ([1, 1], {'_': lambda v: True}),

    'list-cnc': ([0, 1], {
        'ip': lambda v: True,
        'bot_id': lambda v: True}),

    'list-cnc-stat': ([0, 1], {
        'ip': lambda v: True,
        'bot_id': lambda v: True}),

    'schedinfo': ([0, 0], {}),

    'set-sched': ([1, 5], {\
        'mode': lambda v: v in ['auto', 'manual'],
        'sandbox_vcpu_quota': lambda v: v.isdigit() and int(v) > 0 and int(v) <= 100,
        'max_sandbox_num': lambda v: v.isdigit(),
        'max_dormant_duration': lambda v: v.isdigit(),
        'cnc_probing_duration': lambda v: v.isdigit()})
}

def parse_cmd(command):
    cmd_split = command.split(' ')
    cmd = cmd_split[0]
    params = {}

    if len(cmd_split) > 1:
        for p in cmd_split[1:]:
            if p.find('--') == 0 and p.find('=') != -1:
                kv = p.split('=')
                k = kv[0][2:]
                params[k] = kv[1]
            else:
                params['_'] = p

    return cmd, params

def check_args(cmd, params):
    if cmd not in cmd_config:
        print('command not supported')
        return False

    argc = len(params)
    if argc < cmd_config[cmd][0][0] or argc > cmd_config[cmd][0][1]:
        print('command parameter error')
        return False

    for k, v in params.items():
        if k not in cmd_config[cmd][1]:
            print('command parameter key error')
            return False
        if not cmd_config[cmd][1][k](v):
            print('command parameter value error')
            return False

    return True


def show_help(args):
    if len(args) == 0:
        print(help_outline)
    else:
        print(cmd_help[args['_']])


async def start_cli():
    reader, writer = await asyncio.open_connection('127.0.0.1', 8888)
    print(welcome_ui)
    try:
        while True:
            command = input("bot-tracker # ")
            cmd, params = parse_cmd(command)
            if cmd == 'quit':
                break
            print(f'{cmd} : {params}')
            if check_args(cmd, params) == False:
                continue

            if cmd == 'help':
                show_help(params)
                continue

            writer.write(command.encode())
            data = await reader.read(8192)
            if not data:
                break
            resp = data.decode()
            print(resp)
    finally:
        writer.close()
        await writer.wait_closed()


if __name__ == "__main__":
    try:
        asyncio.run(start_cli(), debug=False)
    except KeyboardInterrupt:
        print('Interrupted by user')
