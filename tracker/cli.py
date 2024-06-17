import asyncio
from datetime import datetime

welcome_ui = "Welcome to bot-tracker command line.\n\n" + \
             "Type:  'help' for help with commands\n" + \
             "       'quit' to exit"
help_outline = "Bot management commands:\n" + \
               "    list-bot                   list bot information.\n" + \
               "    start-bot                  start running bot.\n" + \
               "    stop-bot                   stop running bot.\n\n" + \
               "CnC information query:\n" + \
               "    list-cnc                   list cnc information.\n\n" + \
               "Attack information query:\n" + \
               "    list-attack                list attack information.\n\n" + \
               "Bot scheduler setting commands:\n" + \
               "    schedinfo                  show bot scheduler information.\n" + \
               "    set-sched                  set scheduler parameters."

help_list_bot = "NAME\n" + \
                "  list-bot - list bot information.\n" + \
                "\nSYNOPSIS\n" + \
                "  list-bot [bot_id] [--all] [--status]\n" + \
                "\nDESCRIPTION\n" + \
                "  List bot information with specified bot_id or bot status.\n" + \
                "  If no option specified, list all 'staged','active' and 'dormant' bots.\n" + \
                "\nOPTIONS\n" + \
                "  [bot_id]: bot id\n" + \
                "  [--all]: list all bots\n" + \
                "  [--status]=<status>: bot status, could be one of 'unknown','staged','dormant',\n" + \
                "             'active','interrupted','unstaged','error', or 'duplicate'"

help_start_bot = "NAME\n" + \
                 "  start-bot - start running bot.\n" + \
                 "\nSYNOPSIS\n" + \
                 "  start-bot [bot_id] [--all] [--status]\n" + \
                 "\nDESCRIPTION\n" + \
                 "  Start running bot with specified bot_id or all bots or bots with specified status.\n" + \
                 "  Supported in manual scheduler mode." + \
                 "\nOPTIONS\n" + \
                 "  [--all]: start all bots which are not currently running and not in 'error',\n" + \
                 "           'duplicated' or 'unstaged' state\n" + \
                 "  [--status]=<status>: bot status, could be one of 'unknown','staged','dormant',\n" + \
                 "             'active','interrupted','unstaged','error', or 'duplicate'"

help_stop_bot = "NAME\n" + \
                "  stop-bot - stop running bot.\n" + \
                "\nSYNOPSIS\n" + \
                "  stop-bot [bot_id] [--all] [--status] [--unstage]\n" + \
                "\nDESCRIPTION\n" + \
                "  Stop running bot with specified bot_id or all bots or bots with specified status.\n" + \
                "  Supported in manual scheduler mode." + \
                "\nOPTIONS\n" + \
                "  [--all]: stop all bots which are currently running\n" + \
                "  [--status]=<status>: bot status, could be one of 'unknown','staged','dormant',\n" + \
                "             'active','interrupted','unstaged','error', or 'duplicate'\n" + \
                "  [--unstage]=<yes/no>: unstage the bot or not, unstaged bots will not be scheduled\n" + \
                "              in auto schduler mode."

help_list_cnc = "NAME\n" + \
                "  list-cnc - list CnC information.\n" + \
                "\nSYNOPSIS\n" + \
                "  list-cnc [--ip] [--bot_id]\n" + \
                "\nDESCRIPTION\n" + \
                "  List CnC information with specified bot_id or CnC IP.\n" + \
                "  If no option specified, list all CnC information.\n" + \
                "\nOPTIONS\n" + \
                "  [--bot_id]=<bot_id>: bot id\n" + \
                "  [--ip]=<ip>: CnC IP."

help_list_attack = "NAME\n" + \
                     "  list-attack - list attacks.\n" + \
                     "\nSYNOPSIS\n" + \
                     "  list-attack [--cnc_ip] [--bot_id] [--time]\n" + \
                     "\nDESCRIPTION\n" + \
                     "  List attack information with specified bot_id or CnC IP or time range.\n" + \
                     "  If no option specified, list all attacks information.\n" + \
                     "\nOPTIONS\n" + \
                     "  [--bot_id]=<bot_id>: bot id\n" + \
                     "  [--cnc_ip]=<ip>: CnC IP\n" + \
                     "  [--time]=<start,end>: list attack from start time to end time\n" + \
                     "           time format YYYY:MM:DD HH:MI:SS."

help_schedinfo = "NAME\n" + \
                 "  schedinfo - show bot scheduler information.\n" + \
                 "\nSYNOPSIS\n" + \
                 "  schedinfo\n" + \
                 "\nDESCRIPTION\n" + \
                 "  Show bot scheduler information.\n"

help_set_sched = "NAME\n" + \
                 "  set-sched - set bot scheduler parameters.\n" + \
                 "\nSYNOPSIS\n" + \
                 "  set-sched [--mode] [--sandbox_vcpu_quota] [--max_sandbox_num]\n" + \
                 "            [--max_dormant_duration] [--cnc_probing_duration]\n" + \
                 "\nDESCRIPTION\n" + \
                 "  Set bot scheduler parameters, changes will apply immediately.\n" + \
                 "  Multiple parameters can be set at the same time.\n" + \
                 "\nOPTIONS\n" + \
                 "  [--mode]=<mode>: bot scheduler mode, could be 'auto' or 'manual'\n" + \
                 "  [--sandbox_vcpu_quota]=<quota>: sandbox vcpu quota in percentage of a physical cpu core.\n" + \
                 "  [--max_sandbox_num]=<num>: max number of sandboxes the scheduler can run.\n" + \
                 "  [--max_dormant_duration]=<duration>: max dormant hours allowed before a bot is unstaged.\n" + \
                 "  [--cnc_probing_duration]=<duration>: time in second for probing CnC server.\n"

cmd_help = {'list-bot': help_list_bot,
            'start-bot': help_start_bot,
            'stop-bot': help_stop_bot,
            'list-cnc': help_list_cnc,
            'list-attack': help_list_attack,
            'schedinfo': help_schedinfo,
            'set-sched': help_set_sched}

bot_status_list = ['unknown',
                   'staged',
                   'dormant',
                   'active',
                   'interrupted',
                   'unstaged',
                   'error',
                   'duplicate']

def get_datetime_range_from_str(t_str):
    try:
        if t_str == '' or t_str is None:
            return ()
        t_range = t_str.split(',')
        if len(t_range) != 2:
            return ()

        s = datetime.strptime(t_range[0], '%Y-%m-%d %H:%M:%S')
        e = datetime.strptime(t_range[1], '%Y-%m-%d %H:%M:%S')
        if s > e:
            return ()
        return s, e
    except ValueError:
        return ()

cmd_config = {
    'help': ([0, 1], {
        '_': lambda v: v in ['list-bot',
                             'start-bot',
                             'stop-bot',
                             'list-cnc',
                             'list-attack',
                             'schedinfo',
                             'set-sched']}),

    'list-bot': ([0, 1], {
        '_': lambda v: True,
        'all': lambda v: True,
        'status': lambda v: v in bot_status_list}),

    'start-bot': ([1, 1], {
        '_': lambda v: True,
        'all': lambda v: True,
        'status': lambda v: v in bot_status_list}),

    'stop-bot': ([1, 2], {
        '_': lambda v: True,
        'all': lambda v: True,
        'unstage': lambda v: v in ['yes', 'no'],
        'status': lambda v: v in bot_status_list}),

    'list-cnc': ([0, 1], {
        'ip': lambda v: True,
        'bot_id': lambda v: True}),

    'list-attack': ([0, 1], {
        'time': lambda v: len(get_datetime_range_from_str(v)) == 2,
        'cnc_ip': lambda v: True,
        'bot_id': lambda v: True}),

    'schedinfo': ([0, 0], {}),

    'set-sched': ([1, 5], {
        'mode': lambda v: v in ['auto', 'manual'],
        'sandbox_vcpu_quota': lambda v: v.isdigit() and 0 < int(v) <= 100,
        'max_sandbox_num': lambda v: v.isdigit(),
        'max_dormant_duration': lambda v: v.isdigit(),
        'cnc_probing_duration': lambda v: v.isdigit()})
}

cmd_buffer_len = 1024 * 1024 * 4
def parse_cmd(command):
    cmd_split = command.split(' ')
    cmd = cmd_split[0]
    params = {}

    if len(cmd_split) > 1:
        for p in cmd_split[1:]:
            if p.find('--') == 0:
                if p.find('=') != -1:
                    kv = p.split('=')
                    k = kv[0][2:]
                    params[k] = kv[1]
                else:
                    params[p[2:]] = ''
            else:
                params['_'] = p

    return cmd, params


def check_args(cmd, params):
    if cmd not in cmd_config:
        print('Command not supported')
        return False

    argc = len(params)
    if argc < cmd_config[cmd][0][0] or argc > cmd_config[cmd][0][1]:
        print('Command parameter error')
        return False

    for k, v in params.items():
        if k not in cmd_config[cmd][1]:
            print('Command parameter key error')
            return False
        if not cmd_config[cmd][1][k](v):
            print('Command parameter value error')
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
            command = input("\nbot-tracker # ")
            cmd, params = parse_cmd(command)
            if cmd == 'quit':
                break
            #  print(f'{cmd} : {params}')
            if not check_args(cmd, params):
                continue

            if cmd == 'help':
                show_help(params)
                continue

            writer.write(command.encode())
            data = await reader.read(cmd_buffer_len)
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
