import asyncio
import os
from analyzer_executor import *
import configparser
import csv
import shutil
from packet_capture import AsyncFileCapture
from db_store import *
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict


CUR_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = CUR_DIR + os.sep + 'log'
DUP_DIR = DATA_DIR + os.sep + 'DUP'
ERROR_DIR = DATA_DIR + os.sep + 'ERROR'
UNSTAGED_DIR = DATA_DIR + os.sep + 'UNSTAGED'

REPORT_DIR = CUR_DIR + os.sep + 'report'

g_data_dir = []
g_tool_config = None
g_db_store = None

welcome_ui = "\nWelcome to bot-tracker data tool!"
main_ui = "\nPlease choose:\n" + \
          "    1. Analyze data\n" + \
          "    2. Enrich data\n" + \
          "    3. Triage data\n" + \
          "    4. Backup data\n" + \
          "Press 'q' to quit"

choose_data_dir_ui = "\nPlease choose data dir:\n" + \
                     "    1. Working Data\n" + \
                     "    2. DUP\n" + \
                     "    3. ERROR\n" + \
                     "    4. UNSTAGED\n" + \
                     "Press any other key to go back"

data_analysis_ui = "\nPlease choose:\n" + \
                   "    1. Analyze for bots\n" + \
                   "    2. Analyze for measurements of a bot\n" + \
                   "    3. Collect generated reports from measurements\n" + \
                   "    4. Analyze reason for error bots\n" + \
                   "Press any other key to go back"


def list_directories(directory):
    path = Path(directory)
    directories = [p.name for p in path.iterdir() \
                   if p.is_dir() and p.name != 'DUP' and \
                        p.name != 'ERROR' and \
                        p.name != 'UNSTAGED' and \
                        p.name != 'V1']
    directories.sort()
    return directories


# data dir structure: log/bot/measurements
def read_all_data_dir(root):
    global g_data_dir
    g_data_dir.clear()
    bots = list_directories(root)
    for b in bots:
        entry = (b, [])
        g_data_dir.append(entry)
        b_dir = root + os.sep + b
        entry[1].extend(list_directories(b_dir))

    if len(g_data_dir) == 0:
        print('No data to analyze.')


def read_tool_config():
    global REPORT_DIR
    global g_tool_config
    g_tool_config = configparser.ConfigParser()
    ini_file = CUR_DIR + os.sep + 'config' + os.sep + 'tool.ini'
    if not os.path.exists(ini_file):
        l.error('tool config file not exist!')
        g_tool_config = None
        return
    g_tool_config.read(ini_file)
    REPORT_DIR = g_tool_config['report']['report_dir']


async def connect_db():
    global g_db_store
    g_db_store = DBStore(g_tool_config['database']['host'],
                         g_tool_config['database']['port'],
                         g_tool_config['database']['dbname'],
                         g_tool_config['database']['user'],
                         g_tool_config['database']['password'])
    await g_db_store.open()


# data should be stored in list of dict
def write_to_csv(csv_file, data):
    if len(data) == 0:
        #  print(f'No data written to {csv_file}')
        return

    with open(csv_file, 'w', newline='') as file:
        fieldnames = data[0].keys()
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)
        #  print(f'Data written to {csv_file}')


def get_bot_id_prefix(bot_dir):
    # e.g.2024_06_26_16_12_38_mirai_5f2ac36f
    last_ = bot_dir.rfind("_")
    return bot_dir[last_ + 1:]


async def get_bot_info(bot_dir):
    bid_prefix = get_bot_id_prefix(bot_dir)
    bots = await g_db_store.load_bot_info(None, bid_prefix, 1, None, True)
    if len(bots) == 0:
        print(f'Failed to get bot info for {bid_prefix}')
        return None
    return bots[0]


async def get_sandbox_ip(pcap):
    sandbox_ip = None

    # filter packets for downloading bot from malware repo
    display_filter = \
        f"ip.src=={g_tool_config['data_analysis']['subnet']} and " + \
        f"ip.dst=={g_tool_config['data_analysis']['malware_repo_ip']} and " + \
        f"tcp.dstport==22 and tcp.flags.syn==1"

    cap = AsyncFileCapture(pcap, display_filter)
    try:
        async for packet in cap.sniff_continuously(10000):
            sandbox_ip = packet.ip.src
            break
    finally:
        pass

    print(f'Get sandbox ip: {sandbox_ip}')
    await cap.close_async()
    return sandbox_ip


def get_report_dir(report_base, bot, measurement):
    return report_base + os.sep + bot + os.sep + measurement


def create_report_dir(report_base, bot, measurement):
    b_dir = report_base + os.sep + bot
    m_dir = b_dir + os.sep + measurement
    if not os.path.exists(b_dir):
        os.makedirs(b_dir)
    if not os.path.exists(m_dir):
        os.makedirs(m_dir)


def create_triage_dir(base, bot):
    b_dir = base + os.sep + bot
    if not os.path.exists(base):
        os.makedirs(base)
    if not os.path.exists(b_dir):
        os.makedirs(b_dir)


def move_to_triage_dir(base, bot, measurement):
    create_triage_dir(base, bot)
    from_dir = DATA_DIR + os.sep + bot + os.sep + measurement
    to_dir = base + os.sep + bot
    if os.path.exists(to_dir + os.sep + measurement):
        print('already exists, may cover')
    shutil.move(from_dir, to_dir)


def get_data_dir(base, bot, measurement):
    return base + os.sep + bot + os.sep + measurement


async def run_packet_analyzer(base, report_base, bot, measurement, packet_cnt):
    pcap = get_data_dir(base, bot, measurement) + os.sep + 'capture.pcap'
    print('\nStart analyzing attack and CnC stats...')
    display_filter = g_tool_config['data_analysis']['display_filter']
    print(f'pcap file: {pcap}\ndisplay_filter: {display_filter}')
    print(f'packet_cnt: {packet_cnt}...')
    own_ip = await get_sandbox_ip(pcap)
    if own_ip is None:
        print('Sandbox ip not found, aborted!')
        return
    excluded_ips = g_tool_config['data_analysis']['excluded_ips']
    min_cnc_attempts = int(g_tool_config['data_analysis']['min_cnc_attempts'])
    attack_gap = int(g_tool_config['data_analysis']['attack_gap'])
    min_attack_packets = int(g_tool_config['data_analysis']['min_attack_packets'])
    attack_detection_watermark = \
        int(g_tool_config['data_analysis']['attack_detection_watermark'])
    bot_info = await get_bot_info(bot)
    bot_id = bot_info.bot_id

    print(f'bot_id: {bot_id}')
    print(f'sandbox_ip: {own_ip}')
    print(f'min_cnc_attempts: {min_cnc_attempts}')
    print(f'attack_gap:{attack_gap}')
    print(f'min_attack_packets: {min_attack_packets}')
    print(f'attack_detection_watermark: {attack_detection_watermark}')

    cnc_status = []
    cnc_stats = []
    attack_reports = []
    executor_pool = AnalyzerExecutorPool(1)
    eid = executor_pool.open_executor()
    aid = await executor_pool.init_analyzer(eid,
                                            own_ip=own_ip,
                                            excluded_ips=excluded_ips,
                                            min_cnc_attempts=min_cnc_attempts,
                                            attack_gap=attack_gap,
                                            min_attack_packets=min_attack_packets,
                                            attack_detection_watermark=attack_detection_watermark)
    cap = AsyncFileCapture(pcap, display_filter=display_filter)

    def get_report_result(report):
        nonlocal cnc_status, cnc_stats, attack_reports, bot_id
        if len(report['cnc_status']) > 0:
            cnc_status.append(report['cnc_status'])
        cnc_stats.extend(report['cnc_stats'])
        for ar in report['attacks']:
            ar['bot_id'] = bot_id
            attack_reports.append(ar)

    try:
        cnt = 0
        async for packet in cap.sniff_continuously(packet_cnt):
            ret = await executor_pool.analyze_packet(eid, aid, packet)
            if ret is True:
                r = await executor_pool.get_result(eid, aid)
                get_report_result(r)
            cnt += 1
            if cnt % 50000 == 0:
                print(f'{cnt} packets analyzed...')
        print(f'\nTotally {cnt} packets analyzed...')
    finally:
        r = await executor_pool.get_result(eid, aid, True, True)
        get_report_result(r)

    print('Finished analyzing CnC and attack stats')

    await executor_pool.finalize_analyzer(eid, aid)
    executor_pool.close_executor(eid)
    executor_pool.destroy()
    await cap.close_async()

    # report stored in report_dir/bot/xxx_measurement-start-time.csv
    create_report_dir(report_base, bot, measurement)
    report_dir = get_report_dir(report_base, bot, measurement)
    f_cnc_status = report_dir + os.sep + 'cnc-status.csv'
    f_cnc_stats = report_dir + os.sep + 'cnc-stats.csv'
    f_attacks = report_dir + os.sep + 'attacks.csv'
    write_to_csv(f_cnc_status, cnc_status)
    write_to_csv(f_cnc_stats, cnc_stats)
    write_to_csv(f_attacks, attack_reports)

    print(f'Analyzing results have been written to files under:\n{report_dir}')


def get_measure_time(m):
    tr = m.split('_')
    s = datetime.strptime(tr[0], '%Y-%m-%d-%H-%M-%S')
    e = datetime.strptime(tr[1], '%Y-%m-%d-%H-%M-%S')
    return s, e


async def get_attack_info(bid, s, e):
    str_s = datetime.strftime(s, '%Y%m%dT%H%M%S')
    str_e = datetime.strftime(e, '%Y%m%dT%H%M%S')
    attacks = await g_db_store.load_attack_info(bid, None, (str_s, str_e))
    return attacks


async def run_collect_data(base, report_base):
    print(f'\nStart collecting data from {base} and db...')

    for b, ms in g_data_dir:
        for m in ms:
            create_report_dir(report_base, b, m)
            report_dir = get_report_dir(report_base, b, m)
            data_dir = get_data_dir(base, b, m)
            try:
                shutil.copy(data_dir + os.sep + 'cnc-status.csv', report_dir + os.sep + 'cnc-status.csv')
                shutil.copy(data_dir + os.sep + 'cnc-stats.csv', report_dir + os.sep + 'cnc-stats.csv')
            except FileNotFoundError:
                pass
            bid = get_bot_id_prefix(b)
            s, e = get_measure_time(m)
            attacks = await get_attack_info(bid, s, e)
            attack_list = []
            for a in attacks:
                attack_list.append(asdict(a))
            f_attacks = report_dir + os.sep + 'attacks.csv'
            if len(attack_list) > 0:
                write_to_csv(f_attacks, attack_list)

    print(f'\nData has been collected to: {report_base}')


def search_string_in_file(filename, key_words):
    result = []
    with open(filename, 'r') as file:
        for line in file:
            for k in key_words:
                if k in line:
                    result.append({'key': k, 'detail': line})

    return result


async def run_error_analysis(base, report_base):
    print(f'\nStart analyzing reason for error bots from {base}...')

    key_words = ['SIGSEGV', 'SIGPIPE', 'SIGABRT', 'SIGBUS', 'SIGILL', 'SIGKILL',
                 'SIGSYS', 'ETIMEDOUT', 'ENOENT', 'exit']

    for b, ms in g_data_dir:
        for m in ms:
            result = []
            create_report_dir(report_base, b, m)
            report_dir = get_report_dir(report_base, b, m)
            data_dir = get_data_dir(base, b, m)
            try:
                bot_info = await get_bot_info(b)
                bid = bot_info.bot_id
                f_syscall = data_dir + os.sep + 'syscall' + os.sep + bid + '.elf.log'
                result = search_string_in_file(f_syscall, key_words)
                for r in result:
                    r['bot_id'] = bid
            except FileNotFoundError:
                print(f'{b}:{m} syscall file not found!')
                continue

            f_error = report_dir + os.sep + 'error.csv'
            if len(result) > 0:
                write_to_csv(f_error, result)
            else:
                print(f'key words not found in {f_syscall}!')

    print(f'\nError analysis result has been written to: {report_base}')


def input_bots_menu():
    print('\nChoose bots range (e.g: 1,5):')
    i = 1
    for b in g_data_dir:
        print(f'    {i}. {b[0]}')
        i += 1
    r = input('\ndata-tool # ').split(',')
    s = int(r[0])
    e = int(r[1])
    s = s if s >= 1 else 1
    e = e if e <= len(g_data_dir) else len(g_data_dir)
    return g_data_dir[s - 1 : e]


def input_measurement_menu():
    print('\nChoose bot:')
    i = 1
    for b in g_data_dir:
        print(f'    {i}. {b[0]}')
        i += 1
    b_idx = int(input('\ndata-tool # ')) - 1

    print('\nChoose measurements range (e.g: 1,5):')
    i = 1
    bot = g_data_dir[b_idx]
    for m in bot[1]:
        print(f'    {i}. {m}')
        i += 1
    r = input('\ndata-tool # ').split(',')
    s = int(r[0])
    e = int(r[1])
    s = s if s >= 1 else 1
    e = e if e <= len(bot[1]) else len(bot[1])

    return [(bot[0], bot[1][s - 1 : e])]


async def async_data_triage():
    read_all_data_dir(DATA_DIR)
    await connect_db()
    try:
        for b in g_data_dir:
            base = ''
            bi = await get_bot_info(b[0])
            if bi is None:
                print(f'{b[0]} not exist in db, please check!')
                #  shutil.rmtree(DATA_DIR + os.sep + b[0])
                continue
            if bi.status == BotStatus.ERROR.value:
                base = ERROR_DIR
            elif bi.status == BotStatus.DUPLICATE.value:
                base = DUP_DIR
            elif bi.status == BotStatus.UNSTAGED.value:
                base = UNSTAGED_DIR
            else:
                continue
            for m in b[1]:
                move_to_triage_dir(base, b[0], m)
            #  print(f'remove {DATA_DIR + os.sep + b[0]}')
            os.rmdir(DATA_DIR + os.sep + b[0])
        print('Triage data done!')
    finally:
        await g_db_store.close()


async def async_data_analysis():
    print(f'Attention: old reports will be overwritten, input "yes" to continue:')
    ch = input('\ndata-tool # ')
    if ch != 'yes':
        return

    await connect_db()
    try:
        curr_data_dir = ''
        curr_report_dir = ''
        while True:
            print(f'{choose_data_dir_ui}')
            d = input('\ndata-tool # ')
            if d == '1':
                curr_data_dir = DATA_DIR
                curr_report_dir = REPORT_DIR
            elif d == '2':
                curr_data_dir = DUP_DIR
                curr_report_dir = REPORT_DIR + os.sep + 'DUP'
            elif d == '3':
                curr_data_dir = ERROR_DIR
                curr_report_dir = REPORT_DIR + os.sep + 'ERROR'
            elif d == '4':
                curr_data_dir = UNSTAGED_DIR
                curr_report_dir = REPORT_DIR + os.sep + 'UNSTAGED'
            else:
                break
            read_all_data_dir(curr_data_dir)

            print(f'Chosen data dir: {curr_data_dir}, report dir: {curr_report_dir}')

            while True:
                print(f'{data_analysis_ui}')
                op = input('\ndata-tool # ')
                bots = []
                if op == '1':
                    bots = input_bots_menu()
                elif op == '2':
                    bots = input_measurement_menu()
                elif op == '3':
                    await run_collect_data(curr_data_dir, curr_report_dir)
                    continue
                elif op == '4':
                    await run_error_analysis(curr_data_dir, curr_report_dir)
                    continue
                else:
                    break

                if len(bots) > 0:
                    print('\nInput packet number to analyze, 0 means all:')
                    packet_cnt = int(input('\ndata-tool # '))
                    total_b = len(bots)
                    curr_b = 1
                    for b, ms in bots:
                        total_m = len(ms)
                        curr_m = 1
                        for m in ms:
                            print(f'\nAnalyzing {b}: {m}')
                            print(f'\n{datetime.now()}: Progress: bot -> {curr_b}/{total_b}, measurement -> {curr_m}/{total_m}...')
                            await run_packet_analyzer(curr_data_dir,
                                                      curr_report_dir,
                                                      b, m, packet_cnt)
                            curr_m += 1
                        curr_b += 1
                else:
                    print('No bots data to analyze!')
    finally:
        await g_db_store.close()


if __name__ == "__main__":
    try:
        read_tool_config()
        if g_tool_config is None:
            exit(0)
        print(f'{welcome_ui}')
        while True:
            print(f'{main_ui}')
            op = input('\ndata-tool # ')
            if op == '1':
                asyncio.run(async_data_analysis(), debug=True)
            elif op == '2':
                pass
            elif op == '3':
                asyncio.run(async_data_triage(), debug=True)
            elif op == '4':
                pass
            elif op == 'q':
                print('Have a good day! Bye!')
                exit(0)
            else:
                print('Error input!')
    except KeyboardInterrupt:
        print('Have a good day! Bye!')
