import asyncio
import os
from analyzer_executor import *
import configparser
import csv
import shutil
from packet_capture import AsyncFileCapture
from db_store import *
from pathlib import Path


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
                   "Press any other key to go back"

data_analysis_ui_1 = "\nPlease choose:\n" + \
                     "    1. Detect CnC servers\n" + \
                     "    2. Detect CnC and attack stats\n" + \
                     "Press any other key to go back"

def list_directories(directory):
    path = Path(directory)
    directories = [p.name for p in path.iterdir() \
                   if p.is_dir() and p.name != 'DUP' and \
                        p.name != 'ERROR' and p.name != 'UNSTAGED']
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


async def get_cnc_info(bot_dir):
    bid_prefix = get_bot_id_prefix(bot_dir)
    cncs = await g_db_store.load_cnc_info(bid_prefix)
    if len(cncs) == 0:
        print('Cannot find CnC info for this bot')
        return None, None
    bot_id = cncs[0].bot_id
    cnc_ip_ports = [(c.ip, str(c.port)) for c in cncs]
    return bot_id, cnc_ip_ports


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


def get_report_dir(bot, measurement):
    return REPORT_DIR + os.sep + bot + os.sep + measurement


def create_report_dir(bot, measurement):
    b_dir = REPORT_DIR + os.sep + bot
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


async def run_cnc_analyzer(base, bot, measurement, packet_cnt):
    pcap = get_data_dir(base, bot, measurement) + os.sep + 'capture.pcap'
    print('\nStart detecting C2 servers...')
    print(f'pcap file: {pcap}')
    print(f'packet_cnt: {packet_cnt}...')
    own_ip = await get_sandbox_ip(pcap)
    if own_ip is None:
        print('Sandbox ip not found, aborted!')
        return
    excluded_ips = g_tool_config['data_analysis']['excluded_ips'].split(',')
    max_cnc_candidates = \
        int(g_tool_config['data_analysis']['max_cnc_candidates'])

    print(f'sandbox_ip: {own_ip}')
    print(f'max_cnc_candidates: {max_cnc_candidates}')

    executor_pool = AnalyzerExecutorPool(1)
    eid = executor_pool.open_executor()
    aid = await executor_pool.init_analyzer(eid, AnalyzerType.ANALYZER_CNC,
                                            own_ip=own_ip,
                                            excluded_ips=excluded_ips,
                                            excluded_ports=None,
                                            max_cnc_candidates=max_cnc_candidates)
    cap = AsyncFileCapture(pcap)
    cnt = 0
    try:
        async for packet in cap.sniff_continuously(packet_cnt):
            await executor_pool.analyze_packet(eid, aid, packet)
            cnt += 1
            if cnt % 10000 == 0:
                print(f'{cnt} packets analyzed...')
    finally:
        pass

    result = await executor_pool.get_result(eid, aid)
    print(f'Finished detecting CnC servers:\n{result}')
    await cap.close_async()
    await executor_pool.finalize_analyzer(eid, aid)
    executor_pool.close_executor(eid)
    executor_pool.destroy()


async def run_attack_analyzer(base, bot, measurement, packet_cnt):
    pcap = get_data_dir(base, bot, measurement) + os.sep + 'capture.pcap'
    print('\nStart analyzing attack and CnC stats...')
    display_filter = g_tool_config['data_analysis']['display_filter']
    print(f'pcap file: {pcap}\ndisplay_filter: {display_filter}')
    print(f'packet_cnt: {packet_cnt}...')
    own_ip = await get_sandbox_ip(pcap)
    if own_ip is None:
        print('Sandbox ip not found, aborted!')
        return
    excluded_ips = g_tool_config['data_analysis']['excluded_ips'].split(',')
    attack_gap = int(g_tool_config['data_analysis']['attack_gap'])
    min_attack_packets = int(g_tool_config['data_analysis']['min_attack_packets'])
    attack_detection_watermark = \
        int(g_tool_config['data_analysis']['attack_detection_watermark'])
    bot_id, cnc_ip_ports = await get_cnc_info(bot)
    if cnc_ip_ports is None:
        print('CnC not exists for this bot!')
        return

    print(f'sandbox_ip: {own_ip}')
    print(f'CnC info: {cnc_ip_ports}\nattack_gap:{attack_gap}')
    print(f'min_attack_packets: {min_attack_packets}')
    print(f'attack_detection_watermark: {attack_detection_watermark}')

    cnc_status = []
    cnc_stats = []
    attack_reports = []
    executor_pool = AnalyzerExecutorPool(1)
    eid = executor_pool.open_executor()
    aid = await executor_pool.init_analyzer(eid, AnalyzerType.ANALYZER_ATTACK,
                                            cnc_ip_ports=cnc_ip_ports,
                                            own_ip=own_ip,
                                            excluded_ips=excluded_ips,
                                            enable_attack_detection=True,
                                            attack_gap=attack_gap,
                                            min_attack_packets=min_attack_packets,
                                            attack_detection_watermark=\
                                            attack_detection_watermark)
    cap = AsyncFileCapture(pcap, display_filter=display_filter)

    def get_report_result(report):
        nonlocal cnc_status, cnc_stats, attack_reports, bot_id
        if report['cnc_status']['cnc_ready']:
            cnc_status.append(report['cnc_status'])
        cnc_stats.extend(report['cnc_stats'])
        for ar in report['attacks']:
            ar['bot_id'] = bot_id
            ar['cnc_ip'] = report['cnc_status']['cnc_ip']
            ar['cnc_port'] = int(report['cnc_status']['cnc_port'])
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
        r = await executor_pool.get_result(eid, aid, True)
        get_report_result(r)

    print('Finished analyzing CnC and attack stats')

    await executor_pool.finalize_analyzer(eid, aid)
    executor_pool.close_executor(eid)
    executor_pool.destroy()
    await cap.close_async()

    # report stored in report_dir/bot/xxx_measurement-start-time.csv
    create_report_dir(bot, measurement)
    report_dir = get_report_dir(bot, measurement)
    f_cnc_status = report_dir + os.sep + 'cnc-status.csv'
    f_cnc_stats = report_dir + os.sep + 'cnc-stats.csv'
    f_attacks = report_dir + os.sep + 'attacks.csv'
    write_to_csv(f_cnc_status, cnc_status)
    write_to_csv(f_cnc_stats, cnc_stats)
    write_to_csv(f_attacks, attack_reports)

    print(f'Analyzing results have been written to files under:\n{report_dir}')


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
        while True:
            print(f'{choose_data_dir_ui}')
            d = input('\ndata-tool # ')
            if d == '1':
                curr_data_dir = DATA_DIR
            elif d == '2':
                curr_data_dir = DUP_DIR
            elif d == '3':
                curr_data_dir = ERROR_DIR
            elif d == '4':
                curr_data_dir = UNSTAGED_DIR
            else:
                break
            read_all_data_dir(curr_data_dir)

            print(f'Chosen data dir: {curr_data_dir}')

            while True:
                print(f'{data_analysis_ui}')
                op = input('\ndata-tool # ')
                bots = []
                if op == '1':
                    bots = input_bots_menu()
                elif op == '2':
                    bots = input_measurement_menu()
                else:
                    break

                while True:
                    if len(bots) > 0:
                        print(f'{data_analysis_ui_1}')
                        choice = input('\ndata-tool # ')

                        if choice not in ['1','2']:
                            break

                        print('\nInput packet number to analyze, 0 means all:')
                        packet_cnt = int(input('\ndata-tool # '))
                        run_analyzer = None
                        if choice == '1':
                            run_analyzer = run_cnc_analyzer
                        else:
                            run_analyzer = run_attack_analyzer

                        total_b = len(bots)
                        curr_b = 1
                        for b, ms in bots:
                            total_m = len(ms)
                            curr_m = 1
                            for m in ms:
                                print(f'\nAnalyzing {b}: {m}')
                                print(f'Progress: bot -> {curr_b}/{total_b}, measurement -> {curr_m}/{total_m}...')
                                await run_analyzer(curr_data_dir, b, m, packet_cnt)
                                curr_m += 1
                            curr_b += 1
                    else:
                        print('No bots data to analyze!')
                        break
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
