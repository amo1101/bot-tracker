import asyncio
import os
from analyzer_executor import *
import configparser
import csv
import shutil
from packet_capture import AsyncFileCapture
import pandas as pd
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict
import requests
import json

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = CUR_DIR + os.sep + 'log'
DUP_DIR = DATA_DIR + os.sep + 'DUP'
ERROR_DIR = DATA_DIR + os.sep + 'ERROR'
UNSTAGED_DIR = DATA_DIR + os.sep + 'UNSTAGED'
DB_DIR = DATA_DIR + os.sep + 'DB'

REPORT_DIR = CUR_DIR + os.sep + 'report'

g_data_dir = []
g_tool_config = None
g_db_bot_info = None
g_db_cnc_info = None
g_db_attack_info = None
g_db_cnc_status_info = None

welcome_ui = "\nWelcome to bot-tracker data tool!"
main_ui = "\nPlease choose:\n" + \
          "    1. Analyze data\n" + \
          "    2. Enrich data\n" + \
          "    3. Triage data\n" + \
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

data_enrichment_ui = "\nPlease choose:\n" + \
                   "    1. Enrich C2\n" + \
                   "    2. Enrich atack info\n" + \
                   "    3. Rebuild C2 status\n" + \
                   "Press any other key to go back"


def list_directories(directory):
    path = Path(directory)
    directories = [p.name for p in path.iterdir() \
                   if p.is_dir() and p.name != 'DUP' and \
                        p.name != 'ERROR' and \
                        p.name != 'UNSTAGED' and \
                        p.name != 'DB']
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
    global REPORT_DIR, DATA_DIR, DUP_DIR, ERROR_DIR, UNSTAGED_DIR, DB_DIR
    global g_tool_config
    g_tool_config = configparser.ConfigParser()
    ini_file = CUR_DIR + os.sep + 'config' + os.sep + 'tool.ini'
    if not os.path.exists(ini_file):
        l.error('tool config file not exist!')
        g_tool_config = None
        return
    g_tool_config.read(ini_file)
    DATA_DIR = g_tool_config['dir']['data_base']
    DUP_DIR = DATA_DIR + os.sep + 'DUP'
    ERROR_DIR = DATA_DIR + os.sep + 'ERROR'
    UNSTAGED_DIR = DATA_DIR + os.sep + 'UNSTAGED'
    DB_DIR = DATA_DIR + os.sep + 'DB'
    REPORT_DIR = g_tool_config['dir']['report_base']


def load_db_from_csv():
    global g_db_bot_info, g_db_cnc_info, g_db_attack_info, g_db_cnc_status_info
    g_db_bot_info = pd.read_csv(DB_DIR + os.sep + 'bot_info.csv') if \
        g_db_bot_info is None else g_db_bot_info
    g_db_cnc_info = pd.read_csv(DB_DIR + os.sep + 'cnc_info.csv') if \
        g_db_cnc_info is None else  g_db_cnc_info
    if g_db_attack_info is None:
        g_db_attack_info = pd.read_csv(DB_DIR + os.sep + 'attack_info.csv')
        g_db_attack_info['time'] = pd.to_datetime(g_db_attack_info['time']).dt.tz_localize(None)
        g_db_attack_info['duration'] =  pd.to_timedelta(g_db_attack_info['duration'])
    if g_db_cnc_status_info is None:  # this is optional
        stats_db_f = DB_DIR + os.sep + 'cnc_stats_db.csv'
        if os.path.isfile(stats_db_f):
            g_db_cnc_status_info = pd.read_csv(stats_db_f)
            g_db_cnc_status_info['time'] = pd.to_datetime(g_db_cnc_status_info['measure_start']).dt.tz_localize(None)


# data should be stored in list of dict
def write_to_csv(csv_file, data):
    if len(data) == 0:
        #  print(f'No data written to {csv_file}')
        return
    df = pd.DataFrame(data)
    df.to_csv(csv_file, index=False, escapechar='\\')

def get_bot_id_prefix(bot_dir):
    # e.g.2024_06_26_16_12_38_mirai_5f2ac36f
    last_ = bot_dir.rfind("_")
    return bot_dir[last_ + 1:]


def get_bot_info(bot_dir):
    bid_prefix = get_bot_id_prefix(bot_dir)
    #  bots = g_db_bot_info[g_db_bot_info['bot_id'] == bid_prefix].to_dict(orient='records')
    bots = g_db_bot_info[g_db_bot_info['bot_id'].str.startswith(bid_prefix)].to_dict(orient='records')
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
    display_filter = None
    if g_tool_config.has_option('data_analysis', 'display_filter'):
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
    bot_info = get_bot_info(bot)
    bot_id = bot_info['bot_id']

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


def get_attack_info(bid, s, e):
    df = g_db_attack_info
    attacks = df[(df['bot_id'].str.startswith(bid)) & (df['time'] > s) & (df['time'] < e)]
    return attacks.to_dict(orient='records')


def run_collect_data(base, report_base):
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
            attacks = get_attack_info(bid, s, e)
            f_attacks = report_dir + os.sep + 'attacks.csv'
            if len(attacks) > 0:
                write_to_csv(f_attacks, attacks)

    print(f'\nData has been collected to: {report_base}')


def search_string_in_file(filename, key_words):
    result = []
    with open(filename, 'r') as file:
        for line in file:
            for k in key_words:
                if k in line:
                    result.append({'key': k, 'detail': line})

    return result


def run_error_analysis(base, report_base):
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
                bot_info = get_bot_info(b)
                bid = bot_info['bot_id']
                f_syscall = data_dir + os.sep + 'syscall' + os.sep + bid + '.elf.log'
                result = search_string_in_file(f_syscall, key_words)
                for r in result:
                    r['bot_id'] = bid
            except FileNotFoundError:
                r['bot_id'] = bid
                r['key'] = 'NotActivated'
                r['detail'] = 'syscall file not found'
                result.append(r)
                print(f'{b}:{m} syscall file not found!')

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


def sync_data_triage():
    read_all_data_dir(DATA_DIR)
    load_db_from_csv()
    try:
        for b in g_data_dir:
            base = ''
            bi = get_bot_info(b[0])
            if bi is None:
                print(f'{b[0]} not exist in db, please check!')
                #  shutil.rmtree(DATA_DIR + os.sep + b[0])
                continue
            if bi['status'] == BotStatus.ERROR.value:
                base = ERROR_DIR
            elif bi['status'] == BotStatus.DUPLICATE.value:
                base = DUP_DIR
            elif bi['status'] == BotStatus.UNSTAGED.value:
                base = UNSTAGED_DIR
            else:
                continue
            for m in b[1]:
                move_to_triage_dir(base, b[0], m)
            #  print(f'remove {DATA_DIR + os.sep + b[0]}')
            os.rmdir(DATA_DIR + os.sep + b[0])
        print('Triage data done!')
    finally:
        pass


async def async_data_analysis():
    print(f'Attention: old reports will be overwritten, input "yes" to continue:')
    ch = input('\ndata-tool # ')
    if ch != 'yes':
        return

    load_db_from_csv()
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
                    run_collect_data(curr_data_dir, curr_report_dir)
                    continue
                elif op == '4':
                    run_error_analysis(curr_data_dir, curr_report_dir)
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
                            rd = get_report_dir(curr_report_dir, b, m)
                            if os.path.isdir(rd):
                                print('skip already analyzed measurement.')
                                curr_m += 1
                                continue
                            await run_packet_analyzer(curr_data_dir,
                                                      curr_report_dir,
                                                      b, m, packet_cnt)
                            curr_m += 1
                        curr_b += 1
                else:
                    print('No bots data to analyze!')
    finally:
        pass


def get_ip_info(ip):
    try:
        if ip == '':
            return {}
        access_key = '126e7f8cef039e'
        response = requests.get(f'http://ipinfo.io/{ip}?token={access_key}')
        return response.json()
    except Exception as e:
        print(f'an error occured {e}')
        return {}

def enrich_cnc_info():
    edf_file = DB_DIR + os.sep + 'cnc_info_enriched.csv'
    lst = []
    cnt = 1
    total = len(g_db_cnc_info)
    for row in g_db_cnc_info.itertuples():
        print(f'enrich c2 {cnt}/{total}...')
        ipinfo = get_ip_info(row.ip)
        erow = [
            row.ip,
            row.port,
            row.bot_id,
            row.domain,
            ipinfo.get('hostname'),
            ipinfo.get('city'),
            ipinfo.get('region'),
            ipinfo.get('country'),
            ipinfo.get('loc'),
            ipinfo.get('org'),
            ipinfo.get('postal'),
            ipinfo.get('timezone')
        ]
        lst.append(erow)
        cnt += 1

    edf = pd.DataFrame(lst, columns=['ip','port','bot_id','domain',
                                'hostname','city','region','country',
                                'loc','org','postal','timezone'])
    edf.to_csv(edf_file, index=False)


def find_pcap_file(bot_id, t):
    for b, ms in g_data_dir:
        if b.rfind(bot_id[:8]) != -1:
            for m in ms:
                s, e = get_measure_time(m)
                if t >= s and t <= e:
                    return get_data_dir(UNSTAGED_DIR,b,m) + os.sep + 'capture.pcap'
    return None


async def enrich_attack_report(raw):
    added = {}
    pcap = find_pcap_file(raw.bot_id, raw.time)
    if pcap is None:
        print(f'bot measurement folder for {raw.bot_id} at {raw.time} not found.')

    attack_type = raw.attack_type
    if attack_type != 'DP Attack' or pcap is None:
        added['layers'] = ''
        added['dst_port'] = raw.dst_port
        added['packet_cnt_check'] = -1
        return added

    time_e = raw.time + raw.duration
    display_filter = f"ip.dst=={raw.target} and " + \
                     "!tcp.analysis.retransmission and !tcp.analysis.fast_retransmission and " + \
                     f"frame.time >= \"{raw.time}\" and frame.time <= \"{time_e}\""
    cap = AsyncFileCapture(pcap, display_filter=display_filter)
    layers = set()
    dst_port = set()
    proxied = set()
    cnt = 0
    print(f'analyzing {pcap}, filter:{display_filter}...')
    try:
        async for packet in cap.sniff_continuously(0):
            pkt_summary = PacketSummary()
            pkt_summary.extract(packet)
            if len(layers) < 50:
                layers.update(pkt_summary.layer_names)
            if len(dst_port) < 50 and pkt_summary.dstport is not None:
                dst_port.add(pkt_summary.dstport)
            cnt += 1
            if cnt % 10000 == 0:
                print(f'{cnt} packets analyzed...')
        print(f'\nTotally {cnt} packets analyzed...')
    finally:
        pass

    await cap.close_async()

    added['dst_port'] = ','.join(dst_port)
    added['layers'] = ','.join(layers)
    added['packet_cnt_check'] = cnt
    return added

async def rebuild_cnc_status_report(raw):
    reports = []
    def add_report(status, update_time):
        nonlocal reports, raw
        reports.append([raw.bot_id, raw.ip, raw.port, raw.measure_start,
            raw.measure_end, status, update_time])

    pcap = find_pcap_file(raw.bot_id, raw.time)
    if pcap is None:
        print(f'bot measurement folder for {raw.bot_id} at {raw.time} not found.')
        return []

    display_filter = f"(ip.dst=={raw.ip} and tcp.dstport=={raw.port}) or " + \
                     f"(ip.src=={raw.ip} and tcp.srcport=={raw.port})"

    cap = AsyncFileCapture(pcap, display_filter=display_filter)

    print(f'analyzing {pcap}, filter:{display_filter}...')
    try:
        cnt = 0
        curr_status = 'unknown'
        async for packet in cap.sniff_continuously(0):
            pkt_summary = PacketSummary()
            pkt_summary.extract(packet)
            if pkt_summary.tcp_len > 0:
                if curr_status != 'alive':
                    curr_status = 'alive'
                    add_report('alive', pkt_summary.sniff_time)
            if pkt_summary.tcp_flags_fin == 'True':
                if curr_status != 'disconnected':
                    curr_status = 'disconnected'
                    add_report('disconnected', pkt_summary.sniff_time)

            cnt += 1
            if cnt % 10000 == 0:
                print(f'{cnt} packets analyzed...')
        print(f'\nTotally {cnt} packets analyzed...')
    finally:
        pass

    await cap.close_async()
    return reports


async def rebuild_cnc_status(s, e):
    edf_file = DB_DIR + os.sep + f'cnc_status_rebuilt_{s}_{e}.csv'
    start = s - 1
    if os.path.isfile(edf_file):
        df = pd.read_csv(edf_file)
        start += len(df)
    cnt = s
    c2_status = g_db_cnc_status_info.iloc[s-1:e]
    total = len(c2_status)
    for row in c2_status.itertuples():
        print(f'Rebuilding status {cnt}/{s - 1 + total}...')
        if cnt <= start:
            print('skip already rebuilt cnc status.')
            cnt += 1
            continue
        reports = await rebuild_cnc_status_report(row)
        if len(reports) == 0:
            cnt += 1
            continue

        edf = pd.DataFrame(reports, columns=['bot_id','ip','port','measure_start',
                                'measure_end','status','update_time'])

        if not os.path.isfile(edf_file):
            edf.to_csv(edf_file, mode='a', header=True, index=False)
        else:
            edf.to_csv(edf_file, mode='a', header=False, index=False)

        cnt += 1


async def enrich_attack_info(s, e):
    edf_file = DB_DIR + os.sep + f'attack_info_enriched_{s}_{e}.csv'
    start = s - 1
    if os.path.isfile(edf_file):
        df = pd.read_csv(edf_file)
        start += len(df)
    cnt = s
    attacks = g_db_attack_info.iloc[s-1:e]
    total = len(attacks)
    for row in attacks.itertuples():
        print(f'Enriching attack {cnt}/{s - 1 + total}...')
        if cnt <= start:
            print('skip already enriched attack report.')
            cnt += 1
            continue
        added = await enrich_attack_report(row)
        if row.attack_type == 'Scanning':
            target = ''
        else:
            target = row.target
            p = target.rfind('/24')
            if p != -1:
                target = target[:p]
        ipinfo = get_ip_info(target)
        erow = [
            row.bot_id,
            row.cnc_ip,
            row.cnc_port,
            row.attack_type,
            row.time,
            row.duration,
            row.target,
            row.protocol,
            added['layers'],
            row.src_port,
            added['dst_port'],
            row.spoofed,
            row.packet_num,
            row.total_bytes,
            row.pps,
            row.bandwidth,
            ipinfo.get('hostname',''),
            ipinfo.get('city',''),
            ipinfo.get('region',''),
            ipinfo.get('country',''),
            ipinfo.get('loc',''),
            ipinfo.get('org',''),
            ipinfo.get('postal',''),
            ipinfo.get('timezone',''),
            added['packet_cnt_check']
        ]

        edf = pd.DataFrame([erow], columns=['bot_id','cnc_ip','cnc_port','attack_type',
                                'time','duration','target','protocol','layers',
                                'src_port','dst_port','spoofed',
                                'packet_num','total_bytes','pps','bandwidth',
                                't_hostname','t_city','t_region','t_country',
                                't_loc','t_org','t_postal','t_timezone','packet_cnt_check'])

        if not os.path.isfile(edf_file):
            edf.to_csv(edf_file, mode='a', header=True, index=False)
        else:
            edf.to_csv(edf_file, mode='a', header=False, index=False)

        cnt += 1

async def async_data_enrichment():
    print(f'Attention: Data enrichment will use data under DB and UNSTAGED folder, data will be kept intact.')
    print(f'DB folder: {DB_DIR}')
    print(f'UNSTAGED folder: {UNSTAGED_DIR}')

    read_all_data_dir(UNSTAGED_DIR)
    load_db_from_csv()
    while True:
        print(data_enrichment_ui)
        op = input('\ndata-tool # ')
        if op == '1':
            print('Enriching C2 info...')
            enrich_cnc_info()
        if op == '2':
            print(f'Enriching attack info, totally {len(g_db_attack_info)} attacks...')
            print('Choose attack info range, e.g. 1,100')
            r = input('\ndata-tool # ').split(',')
            s = int(r[0])
            e = int(r[1])
            await enrich_attack_info(s, e)
        if op == '3':
            print(f'Rebuild C2 status for v1, {len(g_db_cnc_status_info)} C2 status...')
            print('Choose C2 status info range, e.g. 1,100')
            r = input('\ndata-tool # ').split(',')
            s = int(r[0])
            e = int(r[1])
            await rebuild_cnc_status(s, e)
        else:
            break


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
                asyncio.run(async_data_enrichment(), debug=True)
            elif op == '3':
                sync_data_triage()
            elif op == 'q':
                print('Have a good day! Bye!')
                exit(0)
            else:
                print('Error input!')
    except KeyboardInterrupt:
        print('Have a good day! Bye!')
