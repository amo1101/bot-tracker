import asyncio
import os
from analyzer_executor import *
import configparser
import csv
from packet_capture import AsyncFileCapture
from db_store import *

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = CUR_DIR + os.sep + 'log'
REPORT_DIR = CUR_DIR + os.sep + 'report'
g_data_dir = []
g_tool_config = None
g_db_store = None


# data dir structure: log/bot/measurements
def read_all_data_dir():
    global g_data_dir
    for r, d, f in os.walk(DATA_DIR):
        entry = (d, [])
        g_data_dir.append(entry)
        curr_path = r + os.sep + d
        for r1, d1, f1 in os.walk(curr_path):
            entry[1].append(d1)
    if len(g_data_dir) == 0:
        print('No data to analyze.')


def read_tool_config():
    global g_tool_config
    g_tool_config = configparser.ConfigParser()
    ini_file = REPORT_DIR + os.sep + 'config.ini'
    if not os.path.exists(ini_file):
        l.error('tool config file not exist!')
        g_tool_config = None
        return
    g_tool_config.read(ini_file)


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
        return

    while True:
        if os.path.isfile(csv_file):
            print(f'file {csv_file} already exist, input a new file name:')
            csv_file = input()
        else:
            break

    with open(csv_file, 'w', newline='') as file:
        fieldnames = data[0].keys()
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)


async def get_bot_cnc_info(bot):
    # e.g.2024_06_26_16_12_38_mirai_5f2ac36f
    last_ = bot.rfind("_")
    bot_id = bot[last_ + 1:]
    cncs = await g_db_store.load_cnc_info(bot_id)
    if len(cncs) == 0:
        print('Cannot find CnC info for this bot')
        return None, None
    bot_id_raw = cncs[0].bot_id
    cnc_ip_ports = [(c.ip, str(c.port)) for c in cncs]
    return bot_id_raw, cnc_ip_ports


def get_sandbox_ip(pcap):
    sandbox_ip = None

    def inspect_packet(pkt):
        nonlocal sandbox_ip
        sandbox_ip = pkt.ip.src

    # filter packets for downloading bot from malware repo
    display_filter = \
        f"ip.src=={g_tool_config['data_analysis']['subnet']} and " + \
        f"ip.dst=={g_tool_config['data_analysis']['malware_repo_ip']} and " + \
        f"tcp.dstport=22 and tcp.flags.syn=1"

    cap = pyshark.FileCapture(pcap, display_filter=display_filter)
    cap.apply_on_packets(inspect_packet, packet_count=50)
    print(f'Get sandbox ip: {sandbox_ip}')
    return sandbox_ip


def create_report_dir(bot, measurement):
    b_dir = REPORT_DIR + os.sep + bot
    m_dir = b_dir + os.sep + measurement
    if not os.path.exists(b_dir):
        os.makedirs(b_dir)
    if not os.path.exists(m_dir):
        os.makedirs(m_dir)


def get_report_dir(bot, measurement):
    return REPORT_DIR + os.sep + bot + os.sep + measurement


def get_data_dir(bot, measurement):
    return DATA_DIR + os.sep + bot + os.sep + measurement


async def run_cnc_analyzer(bot, measurement, packet_cnt):
    pcap = get_data_dir(bot, measurement) + os.sep + 'capture.pcap'
    own_ip = get_sandbox_ip(pcap)
    if own_ip is None:
        print('Sandbox ip not found!')
        return
    excluded_ips = g_tool_config['data_analysis']['excluded_ips'].split(',')

    print(f'Start detecting C2 servers...')
    print(f'pcap file: {pcap}\nsandbox_ip: {own_ip}\npacket_cnt: {packet_cnt}')
    executor_pool = AnalyzerExecutorPool(1)
    eid = executor_pool.open_executor()
    aid = await executor_pool.init_analyzer(eid, AnalyzerType.ANALYZER_CNC,
                                            own_ip=own_ip,
                                            excluded_ips=excluded_ips,
                                            excluded_ports=None)
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


async def run_attack_analyzer(bot, measurement, packet_cnt):
    pcap = get_data_dir(bot, measurement) + os.sep + 'capture.pcap'
    own_ip = get_sandbox_ip(pcap)
    if own_ip is None:
        print('Sandbox ip not found!')
        return
    excluded_ips = g_tool_config['data_analysis']['excluded_ips'].split(',')
    attack_gap = int(g_tool_config['data_analysis']['attack_gap'])
    min_attack_packets = int(g_tool_config['data_analysis']['min_attack_packets'])
    bot_id, cnc_ip_ports = await get_bot_cnc_info(bot)
    if cnc_ip_ports is None:
        print('CnC not exists for this bot!')
        return

    print(f'Start analyzing attack and CnC stats...')
    print(f'pcap file: {pcap}\nsandbox_ip: {own_ip}\npacket_cnt: {packet_cnt}')
    print(f'CnC info: {cnc_ip_ports}\nattack_gap:{attack_gap}')
    print(f'min_attack_packets: {min_attack_packets}')

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
                                            min_attack_packets=min_attack_packets)
    cap = AsyncFileCapture(pcap)

    def get_report_result(report):
        nonlocal cnc_status, cnc_stats, attack_reports
        if report['cnc_status']['ready']:
            cnc_status.append(report['cnc_status'])
        cnc_stats.extend(report['cnc_stats'])
        for ar in report['attacks']:
            ar['bot_id'] = bot_id
            ar['cnc_ip'] = report['cnc_status']['cnc_ip']
            attack_reports.append(ar)

    try:
        cnt = 0
        async for packet in cap.sniff_continuously(packet_cnt):
            ret = await executor_pool.analyze_packet(eid, aid, packet)
            if ret is True:
                r = await executor_pool.get_result(eid, aid)
                get_report_result(r)
            cnt += 1
            if cnt % 10000 == 0:
                print(f'{cnt} packets analyzed...')
    finally:
        r = await executor_pool.get_result(eid, aid, True)
        get_report_result(r)

    print('Finished analyzing CnC and attack stats')

    await executor_pool.finalize_analyzer(eid, aid)
    executor_pool.close_executor(eid)
    executor_pool.destroy()
    await cap.close_async()

    create_report_dir(bot, measurement)
    str_time = datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
    report_dir = get_report_dir(bot, measurement)
    f_cnc_status = report_dir + os.sep + 'cnc-status_' + str_time + '.csv'
    f_cnc_stats = report_dir + os.sep + 'cnc-stats_' + str_time + '.csv'
    f_attacks = report_dir + os.sep + 'attacks_' + str_time + '.csv'
    write_to_csv(f_cnc_status, cnc_status)
    write_to_csv(f_cnc_stats, cnc_stats)
    write_to_csv(f_attacks, attack_reports)

    print('Analyzing results have been written to files under:\n{report_dir}')


def input_bot_measurement_menu():
    print('Choose bot:')
    i = 1
    for b in g_data_dir:
        print(f'{i}: {b[0]}')
        i += 1
    b_idx = int(input()) - 1

    print('Choose measurement:')
    i = 1
    for m in g_data_dir[b_idx][1]:
        print(f'{i}: {m}')
        i += 1
    m_idx = int(input()) - 1
    bot = g_data_dir[b_idx][0]
    m = g_data_dir[b_idx][1][m_idx]

    print('Input packet number to analyze:')
    packet_cnt = int(input())
    return bot, m, packet_cnt


async def async_data_analysis():
    await connect_db()
    try:
        while True:
            print('Please choose:\n1: detect CnC server\n2: analyze attacks and CnC stats')
            op = input()
            if op == '1':
                b, m, packet_cnt = input_bot_measurement_menu()
                await run_cnc_analyzer(b, m, packet_cnt)
            elif op == '2':
                print('Choose:\n1: analyze for a specific bot\n2: analyze all')
                choice = input()
                if choice == '1':
                    b, m, packet_cnt = input_bot_measurement_menu()
                    await run_attack_analyzer(b, m, packet_cnt)
                elif choice == '2':
                    for b, ms in g_data_dir:
                        for m in ms:
                            await run_attack_analyzer(b, m, 0)
                else:
                    pass
            else:
                pass
    finally:
        await g_db_store.close()


if __name__ == "__main__":
    try:
        read_all_data_dir()
        read_tool_config()
        if len(g_data_dir) == 0 or g_tool_config is None:
            exit(0)
        print('Welcome to botnet tracker data processing tool')
        while True:
            print('Please choose:\n1: data analysis\n2: data enrichment\n3: data backup')
            op = input()
            if op == '1':
                asyncio.run(async_data_analysis(), debug=True)
            elif op == '2':
                pass
            elif op == '3':
                pass
            else:
                print('Error input!')
    except KeyboardInterrupt:
        print('Have a good day! Bye!')
