import asyncio
import os
from analyzer_executor import *
import argparse
import configparser
import csv
from packet_capture import AsyncFileCapture
from db_store import *

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = CUR_DIR + os.sep + 'log'
g_data_dir = {}

# data dir structure: log/bot/measurements
def read_all_data_dir():
    for r, d, f in os.walk(DATA_DIR):
        entry = (d, [])
        g_data_dir.append(entry)
        curr_path = os.path.join(r, d)
        for r1, d1, f1 in os.walk(curr_path):
            entry[1].append(d1)


# data should stored in list of dict
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
    print(f"Data written to {csv_file}")

async def run_cnc_analyzer(pcap, own_ip, excluded_ips, packet_count):
    executor_pool = AnalyzerExecutorPool(1)
    eid = executor_pool.open_executor()
    aid = await executor_pool.init_analyzer(eid, AnalyzerType.ANALYZER_CNC,
                                            own_ip=own_ip,
                                            excluded_ips=excluded_ips,
                                            excluded_ports=None)
    cap = AsyncFileCapture(pcap)
    try:
        async for packet in cap.sniff_continuously(packet_count):
            await executor_pool.analyze_packet(eid, aid, packet)
    finally:
        pass

    result = await executor_pool.get_result(eid, aid)
    print(f'result of cnc_analyze: {result}')
    await cap.close_async()

    await executor_pool.finalize_analyzer(eid, aid)
    executor_pool.close_executor(eid)
    executor_pool.destroy()


async def run_attack_analyzer(pcap, cnc_ip, own_ip, excluded_ips, attack_gap,
                              min_attack_packets, packet_count,
                              output_file):
    output_files = output_file.split(',')
    cnc_reports = []
    attack_reports = []
    executor_pool = AnalyzerExecutorPool(1)
    eid = executor_pool.open_executor()
    aid = await executor_pool.init_analyzer(eid, AnalyzerType.ANALYZER_ATTACK,
                                            cnc_ip=cnc_ip,
                                            cnc_port=None,
                                            own_ip=own_ip,
                                            excluded_ips=excluded_ips,
                                            enable_attack_detection=True,
                                            attack_gap=attack_gap,
                                            min_attack_packets=min_attack_packets)
    cap = AsyncFileCapture(pcap)
    try:
        async for packet in cap.sniff_continuously(packet_count):
            ret = await executor_pool.analyze_packet(eid, aid, packet)
            if ret is True:
                report = await executor_pool.get_result(eid, aid)
                print(f'attack detected: {report}')
                cnc_reports.append(report['cnc_status'])
                attack_reports.extend(report['attacks'])
    finally:
        report = await executor_pool.get_result(eid, aid, True)
        cnc_reports.append(report['cnc_status'])
        attack_reports.extend(report['attacks'])
        print(f'final attack detected: {report}')

    await executor_pool.finalize_analyzer(eid, aid)
    executor_pool.close_executor(eid)
    executor_pool.destroy()
    await cap.close_async()

    write_to_csv(output_files[0], cnc_reports)
    write_to_csv(output_files[1], attack_reports)


def input_bot_measurement_menu():
    print('Choose bot:')
    i = 1
    for b in g_data_dir:
        print(f'i: b[0]')
        i += 1
    b_idx = int(input()) - 1

    print('Choose measurement:')
    i = 1
    for m in g_data_dir[b_idx][1]:
        print(f'i: m')
        i += 1
    m_idx = int(input()) - 1
    bot = g_data_dir[b_idx][0]
    m = g_data_dir[b_idx][1][m_idx]

    print('Input packet number to analyze:')
    packet_cnt = int(input())
    return bot, m, packet_cnt


async def async_data_analysis(args):
    while True:
        print('Please choose:
               1: detect CnC server
               2: analzye attacks and CnC statistics
               b: go back')
        op = input()
        if op == '1':
            b, m, packet_cnt = input_bot_measurement_menu()
            await run_cnc_analyzer(b, m, packet_cnt)
        elif op == '2':
            print('Choose:
                   1: analyze for a specific bot
                   2: analyze all')
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
        elif op == 'b':
            return
        else:
            pass


if __name__ == "__main__":
    try:
        read_all_data_dir()
        print('Welcome to botnet tracker data processing tool')
        while True:
            print('Please choose:
                   1.data analysis
                   2.data enrichement
                   3.data backup
                   q: quit')

            op = input()
            if op == '1':
                asyncio.run(async_data_analysis(), debug=True)
            elif op == '2':
                pass
            elif op == '3':
                pass
            elif op == 'q':
                return
            else:
                print('error input!')
    except KeyboardInterrupt:
        print('Interrupted by user')

