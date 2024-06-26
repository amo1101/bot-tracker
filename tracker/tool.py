import asyncio
import os
from analyzer_executor import *
import argparse
import csv
from packet_capture import AsyncFileCapture

CUR_DIR = os.path.dirname(os.path.abspath(__file__))


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


async def async_main(args):
    if args.type == 0:
        await run_cnc_analyzer(args.pcap, args.sandbox_ip,
                               args.excluded_ips.split(','),
                               args.packet_count)
    else:
        await run_attack_analyzer(args.pcap, args.cnc_ip,
                                  args.sandbox_ip,
                                  args.excluded_ips.split(','),
                                  args.attack_gap,
                                  args.min_attack_packets,
                                  args.packet_count,
                                  args.output_file)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CnC and attack analyze tool.")
    parser.add_argument("-t", "--type", type=int, required=True,
                        help="choose analyzer, 0: CnCAnalyzer, 1: AttackAnalyzer")
    parser.add_argument("-p", "--pcap", type=str, required=False, default='',
                        help="pcap file to load packets from")
    parser.add_argument("-n", "--packet_count", type=int, required=False, default=0,
                        help="number of packets to analyze")
    parser.add_argument("-s", "--sandbox_ip", type=str, required=False, default='',
                        help="Sandbox IP, required for both analzyers")
    parser.add_argument("-e", "--excluded_ips", type=str, required=False, default='',
                        help="Exclueded IPs for CnCAnalyzer, separate with comma")
    parser.add_argument("-c", "--cnc_ip", type=str, required=False, default='',
                        help="C2 IP, for AttackAnalyzer")
    parser.add_argument("-g", "--attack_gap", type=int, required=False,
                        default=900,
                        help="Attack gap for AttackAnalyzer")
    parser.add_argument("-m", "--min_attack_packets", type=int, required=False,
                        default=30,
                        help="Minimum attack packets for AttackAnalyzer")
    parser.add_argument("-o", "--output_file", type=str, required=False,
                        default='cnc_report.csv,attack_report.csv',
                        help="Out file in csv format for C2 status and attack \
                        reports, separated by comma, e.g.,cnc_report.csv,attack_report.csv")
    args = parser.parse_args()

    try:
        asyncio.run(async_main(args), debug=True)
    except KeyboardInterrupt:
        print('Interrupted by user')

