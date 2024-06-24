import asyncio
import os
from analyzer_executor import *
from log import TaskLogger
import argparse
from packet_capture import AsyncFileCapture

l: TaskLogger = TaskLogger(__name__)
CUR_DIR = os.path.dirname(os.path.abspath(__file__))


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
                              min_attack_packets, packet_count):
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
    finally:
        report = await executor_pool.get_result(eid, aid, True)
        print(f'final attack detected: {report}')

    await executor_pool.finalize_analyzer(eid, aid)
    executor_pool.close_executor(eid)
    executor_pool.destroy()
    await cap.close_async()


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
                                  args.packet_count)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test CnCAnalyzer and AttackAnalyzer.")
    parser.add_argument("-t", "--type", type=int, required=True,
                        help="analyzer to test: CnCAnalyzer, 1: AttackAnalyzer")
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
    args = parser.parse_args()

    try:
        asyncio.run(async_main(args), debug=True)
    except KeyboardInterrupt:
        print('Interrupted by user')

