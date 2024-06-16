import signal
from concurrent.futures import ProcessPoolExecutor
import asyncio
import os
from attack_analyzer import *
from cnc_analyzer import *
from log import TaskLogger
from enum import Enum

l: TaskLogger = TaskLogger(__name__)
CUR_DIR = os.path.dirname(os.path.abspath(__file__))


# the AnalyzerContext instance will be serialized and sent to run in executor
# process remotely
class AnalyzerContext:
    def __init__(self, eid):
        self.eid = eid
        self.analyzer_reg = {}
        self.aid_cnt = 0

    def init_analyzer(self, analyzer):
        aid = self.aid_cnt
        self.aid_cnt += 1
        self.analyzer_reg[aid] = analyzer
        analyzer.set_tag(f'analyzer-{self.eid}-{aid}')
        l.debug(f'init_analyzer done aid:{aid}\n')
        return aid

    def analyze_packet(self, aid, packet):
        l.debug(f'analyze_packet at aid: {aid}...')
        if aid in self.analyzer_reg:
            return self.analyzer_reg[aid].analyze(packet)
        return False

    def get_result(self, aid, flush=False):
        l.debug(f'get_result from aid: {aid}...')
        if aid in self.analyzer_reg:
            return self.analyzer_reg[aid].get_result(flush)
        return None

    def finalize_analyzer(self, aid):
        l.debug(f'finalize_analyzer aid: {aid}...')
        if aid in self.analyzer_reg:
            del self.analyzer_reg[aid]


analyzer_context: AnalyzerContext


# these functions run in executor process remotely
def init_analyzer_in_executor(analyzer):
    global analyzer_context
    return analyzer_context.init_analyzer(analyzer)


def analyze_packet_in_executor(aid, packet):
    global analyzer_context
    return analyzer_context.analyze_packet(aid, packet)


def get_analyze_result_in_executor(aid, flush=False):
    global analyzer_context
    return analyzer_context.get_result(aid, flush)


def finalize_analyzer_in_executor(aid):
    global analyzer_context
    return analyzer_context.finalize_analyzer(aid)


def init_worker(analyzer_ctx):
    # suppress SIGINT in worker process to cleanly reclaim resource only by
    # main process
    global analyzer_context
    analyzer_context = analyzer_ctx
    l.debug('init_worker called!')
    signal.signal(signal.SIGINT, signal.SIG_IGN)


# following code run locally
class AnalyzerType(Enum):
    ANALYZER_CNC = 0
    ANALYZER_ATTACK = 1


# simple wrapper for ProcessPoolExecutor
# run task remotely in a specified executor process with executor id
class AnalyzerExecutorPool:
    def __init__(self, max_executors=1):
        self.max_executors = max_executors
        # eid : executor
        self.executor_reg = {}
        self._executor_cnt = 0

    def destroy(self):
        for k, v in self.executor_reg.items():
            v.shutdown()
        l.info('AnalyzerExecutorPool destroyed')

    # allocate an executor
    def open_executor(self):
        eid = self._executor_cnt % self.max_executors
        if eid in self.executor_reg:
            pass
        else:
            # for our purpose, we use only 1 worker from the underlying pool
            # otherwise we lose grip since we cannot single out a specific worker from the pool
            e = ProcessPoolExecutor(max_workers=1, initializer=init_worker,
                                    initargs=(AnalyzerContext(eid),))
            self.executor_reg[eid] = e

        self._executor_cnt += 1
        l.info(f'Executor {eid} opened')
        return eid

    def close_executor(self, eid):
        if eid in self.executor_reg:
            pass
        l.info(f'Executor {eid} closed')

    async def init_analyzer(self, eid, which, **kwargs):
        if eid not in self.executor_reg:
            l.warning(f'Executor {eid} not exist!')
            return None

        l.info(f'Initialzing analyzer at executor {eid} ...')
        e = self.executor_reg[eid]
        if which == AnalyzerType.ANALYZER_CNC:
            analyzer = CnCAnalyzer(kwargs['own_ip'],
                                   kwargs['excluded_ips'],
                                   kwargs['excluded_ports'])
        else:
            analyzer = AttackAnalyzer(kwargs['cnc_ip'],
                                      kwargs['cnc_port'],
                                      kwargs['own_ip'],
                                      kwargs['excluded_ips'])

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(e, init_analyzer_in_executor, analyzer)

    async def analyze_packet(self, eid, aid, packet):
        if eid not in self.executor_reg:
            l.warning(f'Executor {eid} not exist!')
            return False

        e = self.executor_reg[eid]

        # only send packet summary
        pkt_summary = PacketSummary()
        pkt_summary.extract(packet)
        l.debug(f'Analzying new packet at {eid}-{aid}:\n{repr(pkt_summary)}')

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(e, analyze_packet_in_executor,
                                          aid, pkt_summary)

    async def get_result(self, eid, aid, flush=False):
        if eid not in self.executor_reg:
            l.warning(f'Executor {eid} not exist!')
            return None
        e = self.executor_reg[eid]
        l.debug(f'Geting result at {eid}-{aid}...')
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(e, get_analyze_result_in_executor,
                                          aid, flush)

    async def finalize_analyzer(self, eid, aid):
        if eid not in self.executor_reg:
            l.warning(f'Executor {eid} not exist!')
            return
        e = self.executor_reg[eid]
        l.info(f'Finalizing analyzer at {eid}-{aid}...')
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(e, finalize_analyzer_in_executor, aid)


from packet_capture import AsyncFileCapture

async def test_executor_cnc_analyzer(pcap, own_ip, excluded_ips, packet_count,
                                    executor_cnt=1, task_cnt=1):
    executor_pool = AnalyzerExecutorPool(executor_cnt)
    eid = [0] * 5
    aid = [0] * 5
    for i in range(task_cnt):
        eid[i] = executor_pool.open_executor()
        aid[i] = await executor_pool.init_analyzer(eid[i], AnalyzerType.ANALYZER_CNC,
                                                own_ip=own_ip,
                                                excluded_ips=excluded_ips,
                                                excluded_ports=None)
        cap = AsyncFileCapture(pcap)
        try:
            async for packet in cap.sniff_continuously(packet_count):
                await executor_pool.analyze_packet(eid[i], aid[i], packet)
        finally:
            pass

        result = await executor_pool.get_result(eid[i], aid[i])
        print(f'result of cnc_analyze: {result}')
        await cap.close_async()

    for i in range(5):
        await executor_pool.finalize_analyzer(eid[i], aid[i])
        executor_pool.close_executor(eid[i])

    executor_pool.destroy()

async def test_executor_attack_analyzer(pcap, cnc_ip, own_ip, excluded_ips, packet_count):
    executor_pool = AnalyzerExecutorPool(2)
    eid = executor_pool.open_executor()
    aid = await executor_pool.init_analyzer(eid, AnalyzerType.ANALYZER_ATTACK,
                                            cnc_ip=cnc_ip,
                                            cnc_port=None,
                                            own_ip=own_ip,
                                            excluded_ips=excluded_ips)
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


#  import argparse
#  async def async_main(args):
    #  if args.type == 0:
        #  await test_executor_cnc_analyzer(args.pcap, args.sandbox_ip,
                                         #  args.excluded_ips.split(','),
                                         #  args.packet_count)
    #  else:
        #  await test_executor_attack_analyzer(args.pcap, args.cnc_ip,
                                            #  args.sandbox_ip,
                                            #  args.excluded_ips.split(','),
                                            #  args.packet_count)

#  if __name__ == "__main__":
    #  parser = argparse.ArgumentParser(description="Test CnCAnalyzer and AttackAnalyzer.")
    #  parser.add_argument("-t", "--type", type=int, required=True,
                        #  help="analyzer to test: CnCAnalyzer, 1: AttackAnalyzer")
    #  parser.add_argument("-p", "--pcap", type=str, required=False, default='',
                        #  help="pcap file to load packets from")
    #  parser.add_argument("-n", "--packet_count", type=int, required=False, default=0,
                        #  help="number of packets to analyze")
    #  parser.add_argument("-s", "--sandbox_ip", type=str, required=False, default='',
                        #  help="Sandbox IP, required for both analzyers")
    #  parser.add_argument("-e", "--excluded_ips", type=str, required=False, default='',
                        #  help="Exclueded IPs for CnCAnalyzer, separate with comma")
    #  parser.add_argument("-c", "--cnc_ip", type=str, required=False, default='',
                        #  help="C2 IP, for AttackAnalyzer")
    #  args = parser.parse_args()

    #  try:
        #  asyncio.run(async_main(args), debug=True)
    #  except KeyboardInterrupt:
        #  print('Interrupted by user')

