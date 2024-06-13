import signal
from concurrent.futures import ProcessPoolExecutor
import asyncio
import os
from packet_parser import *
from attack_analyzer import *
from cnc_analyzer import *
from log import TaskLogger
from enum import Enum

l: TaskLogger = TaskLogger(__name__)
CUR_DIR = os.path.dirname(os.path.abspath(__file__))

analyzer_context = None

# the AnalyzerContext instance will be serialized and sent to run in executor
# process remotely
class AnalyzerContext:
    def __init__(self):
        self.analyzer_reg = {}
        self.aid_cnt = 0

    def init_analyzer(self, analyzer):
        self.ai_cnt += 1
        aid = self.aid_cnt
        self.analyzer_reg[aid] = analyzer
        return aid

    def analyze_packet(self, aid, packet):
        if aid in self.analyzer_reg:
            return self.analyzer[aid].analyze(packet)
        return None

    def get_result(self, aid):
        if aid in self.analyzer_reg:
            return self.analyzer[aid].get_result()
        return None

    def finalize_analyzer(self, analyzer):
        if aid in self.analyzer_reg:
            del self.analyzer_reg[aid]

# these functions run in executor process remotely
def init_analyzer_in_executor(analyzer):
    global analyzer_context
    return analyzer_context.init_analyzer(analyzer)

def analyze_packet_in_executor(aid, packet):
    global analyzer_context
    return analyzer_context.analyze_packet(packet)

def get_analyze_result_in_executor(aid, packet):
    global analyzer_context
    return analyzer_context.get_result(aid)

def finalize_analyzer_in_executor(aid):
    global analyzer_context
    return analyzer_context.finalize_analyzer(aid)

def init_worker(analyzer_ctx):
    # suppress SIGINT in worker process to cleanly reclaim resource only by
    # main process
    global analyzer_context
    analyzer_context = analyzer_ctx
    signal.signal(signal.SIGINT, signal.SIG_IGN)

# following code run locally
class AnalyzerType(Enum):
    ANALYZER_CNC = 0
    ANALYZER_ATTACK = 1

# simple wrapper for ProcessPoolExecutor
# run task remotely in a speicified executor process with executor id
class AnalyzerExecutorPool:
    def __init__(self, max_executors=1):
        self.max_executors = max_executors
        # eid : (executor, attached_caller_cnt)
        self.executor_reg = {}
        self._executor_cnt = 0

    def destroy(self):
        for k, v in self.executor_reg:
            e, c = v
            if c != 0:
                l.warning('Executor still in use, destroy it anyway.')
            e.shutdown()

    # allocate an executor
    def open_executor(self):
        eid = self._executor_cnt % self.max_executors
        if eid in self.executor_reg:
            self.executor_reg[eid][1] += 1
        else:
            # for our purpose, we use only 1 worker from the underlying pool
            # otherwise we lose grip since we cannot single out a specific worker from the pool
            e = ProcessPoolExecutor(max_workers=1, initializer=init_worker,
                                    initargs=(AnalyzerContext(),))
            self.executor_reg[eid] = (e, 1)

        self._executor_cnt += 1
        return eid

    def close_executor(self, eid):
        if eid in self.executor_reg:
            self.executor_reg[eid][1] -= 1

    async def init_analyzer(self, eid, which, **kwargs):
        if eid not in self.executor_reg:
            l.warning(f'Excutor {eid} not exist!')

        e = self.executor_reg[eid][0]
        loop = asyncio.get_running_loop()

        analzyer = None
        if which == AnalyzerType.ANALYZER_CNC:
            analyzer = CnCAnalyzer(kwargs['own_ip'],
                                   kwargs['excluded_ips'],
                                   kwargs['excluded_ports'])
        else:
            analyzer = AttackAnalyzer(kwargs['cnc_ip'],
                                      kwargs['cnc_port'],
                                      kwargs['own_ip'])

        return await loop.run_in_executor(e, init_analyzer_in_executor, analyzer)

    async def analyze_packet(self, eid, aid, packet):
        if eid not in self.executor_reg:
            l.warning(f'Excutor {eid} not exist!')
            return

        e = self.executor_reg[eid][0]

        # only send packet summary
        pkt_summary = PacketSummary()
        pkt_summary.extract(packet)
        await self.loop.run_in_executor(e, analyze_packet_in_executor,
                                        aid, pkt_summary)

    async def get_result(self, eid, aid):
        if eid not in self.executor_reg:
            l.warning(f'Excutor {eid} not exist!')
            return
        e = self.executor_reg[eid][0]
        await self.loop.run_in_executor(e, get_analyze_result_in_executor, aid)

    async def fanalize_analyzer(self, eid, aid):
        if eid not in self.executor_reg:
            l.warning(f'Excutor {eid} not exist!')
            return
        e = self.executor_reg[eid][0]
        await self.loop.run_in_executor(e, finalize_analyzer_in_executor, aid)
