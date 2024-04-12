#!/usr/bin/env python3

import time
import os
import sys
import asyncio
import signal
from datetime import datetime, timedelta
from concurrent.futures import ProcessPoolExecutor
import logging

#  logging.basicConfig(format='%(asctime)s-%(task_name)s-%(name)s-%(levelname)s-%(message)s',
#  datefmt='%d-%b-%y %H:%M:%S', level = logging.DEBUG)

log_format = '%(asctime)s-%(name)s-%(levelname)s-%(message)s'


class MyStreamHandler(logging.StreamHandler):
    def __init__(self):
        super().__init__()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            task = asyncio.current_task(asyncio.get_running_loop())
            if task is not None:
                record.__setattr__("name", f"{record.name}-{task.get_name()}")
            #  record.__setattr__("name", f"'task'-{record.name}")
        except RuntimeError:
            pass
        super().emit(record)


class TaskLogger:
    #  _next_id = itertools.count().__next__
    #  _task_ids = weakref.WeakKeyDictionary()

    def __init__(self, name):
        self._logger = logging.getLogger(name)
        self._handler = MyStreamHandler()
        self._handler.setFormatter(logging.Formatter(fmt=log_format))
        self._logger.addHandler(self._handler)
        self._logger.setLevel(logging.DEBUG)

    #  def _task_name(self):
    #  task_name = asyncio.current_task().get_name()
    #  if task_name is None:
    #  task_name = 'null'
    #  return f't-{task_name[0:6]}'
    #  if task not in self._task_ids:
    #  self._task_ids[task] = self._next_id()
    #  return f'task-{self._task_ids[task]}'

    def debug(self, *args, **kwargs):
        self._logger.debug(*args, **kwargs)

    def info(self, *args, **kwargs):
        self._logger.info(*args, **kwargs)

    def warning(self, *args, **kwargs):
        self._logger.warning(*args, **kwargs)

    def error(self, *args, **kwargs):
        self._logger.error(*args, **kwargs)

    def critical(self, *args, **kwargs):
        self._logger.critical(*args, **kwargs)


l = TaskLogger(__name__)


class capture:
    def __init__(self):
        self.count = 0

    async def gen_item(self):
        try:
            while True:
                #  l.debug("gen_item...")
                await asyncio.sleep(1)
                yield self.count
                self.count += 1
        finally:
            l.debug('gen finilized')


#  analyzerContextPool = {}

def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    #  global analyzerContextPool
    #  analyzerContextPool.clear()


class analyzerReport:
    def __init__(self):
        self.result = 0


class analyzer:
    def __init__(self):
        self.report = analyzerReport()

    def analyze(self, n):
        l.debug(f"analyze {n} when result: {self.report.result}")
        time.sleep(0.5)
        self.report.result += n
        l.debug(f"analyze result: {self.report.result}")
        return self.report


class test:
    executor = ProcessPoolExecutor(max_workers=2,
                                   initializer=init_worker)

    def __init__(self, name):
        self.name = name
        self.tasks = set()
        self.gen = capture()
        self.analyzer = analyzer()

    async def find_cnc(self):
        res = None
        try:
            loop = asyncio.get_event_loop()
            #  loop.set_debug(True)
            async for n in self.gen.gen_item():
                #  self.analyzer.analyze(n)
                #  with ProcessPoolExecutor(max_workers=1) as pool:
                #  await loop.run_in_executor(pool,
                #  self.analyzer.analyze,
                #  n)
                res = await loop.run_in_executor(test.executor,
                                                 self.analyzer.analyze,
                                                 n)
                self.analyzer.report = res
                l.debug(f'{self.name}-cnc, result {res.result}')
        #  except asyncio.TimeoutError:
        #  l.debug(f'{self.name}-cnc-timeout, result {self.analyzer.get_result()}')
        #  except asyncio.CancelledError:
        #  l.debug(f'{self.name}-cnc-cancelled, result {self.analyzer.get_result()}')
        finally:
            l.debug(f'{self.name}-cnc-finally')

    async def find_attack(self):
        res = None
        try:
            #  l.debug("find_attack in...")
            loop = asyncio.get_event_loop()
            #  l.debug("loop get...")
            async for n in self.gen.gen_item():
                #  l.debug(f"get an item...{n}")
                #  self.analyzer.analyze(n)
                res = await loop.run_in_executor(test.executor,
                                                 self.analyzer.analyze,
                                                 n)
                self.analyzer.report = res
                l.debug(f'{self.name}-attack result {res.result}')
        finally:
            pass

    async def run(self):
        try:
            #  await self.find_cnc()
            try:
                await asyncio.wait_for(self.find_cnc(), timeout=5)
            except asyncio.TimeoutError:
                l.debug('timeout error')
            await self.find_attack()
        except asyncio.CancelledError:
            l.debug(f'{self.name} run task is canclled')
        except KeyboardInterrupt:
            l.debug(f'{self.name} run task is interrupted')


class test_sche:
    def __init__(self):
        self.count = 0
        self.tasks = {}

    async def sched(self):
        try:
            while True:
                #  l.debug("sched in...")
                def done_cb(t):
                    l.debug(f'remove item from dict: {t.get_name()}')
                    if t in self.tasks:
                        l.debug(f'{t.get_name()} is in dicts')
                        del self.tasks[t]

                if self.count % 5 == 0:
                    tn = f'task-{self.count / 5}'
                    obj = test(tn)
                    t = asyncio.create_task(obj.run(), name=tn)
                    self.tasks[t] = obj
                    t.add_done_callback(done_cb)

                await asyncio.sleep(1)
                self.count += 1
        except asyncio.CancelledError:
            l.debug('sched cancelled')
            for k, v in self.tasks.items():
                if not k.done():
                    k.cancel()
                else:
                    l.debug(f"task {k} is done, no need to cancel")

            test.executor.shutdown()


async def async_main():
    try:
        ts = test_sche()
        await ts.sched()
    except asyncio.CancelledError:
        l.debug('User cancelled async main')


def test_time():
    td = timedelta(days=0, hours=0, minutes=0, seconds=30)
    t1 = datetime.now()
    l.debug(f't1: {t1}')

    while True:
        time.sleep(2)
        t2 = datetime.now()
        l.debug(f't2: {t2}')
        tdiff = t2 - t1
        l.debug(f'tdiff: {tdiff}')
        if tdiff > td:
            l.debug('time is up')
            break
        else:
            l.debug(f'time left: \n{td - tdiff}')


def test_dict():
    d = {'a': '1', 'b': '2', 'c': '3', 'd': '4', 'e': '5'}
    to_del = []
    for k, v in d.items():
        del d[k]
        print(f'after delete {k}, d:{d}')


async def task1():
    try:
        print('task1 enter')
        await asyncio.sleep(10)
        print('task1 quit')
    except asyncio.CancelledError:
        print('task1 get cancelled error')
    finally:
        print('task1 get finalized error')


async def task2():
    try:
        print('task2 enter')
        await asyncio.sleep(10)
        print('task2 quit')
    except asyncio.CancelledError:
        print('task2 get cancelled error')
        raise asyncio.CancelledError


async def async_task():
    try:
        t1 = asyncio.create_task(task1())
        t2 = asyncio.create_task(task2())
        await asyncio.sleep(2)
        t1.cancel()
        await t1
        await asyncio.sleep(2)
        t2.cancel()
        await asyncio.sleep(10)
    except asyncio.CancelledError:
        print('async_task get cancelled error')


if __name__ == '__main__':
    #  test_dict()
    try:
        asyncio.run(async_task())
    except KeyboardInterrupt:
        print('Main Interrupted')
