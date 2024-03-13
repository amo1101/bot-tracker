#!/usr/bin/env python3

import time
import os
import sys
import asyncio
import signal
from datetime import datetime, timedelta
from concurrent.futures import ProcessPoolExecutor

class capture:
    def __init__(self):
        self.count = 0

    async def gen_item(self):
        try:
            while True:
                #  print("gen_item...")
                await asyncio.sleep(1)
                yield self.count
                self.count += 1
        finally:
           print('gen finilized')

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
        print(f"analyze {n} when result: {self.report.result}")
        time.sleep(0.5)
        self.report.result += n
        print(f"analyze result: {self.report.result}")
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
                print(f'{self.name}-cnc, result {res.result}')
        #  except asyncio.TimeoutError:
            #  print(f'{self.name}-cnc-timeout, result {self.analyzer.get_result()}')
        #  except asyncio.CancelledError:
            #  print(f'{self.name}-cnc-cancelled, result {self.analyzer.get_result()}')
        finally:
            print(f'{self.name}-cnc-finally')

    async def find_attack(self):
        res = None
        try:
            #  print("find_attack in...")
            loop = asyncio.get_event_loop()
            #  print("loop get...")
            async for n in self.gen.gen_item():
                #  print(f"get an item...{n}")
                #  self.analyzer.analyze(n)
                res = await loop.run_in_executor(test.executor,
                                           self.analyzer.analyze,
                                           n)
                self.analyzer.report = res
                print(f'{self.name}-attack result {res.result}')
        finally:
            pass

    async def run(self):
        try:
            #  await self.find_cnc()
            try:
                await asyncio.wait_for(self.find_cnc(), timeout=5)
            except asyncio.TimeoutError:
                print('timeout error')
            await self.find_attack()
        except asyncio.CancelledError:
            print(f'{self.name} run task is canclled')
        except KeyboardInterrupt:
            print(f'{self.name} run task is interrupted')

class test_sche:
    def __init__(self):
        self.count = 0
        self.tasks = {}

    async def sched(self):
        try:
            while True:
                #  print("sched in...")
                def done_cb(t):
                    print(f'remove item from dict: {t.get_name()}')
                    if t in self.tasks:
                        print(f'{t.get_name()} is in dicts')
                        del self.tasks[t]

                if self.count % 5 == 0:
                    tn = f'task-{self.count/5}'
                    obj = test(tn)
                    t = asyncio.create_task(obj.run(), name=tn)
                    self.tasks[t] = obj
                    t.add_done_callback(done_cb)

                await asyncio.sleep(1)
                self.count += 1
        except asyncio.CancelledError:
            print('sched cancelled')
            for k,v in self.tasks.items():
                if not k.done():
                    k.cancel()
                else:
                    print(f"task {k} is done, no need to cancel")

            test.executor.shutdown()


async def async_main():
    try:
        ts = test_sche()
        await ts.sched()
    except asyncio.CancelledError:
        print('User cancelled async main')

def test_time():
    td = timedelta(days=0, hours=0, minutes=0, seconds=30)
    t1 = datetime.now()
    print(f't1: {t1}')

    while True:
        time.sleep(2)
        t2 = datetime.now()
        print(f't2: {t2}')
        tdiff = t2 - t1
        print(f'tdiff: {tdiff}')
        if tdiff > td:
            print('time is up')
            break
        else:
            print(f'time left: \n{td-tdiff}')

if __name__ == '__main__':
    #  test_time()
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print('Main Interrupted')


