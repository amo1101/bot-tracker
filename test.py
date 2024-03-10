#!/usr/bin/env python3

import time
import os
import sys
import asyncio
import signal
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

analyzerContextPool = {}

def reset_analyzer_context_pool():
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    global analyzerContextPool
    analyzerContextPool.clear()

class analyzerContext:
    def __init__(self):
        self.result = 0

class analyzer:
    def __init__(self, uid):
        self.uid = uid
    def _get_context(self):
        global analyzerContextPool
        if self.uid not in analyzerContextPool:
            analyzerContextPool[self.uid] = analyzerContext()
            print(f'analzyer ctx for {self.uid} created')
        return analyzerContextPool[self.uid]

    def _set_context(self, ctx):
        global analyzerContextPool
        analyzerContextPool[self.uid] = ctx


    def analyze(self, n):
        ctx = self._get_context()
        print(f"analyze {n} when result: {ctx.result}")
        time.sleep(0.5)
        ctx.result += n
        self._set_context(ctx)
        print(f"analyze result: {ctx.result}")
        return ctx.result

class test:
    executor = ProcessPoolExecutor(max_workers=1,
                                   initializer=reset_analyzer_context_pool)
    def __init__(self, name):
        self.name = name
        self.tasks = set()
        self.gen = capture()
        self.analyzer = analyzer(name)

    async def find_cnc(self):
        res = None
        print(f'analzyer oid is {self.analyzer.uid}')
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
                print(f'{self.name}-cnc, result {res}')
        #  except asyncio.TimeoutError:
            #  print(f'{self.name}-cnc-timeout, result {self.analyzer.get_result()}')
        #  except asyncio.CancelledError:
            #  print(f'{self.name}-cnc-cancelled, result {self.analyzer.get_result()}')
        finally:
            print(f'{self.name}-cnc-finally, result {res}')

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
                print(f'{self.name}-attack result {res}')
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
                if self.count % 5 == 0:
                    tn = f'task-{self.count/5}'
                    obj = test(tn)
                    t = asyncio.create_task(obj.run(), name=tn)
                    self.tasks[tn] = [t, obj]

                await asyncio.sleep(1)
                self.count += 1
        except asyncio.CancelledError:
            print('sched cancelled')
            for k,v in self.tasks.items():
                if not v[0].done():
                    v[0].cancel()
                else:
                    print(f"task {k} is done, no need to cancel")

            test.executor.shutdown()


async def async_main():
    try:
        ts = test_sche()
        await ts.sched()
    except asyncio.CancelledError:
        print('User cancelled async main')

if __name__ == '__main__':
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        print('Main Interrupted')


