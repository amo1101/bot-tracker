#!/usr/bin/env python3

import time
import os
import sys
import asyncio
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

class analyzer:
    def __init__(self):
        self.result = 0

    def analyze(self, n):
        print(f"analyze {n}")
        time.sleep(0.5)
        self.result += n
        print(f"analyze result: {self.result}")

    def get_result(self):
        return self.result


class test:
    executor = ProcessPoolExecutor(max_workers=1)
    def __init__(self, name):
        self.name = name
        self.tasks = set()
        self.gen = capture()
        self.analyzer = analyzer()

    async def find_cnc(self):
        try:
            loop = asyncio.get_event_loop()
            #  loop.set_debug(True)
            async for n in self.gen.gen_item():
                self.analyzer.analyze(n)
                #  await loop.run_in_executor(test.executor,
                                           #  self.analyzer.analyze,
                                           #  n)
                print(f'{self.name}-cnc, result {self.analyzer.get_result()}')
        #  except asyncio.TimeoutError:
            #  print(f'{self.name}-cnc-timeout, result {self.analyzer.get_result()}')
        #  except asyncio.CancelledError:
            #  print(f'{self.name}-cnc-cancelled, result {self.analyzer.get_result()}')
        finally:
            print(f'{self.name}-cnc-finally, result {self.analyzer.get_result()}')

    async def find_attack(self):
        try:
            #  print("find_attack in...")
            loop = asyncio.get_event_loop()
            #  print("loop get...")
            async for n in self.gen.gen_item():
                #  print(f"get an item...{n}")
                self.analyzer.analyze(n)
                #  await loop.run_in_executor(test.executor,
                                           #  self.analyzer.analyze,
                                           #  n)
                print(f'{self.name}-attack result {self.analyzer.get_result()}')
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
                print("sched in...")
                if self.count % 5 == 0:
                    tn = f'task-{self.count/5}'
                    obj = test(tn)
                    t = asyncio.create_task(obj.run(), name=tn)
                    self.tasks[tn] = [t, obj]

                await asyncio.sleep(5)
                self.count += 1
        except asyncio.CancelledError:
            print('sched cancelled')
            for k,v in self.tasks.items():
                if not v[0].done():
                    v[0].cancel()
                else:
                    print(f"task {k} is done, no need to cancel")



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


