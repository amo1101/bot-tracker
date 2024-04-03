import asyncio
import time

cmd_config = {
    'list_bot': [1,2],
    'list_tracker': [1,1],
    'start_bot': [2,2],
    'stop_bot': [2,2],
    'balance_load': [1,1]
}

def check_args(command):
    cmd_split = command.split(' ')
    cmd = cmd_split[0]
    argc = len(cmd_split)
    if cmd not in cmd_config:
        return False
    if argc < cmd_config[cmd][0] or argc > cmd_config[cmd][1]:
        return False
    return True

def show_help():
    pass

async def start_cli():
    reader, writer = await asyncio.open_connection('127.0.0.1', 8888)
    print('Bot Tracker Command line')
    try:
        while True:
            command = input("> ")
            if not check_args(command):
                print('Wrong argument')
                show_help()
            print(f'command: {command}')
            writer.write(command.encode())
            print('command sent..')
            data = await reader.read(8192)
            print('command response..')
            if not data:
                break
            resp = data.decode()
            print(resp)
    finally:
        writer.close()
        await writer.wait_closed()

if __name__ == "__main__":
    try:
        asyncio.run(start_cli(),debug=True)
    except KeyboardInterrupt:
        l.debug('Interrupted by user')

