import asyncio
import time

async def start_bot():
    reader, writer = await asyncio.open_connection('127.0.0.1', 9999)
    reg_cmd = 'register botmaster'
    writer.write(reg_cmd.encode())
    await writer.drain()
    print('Botmaster Connected to C&C Server')
    while True:
        command = input("Enter command: ")
        writer.write(command.encode())
        data = await reader.read(100)
        if not data:
            break
        message = data.decode()
        print(f"\n{message}")

asyncio.run(start_bot())

