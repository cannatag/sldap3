import asyncio

# from sldap3.core.server import Ldap3Protocol, clients
from sldap3.core.server import client_connected, clients

@asyncio.coroutine
def status():
    last = None
    trigger = False
    while True:
        if len(clients) != last:
            print('Clients:', len(clients))
            last = len(clients)
        yield from asyncio.sleep(2)
        if clients:
            trigger = True
        if trigger and not clients:
            break
    print('Closing server')
    server.close()
    print('server closed')

loop = asyncio.get_event_loop()
coro = asyncio.start_server(client_connected, 'localhost', 389)
server = loop.run_until_complete(coro)
print('Server started')
loop.create_task(status())

try:
    loop.run_until_complete(server.wait_closed())
except KeyboardInterrupt:
    print('force exit server')
    server.close()
    print('server closed')
finally:
    loop.close()
    print('loop closed')
