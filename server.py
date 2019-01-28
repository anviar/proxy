import asyncio
from multiprocessing import Process
import yaml
import struct
import socket
from pathlib import Path
import logging
from uuid import uuid4
from os import getpid

workdir = Path(__file__).resolve().parent
with open(workdir / 'config.yml') as config_f:
    config = yaml.load(config_f)

logging.basicConfig(
    format='[%(levelname)s] %(message)s',
    level=logging.getLevelName(config['loglevel']))


class ClientConnection(asyncio.Protocol):
    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        try:
            logging.debug('{}: <<< {}'.format(self.uuid, data))
        except UnicodeDecodeError:
            logging.debug("{}: received {} bytes".format(self.uuid, len(data)))
        self.server_transport.write(data)

    def connection_lost(self, *args):
        self.server_transport.close()


class Socks5Server(asyncio.Protocol):
    """
        https://www.ietf.org/rfc/rfc1928.txt
    """
    def __init__(self, **kwargs):
        self.stage = 'hello'
        self.auth = kwargs.get('auth', False)
        self.uuid = uuid4().hex[:8]
        self.loop = asyncio.get_running_loop()

    async def cmd_connect(self, **kwargs):
        dst_addr = kwargs['dst_addr']
        dst_port = kwargs['dst_port']
        addr_length = kwargs['addr_length']
        try:
            transport, client = await self.loop.create_connection(
                ClientConnection,
                dst_addr,
                dst_port,
            )
            client.server_transport = self.transport
            client.uuid = self.uuid
            self._client = client
            out_ip, out_port = transport.get_extra_info('sockname')
            rep = 0
        except TimeoutError as e:
            logging.warning(f'{self.uuid}: {e}')
            out_ip, out_port = '0.0.0.0', 0
            rep = 3
        out_ip_struct = [int(o) for o in out_ip.split('.')]
        """
            +----+-----+-------+------+----------+----------+
            |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            +----+-----+-------+------+----------+----------+
            | 1  |  1  | X'00' |  1   | Variable |    2     |
            +----+-----+-------+------+----------+----------+
        """
        resp = struct.pack(f'!BBBB{addr_length}BH',
                           5,
                           rep,
                           0,
                           1,
                           *out_ip_struct,
                           out_port)
        self.transport.write(resp)
        if rep == 0:
            logging.debug(
                f'{self.uuid}: Server connected from {out_ip}:{out_port} to {dst_addr}:{dst_port}')
            self.stage = 'work'
        else:
            self.transport.close()

    async def send_data(self, data):
        try:
            logging.debug("{}: >>> {}".format(self.uuid, data.decode('ASCII')))
        except UnicodeDecodeError:
            logging.debug("{}: sent {} bytes".format(self.uuid, len(data)))
        self._client.transport.write(data)

    def connection_made(self, transport):
        src_ip, src_port = transport.get_extra_info('peername')
        self.session_name = f'{src_ip}:{src_port}'
        logging.debug('{}: Connection from {}'.format(self.uuid, self.session_name))
        self.transport = transport

    def data_received(self, data):

        if self.stage == 'hello':
            """
                    +----+----------+----------+
                    |VER | NMETHODS | METHODS  |
                    +----+----------+----------+
                    | 1  |    1     | 1 to 255 |
                    +----+----------+----------+
            """
            ver, nmethods = struct.unpack('<BB', data[:2])
            methods = struct.unpack_from(f'<{nmethods}B', data, offset=2)
            """
                    +----+--------+
                    |VER | METHOD |
                    +----+--------+
                    | 1  |   1    |
                    +----+--------+
            """
            if ver == 5:
                if self.auth and 2 in methods:
                    resp = struct.pack('<BB', 5, 2)
                    self.stage = 'auth'
                    logging.debug(f'{self.uuid}: user\password auth requested')
                    self.transport.write(resp)
                elif not self.auth and 0 in methods:
                    resp = struct.pack('<BB', 5, 0)
                    self.stage = 'init'
                    self.transport.write(resp)
                else:
                    resp = struct.pack('<BB', 5, 255)
                    logging.debug('{}: Not found suitable method in {}'.format(self.uuid, methods))
                    self.transport.write(resp)
                    self.transport.close()
            else:
                resp = struct.pack('<BB', 5, 255)
                logging.debug('{}: Wrong protocol version {}'.format(self.uuid, ver))
                self.transport.write(resp)
                self.transport.close()

        elif self.stage == 'auth':
            """
                https://tools.ietf.org/html/rfc1929
                +----+------+----------+------+----------+
                |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
                +----+------+----------+------+----------+
                | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
                +----+------+----------+------+----------+
            """
            ver, ulen = struct.unpack('<BB', data[:2])
            uname, = (f.decode('ASCII') for f in struct.unpack_from(f'<{ulen}s', data, offset=2))
            plen, = struct.unpack_from(f'<B', data, offset=2 + ulen)
            passwd, = (f.decode('ASCII') for f in struct.unpack_from(
                f'<{plen}s', data, offset=3 + ulen))
            """
                auth reply
                +----+--------+
                |VER | STATUS |
                +----+--------+
                | 1  |   1    |
                +----+--------+
            """
            if uname in config['users'] and config['users'][uname] == passwd:
                resp = struct.pack('<BB', 1, 0)
                self.stage = 'init'
                logging.debug(f'{self.uuid}: AUTH SUCCESS')
                self.transport.write(resp)
            else:
                resp = struct.pack('<BB', 1, 1)
                logging.warning('{}: AUTH FAILED from {}, user={}'.format(
                    self.uuid, self.session_name, uname))
                self.transport.write(resp)

        elif self.stage == 'init':
            """
                +----+-----+-------+------+----------+----------+
                |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
                +----+-----+-------+------+----------+----------+
                | 1  |  1  | X'00' |  1   | Variable |    2     |
                +----+-----+-------+------+----------+----------+
            """
            ver, cmd, rsv, atyp = struct.unpack('<BBBB', data[0:4])
            if cmd == 1:
                # CONNECT
                if atyp == 1:
                    # IPv4 adress
                    addr_length = 4
                    dst_addr = socket.inet_ntop(socket.AF_INET, data[4:8])
                    dst_port, = struct.unpack_from('>H', data, offset=8)
                elif atyp == 6:
                    # IPv6 adress
                    addr_length = 16
                    dst_addr = socket.inet_ntop(socket.AF_INET6, data[4:20])
                    dst_port, = struct.unpack_from('>H', data, offset=20)
                elif atyp == 3:
                    # Domain name
                    dst_name_size, = struct.unpack_from('!B', data, offset=4)
                    dst_host = struct.unpack_from(
                        f'!{dst_name_size}s', data, offset=5)[0].decode('ASCII')
                    dst_port, = struct.unpack_from('>H', data, offset=5 + dst_name_size)
                    dst_addr = socket.gethostbyname(dst_host)
                    addr_length = 4
                self.loop.create_task(self.cmd_connect(
                    dst_addr=dst_addr,
                    dst_port=dst_port,
                    addr_length=addr_length,
                    atyp=atyp
                ))
            else:
                logging.warning(f'CMD {cmd} not implemented yet')
                self._client.transport.close()
        elif self.stage == 'work':
            self.loop.create_task(self.send_data(data))

    def connection_lost(self, *args):
        logging.debug("{}: client connection closed {}".format(self.uuid, args))
        if hasattr(self, '_client'):
            self._client.transport.close()


def service_handler(**args):

    async def main():
        loop = asyncio.get_running_loop()
        server = await loop.create_server(
            lambda: args['service'](**args),
            host=args['host'],
            port=args['port']
        )
        logging.info('PID {} serving on {}'.format(getpid(), server.sockets[0].getsockname()))
        async with server:
            await server.serve_forever()

    asyncio.run(main())


protocols = {
    'socks5': Socks5Server,
}

if __name__ == '__main__':
    servers = list()
    for srv in config['servers']:
        opts = {'service': protocols[srv['protocol']]}
        opts.update(srv)
        p = Process(
            target=service_handler,
            kwargs=(opts))
        p.start()
        servers.append(p)
    for p in servers:
        p.join()
