import asyncio
import concurrent.futures
import frida
import sys


pool = concurrent.futures.ThreadPoolExecutor(max_workers=4)


def make_handler(dev: frida.core.Device, port: int, buffer_size=4096):
    async def handler(reader, writer):
        channel = dev.open_channel('tcp:%d' % port)

        async def read_pipe():
            while True:
                loop = asyncio.get_event_loop()
                try:
                    buf = await loop.run_in_executor(pool, lambda: channel.read(buffer_size))
                except frida.OperationCancelledError:
                    break
                writer.write(buf)

        async def write_pipe():
            try:
                while not reader.at_eof():
                    channel.write(await reader.read(buffer_size))
            except Exception as e:
                sys.stderr.write('error:')
                sys.stderr.write(str(e))
            finally:
                channel.close()

        await asyncio.gather(read_pipe(), write_pipe())

    return handler


def find_free_port():
    import socket
    sock = socket.socket()
    sock.bind(('', 0))
    ip, port = sock.getsockname()
    sock.close()
    return port


def run_iproxy(local_port: int, port: int):
    import shutil
    import subprocess
    import os

    cli = shutil.which('iproxy')
    if not cli:
        return False

    try:
        output = subprocess.check_output([cli, '--help'])
    except:
        return False

    args = [cli]
    if b'LOCAL_PORT:DEVICE_PORT' in output:  # new
        args += [f'{local_port}:{port}']
        if opt.device != 'usb':
            args += ['-u', opt.device]
    else:
        args += [str(local_port), str(port)]
        if opt.device != 'usb':
            if b'--udid UDID' in output:
                args += ['--udid']
            args += [opt.device]

    if sys.platform == 'win32':
        subprocess.call(args)
        sys.exit()
    else:
        os.execv(cli, args)


async def main(opt):
    if opt.device == 'usb':
        dev = frida.get_usb_device()
    else:
        dev = frida.get_device(opt.device)

    if opt.port == 'ssh':
        for port in (22, 44):
            try:
                dev.open_channel('tcp:22').close()
                break
            except frida.ServerNotRunningError:
                continue
        else:
            raise RuntimeError('failed to connect remote SSH')
    else:
        port = int(opt.port)

    local_port = opt.local or find_free_port()

    # if run_iproxy(local_port, port):
    #     sys.exit()

    # fallback to python (bad performace)
    handler = make_handler(dev, port)
    server = await asyncio.start_server(handler, '127.0.0.1', port=opt.local, start_serving=False)
    sys.stdout.write('waiting for connection\n')
    # _, local_port = server.sockets[0].getsockname()
    # print(local_port, flush=True)

    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('device')
    parser.add_argument('port')
    parser.add_argument('local', nargs='?', default=0, type=int)
    opt = parser.parse_args()

    asyncio.run(main(opt))
