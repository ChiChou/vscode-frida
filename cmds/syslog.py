#!/usr/bin/env python3

import frida
import sys

from utils import read_agent

def main(device_id, target):
    if device_id == 'usb':
        device = frida.get_usb_device()
    elif device_id == 'local':
        device = frida.get_local_device()
    else:
        device = frida.get_device(device_id)

    source = read_agent()
    session = device.attach(target)
    script = session.create_script(source)

    def on_message(message, data):
        sys.stdout.buffer.write(data)
        sys.stdout.flush()
    script.on('message', on_message)

    def on_detach(reason):
        sys.stdout.write('[FATAL Error] target disconnected')
        sys.exit(-1)
    session.on('detach', on_detach)

    script.load()
    script.exports.start()
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    finally:
        script.exports.stop()
        session.detach()

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='frida driver')
    parser.add_argument('device')
    parser.add_argument('--app')
    parser.add_argument('--pid', type=int)
    
    args = parser.parse_args()

    if args.pid and args.app:
        raise ValueError('either --app nor --pid is allowed')

    target = args.pid or args.app
    if target:
        main(args.device, target)
    else:
        parser.print_help()
    