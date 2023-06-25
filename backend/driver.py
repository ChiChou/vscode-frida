#!/usr/bin/env python3

import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def main(args):
    from backend import core, rpc, syslog

    if args.remote:
        import frida
        remote_list = args.remote.split(',')
        mgr = frida.get_device_manager()
        for host in remote_list:
            mgr.add_remote_device(host)

    if args.action == 'devices':
        return core.devices()

    if not args.device:
        raise RuntimeError('NOTREACHED')

    device = core.get_device(args.device)
    if args.action == 'ps':
        return core.ps(device)

    if args.action == 'apps':
        return core.apps(device)

    if args.action == 'info':
        return core.device_info(device)

    if args.action == 'location':
        for app in device.enumerate_applications(identifiers=[args.bundle], scope='metadata'):
            return app.parameters.get('path')
        raise RuntimeError('app with bundle %s does not exist' % args.bundle)

    if args.action == 'syslog2':
        return syslog.start(device, pid=args.pid, bundle=args.app)

    target = args.pid or args.name
    agent = rpc.ProcessAgent(device, target) if target else \
        rpc.AppAgent(device, args.app)
    agent.load()

    if args.action == 'rpc':
        return agent.invoke(args.method, *args.args)

    if args.action == 'syslog':
        syslog.pipe(agent)
        return


if __name__ == '__main__':
    import argparse

    requires_device = argparse.ArgumentParser(add_help=False)
    requires_device.add_argument('device')

    requires_path = argparse.ArgumentParser(add_help=False)
    requires_path.add_argument('path')

    requires_app = argparse.ArgumentParser(add_help=False)
    requires_app.add_argument('--device', required=True)
    group = requires_app.add_mutually_exclusive_group()
    group.add_argument('--app')
    group.add_argument('--pid', type=int)
    group.add_argument('--name')
    group.required = True

    parser = argparse.ArgumentParser(description='frida driver')
    parser.add_argument('--remote', type=str)
    subparsers = parser.add_subparsers(dest='action', required=True)
    subparsers.add_parser('devices')
    subparsers.add_parser('apps', parents=[requires_device])
    subparsers.add_parser('ps', parents=[requires_device])
    subparsers.add_parser('info', parents=[requires_device])
    subparsers.add_parser('type', parents=[requires_device])
    subparsers.add_parser('ssh-copy-id', parents=[requires_device])
    subparsers.add_parser('sign-debugserver', parents=[requires_device])
    location_parser = subparsers.add_parser('location', parents=[requires_device])
    location_parser.add_argument('bundle')

    rpc_parser = subparsers.add_parser('rpc', parents=[requires_app])
    rpc_parser.add_argument('method')
    rpc_parser.add_argument('args', metavar='N', nargs='*', default=[])

    subparsers.add_parser('syslog', parents=[requires_app])
    subparsers.add_parser('syslog2', parents=[requires_app])

    args = parser.parse_args()

    if 'DEBUG' in os.environ or args.action == 'syslog2':
        result = main(args)
    else:
        try:
            result = main(args)
        except Exception as e:
            sys.stderr.write('%s\n' % e)
            sys.exit(-1)

    import json
    if args.action not in ['syslog', 'download', 'upload']:
        print(json.dumps(result))
