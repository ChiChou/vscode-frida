#!/usr/bin/env python3

import json
import sys

from io import BytesIO

try:
    import frida
except ImportError:
    print('Unable to import frida. Please ensure you have installed frida-tools via pip')
    sys.exit(-1)

# from pathlib import Path
# sys.path.insert(0, str(Path(__file__).parent))

import png


allowed = set()

def cli(f):
    allowed.add(f.__name__)
    def wrapper(*args):
        return f(*args)
    return wrapper


class Driver(object):
    def __init__(self):
        pass

    @cli
    def devices(self):
        props = ['id', 'name', 'type']

        def wrap(dev):
            obj = {prop: getattr(dev, prop) for prop in props}
            obj['icon'] = png.to_uri(dev.icon)
            return obj

        return [wrap(dev) for dev in frida.enumerate_devices()]

    @cli
    def apps(self, device):
        dev = frida.get_device(device)
        props = ['identifier', 'name', 'pid']

        def wrap(app):
            obj = {prop: getattr(app, prop) for prop in props}
            obj['largeIcon'] = png.to_uri(app.get_large_icon())
            obj['smallIcon'] = png.to_uri(app.get_small_icon())
            return obj

        return [wrap(app) for app in dev.enumerate_applications()]

    @cli
    def ps(self, device):
        dev = frida.get_device(device)
        props = ['name', 'pid']

        def wrap(p):
            obj = {prop: getattr(p, prop) for prop in props}
            obj['largeIcon'] = png.to_uri(p.get_large_icon())
            obj['smallIcon'] = png.to_uri(p.get_small_icon())
            return obj

        return [wrap(p) for p in dev.enumerate_processes()]
    
    @cli
    def ls(self, device, bundle, path):
        self.attach(device, bundle)
        self.load_agent()
        return self.agent.ls(path)

    def attach(self, device, target):
        self.dev = frida.get_device(device)
        self.session = self.dev.attach(target)
        
    def load_agent(self):
        from pathlib import Path
        with (Path(__file__).parent.parent / 'agent' / '_agent.js').open('r') as fp:
            source = fp.read()

        script = self.session.create_script(source)
        script.load()
        self.agent = script.exports
        

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='frida driver')
    parser.add_argument('action')
    parser.add_argument('args', metavar='N', nargs='*', default=[])
    parser.add_argument('--test', default=False, action='store_true')
    args = parser.parse_args()

    driver = Driver()
    if args.action in allowed:
        method = getattr(driver, args.action)
    else:
        raise ValueError('Unknown action "%s"' % args.action)

    if not args.test:
        try:
            result = method(*args.args)
            print(json.dumps(result))
            sys.exit(0)
        except Exception as e:
            print(e)
            sys.exit(-1)
    else:
        result = method(*args.args)
        print(result)
