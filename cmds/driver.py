#!/usr/bin/env python3

import json
import sys

from io import BytesIO
from functools import wraps

try:
    import frida
except ImportError:
    print('Unable to import frida. Please ensure you have installed frida-tools via pip')
    sys.exit(-1)

from utils import read_agent

# from pathlib import Path
# sys.path.insert(0, str(Path(__file__).parent))

import png


allowed = set()


def cli(fn):
    allowed.add(fn.__name__)

    @wraps(fn)
    def wrapped(*args, **kwargs):
        return fn(*args, **kwargs)
    return wrapped


def agent(fn):
    @wraps(fn)
    def wrapped(self, *args, **kwargs):
        self.load_agent()
        func = getattr(self.agent, fn.__name__)
        return func(*args)
        # result = f(self, *args, **kwargs)
    return wrapped


def device(fn):
    @wraps(fn)
    def wrapped(self, *args, **kwargs):
        self.get_device()
        return fn(self, *args, **kwargs)
    return wrapped


class Driver(object):
    def __init__(self, device, app, pid):
        self.device_id = device
        if pid:
            self.target = pid
        elif app:
            self.target = app

        self.device = None

    def get_device(self):
        if self.device_id == 'usb':
            self.device = frida.get_usb_device()
        else:
            self.device = frida.get_device(self.device_id)

    @cli
    def devices(self):
        props = ['id', 'name', 'type']

        def wrap(dev):
            obj = {prop: getattr(dev, prop) for prop in props}
            obj['icon'] = png.to_uri(dev.icon)
            return obj

        return [wrap(dev) for dev in frida.enumerate_devices()]

    @cli
    @device
    def apps(self):
        props = ['identifier', 'name', 'pid']

        def wrap(app):
            obj = {prop: getattr(app, prop) for prop in props}
            obj['largeIcon'] = png.to_uri(app.get_large_icon())
            obj['smallIcon'] = png.to_uri(app.get_small_icon())
            return obj

        return [wrap(app) for app in self.device.enumerate_applications()]

    @cli
    @device
    def ps(self):
        props = ['name', 'pid']

        def wrap(p):
            obj = {prop: getattr(p, prop) for prop in props}
            obj['largeIcon'] = png.to_uri(p.get_large_icon())
            obj['smallIcon'] = png.to_uri(p.get_small_icon())
            return obj

        return [wrap(p) for p in self.device.enumerate_processes()]

    @cli
    @agent
    def fs(self, method, path):
        pass

    @cli
    @device
    def devtype(self):
        mapping = {
            'SpringBoard': 'iOS',
            'Dock': 'macOS',
            'explorer.exe': 'win32',
            'zygote': 'Android',
        }

        for proc in self.device.enumerate_processes():
            if proc.name in mapping:
                return mapping[proc.name]
        else:
            return 'Linux'

    def load_agent(self):
        self.get_device()
        self.session = self.device.attach(self.target)

        source = read_agent()
        script = self.session.create_script(source)
        script.load()
        self.agent = script.exports


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='frida driver')
    parser.add_argument('action')
    parser.add_argument('--device')
    parser.add_argument('--app')
    parser.add_argument('--pid', type=int)
    parser.add_argument('args', metavar='N', nargs='*', default=[])
    parser.add_argument('--test', default=False, action='store_true')
    args = parser.parse_args()

    driver = Driver(device=args.device, app=args.app, pid=args.pid)
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
