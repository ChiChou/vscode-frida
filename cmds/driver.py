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


class Driver(object):
    def __init__(self):
        pass

    def devices(self):
        props = ['id', 'name', 'type']

        def wrap(dev):
            obj = {prop: getattr(dev, prop) for prop in props}
            obj['icon'] = png.to_uri(dev.icon)
            return obj

        return [wrap(dev) for dev in frida.enumerate_devices()]

    def apps(self, id):
        dev = frida.get_device(id)
        props = ['identifier', 'name', 'pid']

        def wrap(app):
            obj = {prop: getattr(app, prop) for prop in props}
            obj['icon'] = png.to_uri(app.get_small_icon())
            return obj

        return [wrap(app) for app in dev.enumerate_applications()]

    def ps(self, id):
        dev = frida.get_device(id)
        props = ['name', 'pid']

        def wrap(p):
            obj = {prop: getattr(p, prop) for prop in props}
            obj['icon'] = icon_str(p.get_small_icon())
            return obj

        return [wrap(p) for p in dev.enumerate_processes()]


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='frida driver')
    parser.add_argument('action')
    parser.add_argument('args', metavar='N', nargs='*', default=[])
    args = parser.parse_args()

    driver = Driver()
    if hasattr(driver, args.action):
        method = getattr(driver, args.action)
    # try:
        result = method(*args.args)
        print(json.dumps(result))
        sys.exit(0)
    # except Exception as e:
    #     print(e)

    sys.exit(-1)
