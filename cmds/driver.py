#!/usr/bin/env python3

import base64
import json
import sys

try:
    import frida
except ImportError:
    print('Unable to import frida. Please ensure you have installed frida-tools via pip')
    sys.exit(-1)


def icon_str(icon):
    if not icon:
        return None

    return base64.b64encode(icon.pixels).decode('ascii')


class Driver(object):
    def __init__(self):
        pass

    def devices(self):
        props = ['id', 'name', 'type']

        def wrap(dev):
            obj = {prop: getattr(dev, prop) for prop in props}
            obj['icon'] = icon_str(dev.icon)
            return obj

        return [wrap(dev) for dev in frida.enumerate_devices()]

    def apps(self, id):
        dev = frida.get_device(id)
        props = ['identifier', 'name', 'pid']

        def wrap(app):
            obj = {prop: getattr(app, prop) for prop in props}
            obj['icon'] = icon_str(app.get_small_icon())
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
        result = method(*args.args)
        print(json.dumps(result))
    else:
        sys.exit(-1)
