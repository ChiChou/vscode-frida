#!/usr/bin/env python3

import subprocess
import urllib.request
import json
import shutil
import tempfile
from pathlib import Path


class Downloader(object):
    def __init__(self, uuid):
        self.uuid = uuid

    def adb(self, *args):
        final_args = ['adb']
        if self.uuid:
            final_args += ['-s', self.uuid]
        final_args += args
        return subprocess.check_output(final_args).strip().decode()

    def download(self):
        mapping = {
            'x86': 'x86',
            'x86_64': 'x86_64',
            'arm64-v8a': 'arm64',
            'armeabi-v7a': 'arm',
        }

        arch = mapping[self.adb('shell', 'getprop', 'ro.product.cpu.abi')]
        suffix = '-android-%s.tar.xz' % arch
        with urllib.request.urlopen('https://api.github.com/repos/frida/frida/releases/latest') as response:
            info = json.loads(response.read())

        for asset in info['assets']:
            name = asset['name']
            if name.endswith(suffix):
                url = asset['browser_download_url']
                break
        else:
            raise RuntimeError('Unable to find frida-server for %s' % arch)

        print('download frida-server')
        tmp = Path(tempfile.gettempdir()) / name
        with urllib.request.urlopen(url) as response, tmp.open('wb') as fp:
            shutil.copyfileobj(response, fp)

        self.adb('push', tmp, '/data/local/tmp/frida-server')

    def start(self):
        self.adb('shell', '/data/local/tmp/frida-server')


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-i', '--uuid', help='uuid of the device', required=False)
    args = parser.parse_args()

    d = Downloader(args.uuid)
    d.download()
