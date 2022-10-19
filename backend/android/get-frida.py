#!/usr/bin/env python3

import subprocess
import urllib.request
import json
import lzma
import shutil
import tempfile
from pathlib import Path

dst = '/data/local/tmp/frida-server'

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
        suffix = '-android-%s.xz' % arch

        with urllib.request.urlopen('https://api.github.com/repos/frida/frida/releases/latest') as response:
            info = json.loads(response.read())

        for asset in info['assets']:
            name = asset['name']
            print(name)
            if name.startswith('frida-server') and name.endswith(suffix):
                url = asset['browser_download_url']
                break
        else:
            raise RuntimeError('Unable to find frida-server for %s' % arch)

        print('download frida-server')

        tmp = Path(tempfile.gettempdir()) / 'frida-server'
        with urllib.request.urlopen(url) as response:
            with lzma.LZMAFile(response) as archive:
                with tmp.open('wb') as fp:
                    shutil.copyfileobj(archive, fp)

        self.adb('push', tmp, dst)

    def start(self):
        if not self.sanity_check():
            self.download()
            self.adb('shell', 'chmod 0755 %s' % dst)
        self.adb('shell', dst)

    def sanity_check(self):
        try:
            self.adb('shell', '%s --version' % dst)
        except:
            return False

        return True


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-i', '--uuid', help='uuid of the device', required=False)
    args = parser.parse_args()

    d = Downloader(args.uuid)
    d.start()
