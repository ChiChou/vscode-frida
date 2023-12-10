#!/usr/bin/env python3

import logging
import urllib.request
import json
import lzma
import shutil
from pathlib import Path

MAPPING = {
    'x86': 'x86',
    'x86_64': 'x86_64',
    'arm64-v8a': 'arm64',
    'armeabi-v7a': 'arm',
}

RELEASE_URL = 'https://api.github.com/repos/frida/frida/releases/latest'


def download(abi: str, path: Path):
    try:
        arch = MAPPING[abi]
    except KeyError:
        raise RuntimeError('Unknown ABI: %s' % abi)

    suffix = '-android-%s.xz' % arch
    with urllib.request.urlopen(RELEASE_URL) as response:
        info = json.loads(response.read())

    for asset in info['assets']:
        name = asset['name']
        logging.debug('asset: %s', name)
        if name.startswith('frida-server') and name.endswith(suffix):
            url = asset['browser_download_url']
            break
    else:
        raise RuntimeError('Unable to find frida-server for %s' % arch)

    logging.debug('downloading %s to %s', url, path)
    with urllib.request.urlopen(url) as response:
        with lzma.LZMAFile(response) as archive:
            with path.open('wb') as fp:
                shutil.copyfileobj(archive, fp)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 3:
        print('usage: %s <abi> <path>' % sys.argv[0])
        sys.exit(1)

    abi = sys.argv[1]
    path = sys.argv[2]

    download(abi, Path(path))
