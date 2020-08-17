#!/usr/bin/env python3

'''ssh-copy-id in frida'''

import frida
from pathlib import Path
from backend.core import device_type, read_agent


def install(device: frida.core.Device):
    pubkey = Path.home() / '.ssh' / 'id_rsa.pub'
    if not (pubkey.exists() and pubkey.is_file()):
        raise RuntimeError('id_rsa.pub does not exists')

    with pubkey.open('r') as fp:
        content = fp.read().strip()
    
    if device_type(device) != 'iOS':
        raise ValueError('This command is for iOS only')

    pid = device.spawn('/bin/sh')
    session = device.attach(pid)
    script = session.create_script(read_agent())
    script.load()
    script.exports.copyid(content)
    session.detach()
    device.kill(pid)

    return True

