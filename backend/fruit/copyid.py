'''ssh-copy-id in frida'''

import frida
from pathlib import Path
from backend.core import os_id, read_agent


def install(device: frida.core.Device):
    if os_id(device) != 'ios':
        raise ValueError('This command is for iOS only')
    
    pubkey = Path.home() / '.ssh' / 'id_rsa.pub'
    if not (pubkey.exists() and pubkey.is_file()):
        raise RuntimeError('id_rsa.pub does not exist')

    with pubkey.open('r') as fp:
        content = fp.read().strip()

    pid = device.spawn('/bin/sh')
    session = device.attach(pid)
    script = session.create_script(read_agent())
    script.load()
    script.exports.copyid(content)
    session.detach()
    device.kill(pid)

    return True

