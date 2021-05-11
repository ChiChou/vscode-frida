import frida
from pathlib import Path
from backend.core import device_type, read_agent

def installed(device: frida.core.Device):
    try:
        pid = device.spawn('/usr/bin/debugserver')
    except frida.ExecutableNotFoundError:
        return False

    device.kill(pid)
    return True

def setup(device: frida.core.Device):
    if device_type(device) != 'iOS':
        raise ValueError('This command is for iOS only')

    if installed(device):
        return True

    with (Path(__file__).parent / 'ent.xml').open('r') as fp:
        content = fp.read()

    pid = device.spawn('/bin/sh')
    session = device.attach(pid)
    script = session.create_script(read_agent())
    script.load()
    script.exports.sign_debugserver(content)
    session.detach()
    device.kill(pid)

    return True