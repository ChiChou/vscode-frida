from pathlib import Path
import frida

def read_agent():
    with (Path(__file__).parent.parent / 'agent' / '_agent.js').open('r', encoding='utf8') as fp:
        return fp.read()

def get_device(device_id):
    if device_id == 'usb':
        return frida.get_usb_device()
    elif device_id == 'local':
        return frida.get_local_device()
    else:
        return frida.get_device(device_id)
