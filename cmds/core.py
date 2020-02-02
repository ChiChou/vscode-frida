from pathlib import Path
import time

try:
    import frida
except ImportError:
    print('Unable to import frida. Please ensure you have installed frida-tools via pip')
    sys.exit(-1)


from cmds import png


def devices() -> list:
    props = ['id', 'name', 'type']

    def wrap(dev):
        obj = {prop: getattr(dev, prop) for prop in props}
        obj['icon'] = png.to_uri(dev.icon)
        return obj

    return [wrap(dev) for dev in frida.enumerate_devices()]


def get_device(device_id: str) -> frida.core.Device:
    frida.get_usb_device().spawn
    if device_id == 'usb':
        return frida.get_usb_device()
    elif device_id == 'local':
        return frida.get_local_device()
    else:
        return frida.get_device(device_id)


def apps(device: frida.core.Device) -> list:
    props = ['identifier', 'name', 'pid']

    def wrap(app):
        obj = {prop: getattr(app, prop) for prop in props}
        obj['largeIcon'] = png.to_uri(app.get_large_icon())
        obj['smallIcon'] = png.to_uri(app.get_small_icon())
        return obj

    return [wrap(app) for app in device.enumerate_applications()]


def ps(device: frida.core.Device) -> list:
    props = ['name', 'pid']

    def wrap(p):
        obj = {prop: getattr(p, prop) for prop in props}
        obj['largeIcon'] = png.to_uri(p.get_large_icon())
        obj['smallIcon'] = png.to_uri(p.get_small_icon())
        return obj

    return [wrap(p) for p in device.enumerate_processes()]


def device_type(device: frida.core.Device) -> str:
    mapping = {
        'SpringBoard': 'iOS',
        'Dock': 'macOS',
        'explorer.exe': 'win32',
        'zygote': 'Android',
    }

    for proc in device.enumerate_processes():
        if proc.name in mapping:
            return mapping[proc.name]
    else:
        return 'Linux'


def spawn_or_attach(device: frida.core.Device, bundle: str) -> frida.core.Session:
    try:
        app = next(app for app in device.enumerate_applications()
                   if app.identifier == bundle)
    except StopIteration:
        raise ValueError('app "%s" not found' % bundle)

    if app.pid > 0:
        front = device.get_frontmost_application()
        if front and front.identifier == bundle:
            return device.attach(app.pid)

        raise RuntimeError(
            'Unable to attach to "%s"(%d) as it is a background app.' % (bundle, app.pid))

    devtype = device_type(device)
    if devtype == 'Android':
        module = 'libc.so'
    elif devtype == 'iOS':
        module = 'Foundation'
    else:
        raise RuntimeError('Unknown device type %s' % devtype)

    source = 'Module.ensureInitialized("%s"); rpc.exports.ok = function() { return true }' % module
    pid = device.spawn(bundle)
    session = device.attach(pid)
    device.resume(pid)
    script = session.create_script(source)
    script.load()
    MAX_RETRY = 5
    for i in range(MAX_RETRY):
        try:
            time.sleep(0.2)
            if script.exports.ok():
                break
        except:
            continue
    else:
        raise RuntimeError('Unable to create process')

    script.unload()
    return session


# TODO: rename _agent.js
def read_agent():
    with (Path(__file__).parent.parent / 'agent' / '_agent.js').open('r', encoding='utf8') as fp:
        return fp.read()
