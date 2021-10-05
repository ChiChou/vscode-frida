from pathlib import Path
import time
import tempfile

try:
    import frida
except ImportError:
    print('Unable to import frida. Please ensure you have installed frida-tools via pip')
    import sys
    sys.exit(-1)


from backend import png


def devices() -> list:
    props = ['id', 'name', 'type']

    def wrap(dev):
        obj = {prop: getattr(dev, prop) for prop in props}
        obj['icon'] = png.to_uri(dev.icon)
        return obj

    # workaround
    try:
        frida.get_usb_device(1)
    except:
        pass

    return [wrap(dev) for dev in frida.enumerate_devices()]


def get_device(device_id: str) -> frida.core.Device:
    if device_id == 'usb':
        return frida.get_usb_device(1)
    elif device_id == 'local':
        return frida.get_local_device()
    else:
        return frida.get_device(device_id, timeout=1)


def tmpicon(uid: str, params: dict):
    parent = Path(tempfile.gettempdir()) / '.vscode-frida'
    parent.mkdir(parents=True, exist_ok=True)

    icons = params.get('icons', [])
    tmp = parent / ('icon-%s.png' % uid)
    for icon in icons:
        if icon.get('format') == 'png':
            with tmp.open('wb') as fp:
                fp.write(icon['image'])
            return tmp.as_uri()
    return None


def info_wrap(props, fmt):
    def wrap(target):
        obj = {prop: getattr(target, prop) for prop in props}
        
        # is new API?
        params = getattr(target, 'parameters')
        try:
            obj['largeIcon'] = png.to_uri(target.get_large_icon())
            obj['smallIcon'] = png.to_uri(target.get_small_icon())
        except AttributeError:
            if params is None:
                raise RuntimeError('frida (%s) not compatable' % frida.__version__)
            obj['largeIcon'] = tmpicon(fmt(target), params)
        return obj

    return wrap


def apps(device: frida.core.Device) -> list:
    props = ['identifier', 'name', 'pid']

    def fmt(app):
        return '%s-%s' % (device.id, app.pid or app.identifier)
    wrap = info_wrap(props, fmt)
    try:
        apps = device.enumerate_applications(scope='full')
    except TypeError:
        raise RuntimeError('Your frida python package is out of date. Please upgrade it')
    except frida.TransportError:
        apps = device.enumerate_applications()
    return [wrap(app) for app in apps]


def ps(device: frida.core.Device) -> list:
    props = ['name', 'pid']

    def fmt(p):
        return '%s-%s' % (device.id, p.name or p.pid)
    wrap = info_wrap(props, fmt)

    try:
        ps = device.enumerate_processes(scope='full')
    except TypeError:
        raise RuntimeError('Your frida python package is out of date. Please upgrade it')
    except frida.TransportError:
        apps = device.enumerate_processes()
    return [wrap(p) for p in ps]


def find_port(device: frida.core.Device) -> int:
    pid = device.spawn('/bin/sh')
    session = device.attach(pid)
    with (Path(__file__).parent.parent / 'agent' / 'socket.js').open('r', encoding='utf8') as fp:
        source = fp.read()
    script = session.create_script(source)
    script.load()
    return script.exports.find()


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
        if device.get_frontmost_application(identifiers=[bundle]):
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
