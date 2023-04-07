from pathlib import Path
import time
import tempfile

try:
    import frida
except ImportError:
    import sys
    sys.stderr.write('Unable to import frida. Please ensure you have installed frida-tools via pip\n')
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
        ps = device.enumerate_processes()
    return [wrap(p) for p in ps]


def find_port(device: frida.core.Device) -> int:
    pid = device.spawn('/bin/sh')
    session = device.attach(pid)
    with (Path(__file__).parent.parent / 'agent' / 'socket.js').open('r', encoding='utf8') as fp:
        source = fp.read()
    script = session.create_script(source)
    script.load()
    return script.exports.find()


def os_id(device: frida.core.Device) -> bool:
    return device_info(device).get('os', {}).get('id')


def device_info(device: frida.core.Device) -> dict:
    return device.query_system_parameters()


def find_app(device: frida.core.Device, bundle: str):
    try:
        app = next(app for app in device.enumerate_applications()
                   if app.identifier == bundle)
    except StopIteration:
        raise ValueError('app "%s" not found' % bundle)

    return app


def spawn_or_attach(device: frida.core.Device, bundle: str) -> frida.core.Session:
    app = find_app(device, bundle)

    if app.pid > 0:
        frontmost = device.get_frontmost_application()
        if frontmost and frontmost.identifier == bundle:
            return device.attach(app.pid)

        device.kill(app.pid)

    pid = device.spawn(bundle)
    session = device.attach(pid)
    device.resume(pid)
    return session


def read_agent():
    filename = Path(__file__).parent.parent / 'agent' / '_agent.js'
    with (filename).open('r', encoding='utf8', newline='\n') as fp:
        return fp.read()
