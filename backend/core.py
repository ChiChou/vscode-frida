from pathlib import Path
import time
import tempfile
import base64

try:
    import frida
except ImportError:
    import sys
    sys.stderr.write(
        'Unable to import frida. Please ensure you have installed frida-tools via pip\n')
    sys.exit(-1)


def devices() -> list:
    props = ['id', 'name', 'type']

    def wrap(dev: frida.core.Device):
        obj = {prop: getattr(dev, prop) for prop in props}
        os = 'unknown'
        try:
            os = dev.query_system_parameters()['os']['id']
        except:
            # frida.ServerNotRunningError, KeyError, 
            # frida.TransportError, frida.NotSupportedError, 
            # frida.ProtocolError
            pass

        obj['os'] = os
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


PROCESS_PARAMETER_KEYS = (
    'path',
    'user',
    'uid',
    'gid',
    'ppid',
    'argv',
    'started',
    'current_directory',
    'cwd',
)


def info_wrap(props, fmt, metadata_status='full', metadata_error=None, include_context=False):
    def wrap(target):
        obj = {prop: getattr(target, prop) for prop in props}

        params = getattr(target, 'parameters', {}) or {}
        icons = params.get('icons', [])
        try:
            icon = next(icon for icon in icons if icon.get('format') == 'png')
            data = icon['image']
            obj['icon'] = 'data:image/png;base64,' + \
                base64.b64encode(data).decode('ascii')
        except StopIteration:
            pass

        if include_context:
            details = {}
            for key in PROCESS_PARAMETER_KEYS:
                if key not in params:
                    continue
                value = params[key]
                if value is not None:
                    details[key] = value

            if details:
                obj['parameters'] = details

            obj['path'] = details.get('path') or ''
            obj['cwd'] = details.get('current_directory') or details.get('cwd') or ''
            obj['user'] = details.get('user') or ''
            obj['ppid'] = details.get('ppid') or 0
            obj['argv'] = details.get('argv') or []
            obj['metadataStatus'] = metadata_status
            obj['metadataError'] = metadata_error or ''

        return obj

    return wrap


def apps(device: frida.core.Device) -> list:
    props = ['identifier', 'name', 'pid']

    def fmt(app):
        return '%s-%s' % (device.id, app.pid or app.identifier)
    wrap = info_wrap(props, fmt)
    try:
        apps = device.enumerate_applications(scope='full')
    except frida.TransportError:
        apps = device.enumerate_applications()
    return [wrap(app) for app in apps]


def ps(device: frida.core.Device) -> list:
    props = ['name', 'pid']

    def fmt(p):
        return '%s-%s' % (device.id, p.name or p.pid)

    try:
        processes = device.enumerate_processes(scope='full')
        wrap = info_wrap(props, fmt, include_context=True)
    except Exception as e:
        processes = device.enumerate_processes()
        wrap = info_wrap(
            props,
            fmt,
            metadata_status='limited',
            metadata_error=str(e),
            include_context=True,
        )
    return [wrap(p) for p in processes]


def device_info(device: frida.core.Device) -> dict:
    params = device.query_system_parameters()
    params['frida'] = frida.__version__
    params['device'] = {
        'id': device.id,
        'name': device.name,
        'type': device.type,
    }
    return params


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
    agent_path = Path(__file__).parent.parent / 'agent' / '_agent.js'
    with agent_path.open('r', encoding='utf8', newline='\n') as fp:
        return fp.read()
