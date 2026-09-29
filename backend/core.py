from pathlib import Path
import time
import tempfile
import base64
import plistlib
import re
import subprocess

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
        params = {}
        try:
            params = dev.query_system_parameters()
            os = params['os']['id']
        except:
            # frida.ServerNotRunningError, KeyError, 
            # frida.TransportError, frida.NotSupportedError, 
            # frida.ProtocolError
            pass

        obj['os'] = os
        obj['type'] = device_type(dev, params)
        return obj

    # workaround
    try:
        frida.get_usb_device(1)
    except:
        pass

    return [wrap(dev) for dev in frida.enumerate_devices()]


def device_type(device: frida.core.Device, params: dict) -> str:
    """Return the extension's device type for a Frida device.

    Frida exposes Simulator devices through a provider whose low-level type is
    ``remote``. Unlike a remote frida-server (whose ID is ``socket@HOST``), the
    Simulator provider reports the Simulator UDID as both its ID and its
    ``udid`` system parameter.
    """
    os_id = params.get('os', {}).get('id')
    if device.type == 'remote' and os_id == 'ios' and params.get('udid') == device.id:
        return 'simulator'
    return device.type


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
    try:
        params = device.query_system_parameters()
    except Exception:
        params = {}

    if device_type(device, params) == 'simulator':
        return simulator_apps(device.id)

    props = ['identifier', 'name', 'pid']

    def fmt(app):
        return '%s-%s' % (device.id, app.pid or app.identifier)
    wrap = info_wrap(props, fmt)
    try:
        apps = device.enumerate_applications(scope='full')
    except frida.TransportError:
        apps = device.enumerate_applications()
    return [wrap(app) for app in apps]


def simulator_apps(device_id: str) -> list:
    """List Simulator apps without Frida's blocking Simmy app query.

    Some Simulator states leave both Frida's application query and
    ``simctl listapps`` waiting indefinitely. The bundle metadata on disk and
    launchd's running jobs contain everything the extension needs for its app
    tree and remain available in that state.
    """
    runtime = subprocess.run(
        ['xcrun', 'simctl', 'getenv', device_id, 'SIMULATOR_ROOT'],
        check=True,
        capture_output=True,
        text=True,
        timeout=5,
    ).stdout.strip()

    device_root = Path.home() / 'Library' / 'Developer' / 'CoreSimulator' / 'Devices' / device_id / 'data'
    info_paths = list((Path(runtime) / 'Applications').glob('*.app/Info.plist'))
    info_paths.extend((device_root / 'Containers' / 'Bundle' / 'Application').glob('*/*.app/Info.plist'))

    pids = simulator_app_pids(device_id)
    result = {}
    for info_path in info_paths:
        try:
            with info_path.open('rb') as fp:
                info = plistlib.load(fp)
        except (OSError, plistlib.InvalidFileException):
            continue

        identifier = info.get('CFBundleIdentifier')
        if not identifier or 'hidden' in info.get('SBAppTags', []):
            continue

        name = info.get('CFBundleDisplayName') or info.get('CFBundleName') or info_path.parent.stem
        result[identifier] = {
            'identifier': identifier,
            'name': name,
            'pid': pids.get(identifier, 0),
        }

    return sorted(result.values(), key=lambda app: (app['name'].casefold(), app['identifier']))


def simulator_app_pids(device_id: str) -> dict:
    try:
        output = subprocess.run(
            ['xcrun', 'simctl', 'spawn', device_id, 'launchctl', 'list'],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return {}

    pids = {}
    pattern = re.compile(r'^(\d+)\s+\S+\s+UIKitApplication:([^\[]+)\[')
    for line in output.splitlines():
        match = pattern.match(line)
        if match:
            pids[match.group(2)] = int(match.group(1))
    return pids


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
        'type': device_type(device, params),
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
