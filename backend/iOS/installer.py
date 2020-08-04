import frida
import struct
import plistlib


class InstallationProxy(object):
    def __init__(self, device: frida.core.Device):
        self.dev = device
        self.pipe = None

    def __enter__(self):
        self.pipe = self.dev.open_channel(
            'lockdown:com.apple.mobile.installation_proxy')
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.pipe.close()

    def write(self, msg):
        buf = plistlib.dumps(msg, fmt=plistlib.FMT_BINARY)
        self.pipe.write_all(struct.pack('>I', len(buf)))
        self.pipe.write_all(buf)

    def read(self):
        size, = struct.unpack('>L', self.pipe.read(4))
        response = self.pipe.read_all(size)
        return plistlib.loads(response)

    def close(self):
        self.pipe.close()


def apps(device: frida.core.Device):
    with InstallationProxy(device) as channel:
        channel.write({
            'Command': 'Browse',
            'ClientOptions': {
                # comment this out to list all apps
                # 'ApplicationType': 'User'
            }
        })

        while True:
            response = channel.read()
            if response['Status'] == 'BrowsingApplications':
                for app in response['CurrentList']:
                    yield app

            elif response['Status'] == 'Complete':
                break

