import frida
import struct
import plistlib


class InstallationProxy(object):
    def __init__(self):
        self.dev = frida.get_usb_device()
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


def apps():
    with InstallationProxy() as channel:
        channel.write({
            'Command': 'Browse',
            'ClientOptions': {
                'ApplicationType': 'User'
            }
        })
        response = channel.read()
        return response['CurrentList']


def main(bundle):
    try:
        root = next(app['Path'] for app in apps() if app['CFBundleIdentifier'] == bundle)
        print(root)
    except StopIteration:
        import sys
        sys.stderr.write('%s not found' % bundle)
        sys.exit(255)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('bundle')
    opt = parser.parse_args()

    main(opt.bundle)
