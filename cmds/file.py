import sys
import frida
import utils
import base64

SIZE = 16 * 1024


class Task(object):
    def __init__(self, device_id: str, target, path: str):
        self.target = target
        self.device = utils.get_device(device_id)
        self.path = path

    def connect(self):
        source = utils.read_agent()
        self.session = session = self.device.attach(target)
        self.script = script = session.create_script(source)

        def on_message(message, data):
            sys.stdout.buffer.write(data)
            sys.stdout.flush()

        script.on('message', on_message)

        def on_detach(reason):
            if reason == 'application-requested':
                return

            sys.stderr.write('[FATAL Error] target disconnected (%s)' % reason)
            sys.exit(-1)

        session.on('detached', on_detach)
        script.load()

    def download(self):
        encoded = self.script.exports.fs('read', self.path)
        sys.stdout.buffer.write(base64.b64decode(encoded))

    def upload(self):
        data = []
        while True:
            buf = sys.stdin.buffer.read()
            if not buf:
                break
            data.append(buf)

        encoded = base64.b64encode(b''.join(data)).decode()
        self.script.exports.fs('write', self.path, encoded)
        
    def leave(self):
        self.session.detach()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='frida driver')
    parser.add_argument('action')
    parser.add_argument('device')
    parser.add_argument('path')
    parser.add_argument('--app')
    parser.add_argument('--pid', type=int)

    args = parser.parse_args()
    if args.pid and args.app:
        raise ValueError('either --app nor --pid is allowed')

    target = args.pid or args.app

    if target:
        task = Task(args.device, target, args.path)
        task.connect()
        if args.action == 'upload':
            task.upload()
        else:
            task.download()
        task.leave()
    else:
        parser.print_help()
        sys.exit(-1)
