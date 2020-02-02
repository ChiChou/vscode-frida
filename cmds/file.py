import sys
import base64


from cmds.fs import FileSystem


def upload(fs: FileSystem, path: str):
    data = []
    while True:
        buf = sys.stdin.buffer.read()
        if not buf:
            break
        data.append(buf)

    fs.write(path, data)


def download(fs: FileSystem, path: str):
    sys.stdout.buffer.write(fs.read(path))
