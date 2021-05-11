import subprocess
import zipfile
import stat
import struct
from copy import deepcopy
from pathlib import Path
from tempfile import NamedTemporaryFile


from base import BaseTool


FAT_MAGIC = 0xcafebabe
FAT_CIGAM = 0xbebafeca
MH_MAGIC = 0xfeedface
MH_CIGAM = 0xcefaedfe
MH_MAGIC_64 = 0xfeedfacf
MH_CIGAM_64 = 0xcffaedfe


class Repack(BaseTool):
    def __init__(self, src: Path, dst: Path, base: Path, port: int, host='localhost', user='root'):
        super().__init__(port, host, user)

        self.src = src
        self.dst = dst
        self.base = base

        self.zin: zipfile.ZipFile = None
        self.zout: zipfile.ZipFile = None
        self.info: zipfile.ZipInfo = None

    def go(self):
        with zipfile.ZipFile(self.src, 'r') as zin, zipfile.ZipFile(self.dst, 'w') as zout:
            for info in zin.infolist():
                self.zin, self.zout = zin, zout
                self.handle_entry(info)

    def handle_macho(self, info: zipfile.ZipInfo, new_info: zipfile.ZipInfo):
        abspath = '/' + info.filename
        with NamedTemporaryFile() as tmpf:
            tmp = tmpf.name

        remote_tmp = subprocess.check_output(self.ssh('mktemp')).decode().strip()
        escaped = '"' + abspath.replace('"', '\\"') + '"'
        subprocess.call(
            self.ssh('/usr/bin/flexdecrypt', escaped, '--output', remote_tmp))
        subprocess.call(self.scp(remote_tmp, tmp))
        subprocess.call(self.ssh('rm', remote_tmp))
        with open(tmp, 'rb') as fp:
            self.zout.writestr(new_info, fp.read())
        Path(tmp).unlink()

    def handle_entry(self, info: zipfile.ZipInfo):
        abspath = '/' + info.filename.encode('cp437').decode('utf8')
        new_file = Path('Payload') / \
            Path(abspath).relative_to(self.base.parent)
        file_mod = info.external_attr >> 16
        new_info = deepcopy(info)
        new_info.filename = Path.as_posix(new_file)

        if stat.S_ISDIR(file_mod):
            # do nothing
            # self.zout.writestr(new_info, b'')
            return

        elif stat.S_ISREG(file_mod) and (file_mod & stat.S_IXUSR):
            with self.zin.open(info, 'r') as fp:
                buf = fp.read(4)
                if len(buf) == 4:
                    magic, = struct.unpack('I', buf)
                    # only enterprise apps are FAT
                    # these apps are not DRM-protected at all
                    if magic in (MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64):
                        self.handle_macho(info, new_info)
                        return

        # copy as is
        self.zout.writestr(new_info, self.zin.read(info))


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('archive')
    parser.add_argument('app')
    parser.add_argument('port', type=int)

    parser.add_argument('-o', '--output', dest='output', action='store')
    parser.add_argument('-H', '--host', dest='host', action='store')
    parser.add_argument('-u', '--user', dest='user', action='store')

    opt = parser.parse_args()

    src = Path(opt.archive)
    dst = Path(opt.output) if opt.output else src.with_suffix('.ipa')
    base = Path(opt.app)

    if opt.host and opt.user:
        r = Repack(src, dst, base, opt.port, host=opt.host, user=opt.user)
    else:
        r = Repack(src, dst, base, opt.port)

    r.go()
