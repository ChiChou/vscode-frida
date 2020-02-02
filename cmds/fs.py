import json
from functools import wraps
from cmds.rpc import BaseAgent
import base64


def stub(fn):
    @wraps(fn)
    def wrapped(self, *args, **kwargs):
        return self.call(fn.__name__, *args)
    return wrapped


class FileSystem(object):
    def __init__(self, agent: BaseAgent):
        self.agent = agent

    def call(self, *args):
        return self.agent.invoke('fs', *args)

    def cp(self, src: str, dst: str, opt_str: str = ''):
        opt = json.loads(opt_str) if opt_str else {}
        return self.call('copy', src, dst, opt)

    @stub
    def mkdir(self, uri: str):
        pass

    def rm(self, uri: str, opt_str: str = ''):
        opt = json.loads(opt_str) if opt_str else {}
        return self.call('rm', uri, opt)

    @stub
    def ls(self, uri: str):
        pass

    def read(self, uri: str) -> bytes:
        encoded = self.call('read', uri)
        return base64.b64decode(encoded)

    def mv(self, src: str, dst: str, opt_str: str = ''):
        opt = json.loads(opt_str) if opt_str else {}
        return self.call('mv', src, dst, parsed_opt)

    @stub
    def stat(self, uri: str):
        pass

    def write(self, uri: str, content: bytes):
        encoded = base64.b64encode(b''.join(content)).decode()
        return self.call('write', uri, encoded)
