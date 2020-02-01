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

    @stub
    def copy(self, src: str, dst: str):
        pass

    @stub
    def mkdir(self, uri: str):
        pass

    def rm(self, uri: str, opt: str = ''):
        parsed_opt = json.loads(opt) if opt else {}
        return self.call('rm', parsed_opt)

    @stub
    def ls(self, uri: str):
        pass

    def read(self, uri: str) -> bytes:
        encoded = self.call('read', uri)
        return base64.b64decode(encoded)

    @stub
    def mv(self, src: str, dst: str):
        pass

    @stub
    def stat(self, uri: str):
        pass

    def write(self, uri: str, content: bytes):
        encoded = base64.b64encode(b''.join(content)).decode()
        return self.call('write', uri, encoded)
