import frida
import sys
import cmds.core
from typing import List, Union



class BaseAgent(object):
    def __init__(self, device: frida.core.Device):
        self.device = device
        self.session = None  # type: frida.core.Session
        self.script = None  # type: frida.core.Script

    def invoke(self, method: str, *args: List[str]):
        if not self.session:
            raise RuntimeError('invalid state')

        invocation = getattr(self.script.exports, method)
        return invocation(*args)

    def load(self):
        if not self.session:
            raise RuntimeError('invalid state')

        session = self.session

        def on_detach(reason):
            if reason == 'application-requested':
                sys.exit(0)
            sys.stderr.write('[FATAL Error] target disconnected\n')
            sys.exit(-1)
        session.on('detached', on_detach)

        source = cmds.core.read_agent()
        script = session.create_script(source)
        script.load()
        self.script = script

    def unload(self):
        if self.session:
            self.session.detach()


class AppAgent(BaseAgent):
    def __init__(self, device: frida.core.Device, bundle: str):
        super().__init__(device)
        self.session = cmds.core.spawn_or_attach(self.device, bundle)


class ProcessAgent(BaseAgent):
    def __init__(self, device, target: Union[int, str]):
        super().__init__(device)
        self.session = self.device.attach(target)
