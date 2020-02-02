import unittest
import json
import frida

from cmds.fs import FileSystem
from cmds.rpc import AppAgent
from cmds.core import device_type


class TestDeviceOperations(unittest.TestCase):
    def test_fs(self):
        usb = frida.get_usb_device()
        self.assertEqual(device_type(usb), 'iOS',
                         'this unittest only works for iOS')
        agent = AppAgent(usb, 'com.apple.Preferences')
        agent.load()
        fs = FileSystem(agent)

        self.assertIsInstance(fs.ls('/etc'), list)
        self.assertIsInstance(fs.ls('~/tmp'), list)
        self.assertIsInstance(fs.read('/etc/passwd'), bytes)
        fs.cp('/etc/passwd', '~/tmp/test')
        fs.rm('~/tmp/test')
        fs.mkdir('~/tmp/testdir')
        fs.rm('~/tmp/testdir', json.dumps({'recursive': True}))
        self.assertIsInstance(fs.stat('~/tmp'), dict)


if __name__ == '__main__':
    unittest.main()
