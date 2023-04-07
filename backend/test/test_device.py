import unittest
import frida

from backend import core


class TestDeviceOperations(unittest.TestCase):
    def setUp(self):
        self.local = frida.get_local_device()
        self.usb = frida.get_usb_device()

    def test_info(self):
        usb = self.usb
        local = self.local

        self.assertIsInstance(core.devices(), list)
        self.assertIsInstance(core.ps(local), list)
        self.assertIsInstance(core.apps(usb), list)

    def test_attach(self):
        usb = self.usb
        local = self.local

        # make safari a background app
        usb.resume(usb.spawn('com.apple.mobilesafari'))
        usb.resume(usb.spawn('com.apple.Preferences'))

        with self.assertRaises(RuntimeError):
            core.spawn_or_attach(usb, 'com.apple.mobilesafari')
        session = core.spawn_or_attach(usb, 'com.apple.Preferences')
        self.assertIsInstance(session, frida.core.Session)

        usb.kill('Settings')
        usb.kill('Safari')

        session.detach()


if __name__ == '__main__':
    unittest.main()
