import frida
import sys
import os

from pathlib import Path


def shell():
  def on_detach(reason, crash):
    # print('detach', reason, crash)
    sys.exit()

  dev = frida.get_usb_device()
  pid = dev.spawn('/bin/sh', stdio='pipe')
  session = dev.attach(pid)
  session.on('detached', on_detach)

  def on_output(source_pid, fd, data):
    if pid != source_pid:
      return

    if fd == 1:
      sys.stdout.buffer.write(data)
      sys.stdout.flush()
    elif fd == 2:
      sys.stderr.buffer.write(data)
      sys.stderr.flush()

  dev.on('output', on_output)
  dev.resume(pid)

  try:
    while True:
      buf = sys.stdin.readline()
      if not buf:
        break
      dev.input(pid, buf.encode('utf8'))
  except KeyboardInterrupt:
    session.detach()
    dev.kill(pid)

shell()
