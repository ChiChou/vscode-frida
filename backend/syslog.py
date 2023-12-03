#!/usr/bin/env python3

from typing import Callable
from enum import Enum

import frida
import sys

from backend.rpc import BaseAgent


def pipe(agent: BaseAgent):
    agent.invoke('start')

    def on_message(message, data):
        sys.stdout.buffer.write(data)
        sys.stdout.flush()

    agent.script.on('message', on_message)

    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
    finally:
        agent.invoke('stop')
        agent.unload()


class SyslogService(object):
    def __init__(self, device: frida.core.Device):
        self.dev = device
        self.pipe = None

    def __enter__(self):
        self.pipe = self.dev.open_channel(
            'lockdown:com.apple.syslog_relay')
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.pipe.close()

    def close(self):
        self.pipe.close()


CHUNK_SIZE = 4096
TIME_FORMAT = '%H:%M:%S'
SYSLOG_LINE_SPLITTER = b'\n\x00'


class Level(Enum):
    Unknown = 0
    Notice = 1
    Warning = 2
    Error = 3


def parse_level(level_text: str) -> Level:
    if level_text == b'<Notice>':
        return Level.Notice

    if level_text == b'<Warning>':
        return Level.Warning

    if level_text == b'<Error>':
        return Level.Error

    return Level.Unknown


def parse_line(line: bytes):
    pid_start = line.find(b'[')
    pid_end = line.find(b']', pid_start + 1)

    assert pid_start > -1 and pid_end > -1
    pid = int(line[pid_start + 1:pid_end], 10)

    colon_index = line.find(b':', pid_end + 1)
    level_text = line[pid_end + 2:colon_index]

    name_start = line.rfind(b' ', 0, pid_start) + 1
    name_and_module = line[name_start:pid_start]

    device_name_end = line.rfind(b' ', 0, name_start)
    device_name_start = line.rfind(b' ', 0, device_name_end)
    ts = line[0:device_name_start]

    if b'(' in name_and_module:
        name_end = name_and_module.find(b'(')
        name = name_and_module[0:name_end]
        module_end = name_and_module.find(b')')
        module = name_and_module[name_end + 1:module_end]
    else:
        name, module = name_and_module, None

    body = line[colon_index + 2:]
    return ts, pid, level_text, name, module, body


class bcolors:
    HEADER = b'\033[95m'
    OKBLUE = b'\033[94m'
    OKCYAN = b'\033[96m'
    OKGREEN = b'\033[92m'
    WARNING = b'\033[93m'
    FAIL = b'\033[91m'
    ENDC = b'\033[0m'
    BOLD = b'\033[1m'
    UNDERLINE = b'\033[4m'


def color(level: Level):
    mapping = {
        # Level.Unknown: b'',
        Level.Notice: bcolors.OKGREEN,
        Level.Warning: bcolors.WARNING,
        Level.Error: bcolors.FAIL
    }

    return mapping.get(level, b'')


def get_proc_name(device: frida.core.Device, bundle: str):
    try:
        info = next(app for app in device.enumerate_applications(
            scope='metadata') if app.identifier == bundle)
    except StopIteration:
        raise RuntimeError('app with bundle %s does not exist' % bundle)

    if info.pid == 0:
        device.resume(device.spawn(bundle))

    return info.parameters.get('path')


def stream(device: frida.core.Device, filter_cb: Callable[[int, str], bool]):
    with SyslogService(device) as channel:
        buf = b''
        while True:
            chunk: bytes = channel.pipe.read_all(CHUNK_SIZE)
            buf += chunk

            # SYSLOG_LINE_SPLITTER is used to split each syslog line
            if SYSLOG_LINE_SPLITTER not in buf:
                continue

            lines = buf.split(SYSLOG_LINE_SPLITTER)

            # handle partial last lines
            if not buf.endswith(SYSLOG_LINE_SPLITTER):
                buf = lines[-1]
                lines = lines[:-1]

            for line in lines:
                if len(line) == 0:
                    continue

                ts, pid, level_text, name, module, body = parse_line(line)
                if not filter_cb(pid, name):
                    continue

                # timestamp
                yield ts
                yield b' '

                # process
                yield bcolors.OKCYAN
                yield name
                yield bcolors.ENDC

                # module
                yield bcolors.OKBLUE
                if module:
                    yield b'('
                    yield module
                    yield b')'

                yield b'[%d]' % pid
                yield bcolors.ENDC
                yield b' '

                # level
                level = parse_level(level_text)
                yield color(level)
                yield level_text
                yield bcolors.ENDC
                yield b': '

                # body
                yield body
                yield b'\n'


def start(device: frida.core.Device, pid: int = None, bundle: str = None):
    if type(pid) is int and pid > 0:
        def filter_cb(target_pid, target_name):
            return pid == target_pid

    elif type(bundle) is str:
        name = get_proc_name(device, bundle).encode('utf-8')

        def filter_cb(target_pid, target_name):
            return name == target_name

    else:
        raise ValueError(
            f'invalid parameter combination: pid={pid} bundle={bundle}')

    try:
        for buf in stream(device, filter_cb):
            sys.stdout.buffer.write(buf)
            if buf == b'\n':
                sys.stdout.flush()

    except KeyboardInterrupt:
        pass
