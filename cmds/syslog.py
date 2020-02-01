#!/usr/bin/env python3

import frida
import sys

from cmds.rpc import BaseAgent

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
