import * as cp from 'child_process';

import { TargetItem, AppItem, ProcessItem } from "../providers/devices";
import { devtype } from '../driver/frida';
import { refresh } from '../utils';

import { window, OutputChannel } from 'vscode';
import { join } from 'path';

const active: { [key: string]: OutputChannel } = {};

export function vacuum() {
  for (const channel of Object.values(active)) {
    channel.dispose();
  }
}

export function show(node?: TargetItem) {
  function cmdChannel(name: string, bin: string, args: string[]) {
    if (name in active) {
      return active[name];
    }

    const channel = window.createOutputChannel(name);
    const child = cp.spawn(bin, args);
    const write = (data: Buffer) => channel.append(data.toString());
    child.stdout.on('data', write);
    child.stderr.on('data', write);
    child.on('close', () =>
      window.showWarningMessage(
        `Console ${name} lost connection, close now?`, 'Close', 'Dismiss').then(option => {
          if (option === 'Close') {
            channel.dispose();
          }
          refresh();
        }));
    return channel;
  }

  let bundleOrPid: string[];
  if (node instanceof AppItem) {
    bundleOrPid = ['--app', node.data.identifier];
  } else if (node instanceof ProcessItem) {
    bundleOrPid = ['--pid', node.data.pid.toString()];
  } else {
    if (node) {
      window.showErrorMessage(`Invalid target "${node.label}"`);
    }
    return;
  }

  devtype(node.device.id).then(type => {
    if (type === 'iOS' || type === 'Linux' || type === 'macOS') {
      const py: string = join(__dirname, '..', '..', 'cmds', 'driver.py');
      const args = [py, 'syslog', '--device', node.device.id.toString(), ...bundleOrPid];
      cmdChannel(`Output: ${node.data.name} (${node.device.name})`, 'python3', args).show();
    } else if (type === 'Android') {
      // todo: adb logcat
    } else {
      window.showErrorMessage(`Unknown type of device ${node.device.name}`);
    }
  });
}