import * as cp from 'child_process';

import { TargetItem, AppItem, ProcessItem } from "../providers/devices";
import { os, lockdownSyslog } from '../driver/frida';
import { python3Path, refresh } from '../utils';
import { DeviceType } from '../types';

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

  os(node.device.id).then(type => {
    if (type === 'ios' && node.device.type === DeviceType.USB) {
      lockdownSyslog(node.device.id, bundleOrPid);
    } else if (type === 'linux' || type === 'macos') {
      const py: string = join(__dirname, '..', '..', 'backend', 'driver.py');
      const args = [py, 'syslog', '--device', node.device.id, ...bundleOrPid];
      cmdChannel(`Output: ${node.data.name} (${node.device.name})`, python3Path(), args).show();
    } else if (type === 'android') {
      const args = ['-s', node.device.id, 'logcat', `--pid=${node.data.pid}`];
      cmdChannel(`Output: ${node.data.name} (${node.device.name})`, 'adb', args).show();
    } else {
      window.showErrorMessage(`Unimplemented type of device ${node.device.name}`);
    }
  });
}