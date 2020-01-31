import * as cp from 'child_process';

import { TargetItem, AppItem, ProcessItem } from "../providers/devices";
import { devtype, launch } from '../driver/frida';
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
      window.showWarningMessage(`Console ${name} lost connection, close now?`, 'Close', 'Dismiss').then(option => {
        if (option === 'Close') {
          channel.dispose();
        }
      }));
    return channel;
  }

  async function work(node: AppItem | ProcessItem) {
    const type = await devtype(node.device.id);
    let bundleOrPid: string[] | null = null;
    if (node instanceof AppItem && !node.data.pid) {
      const selection = await window.showInformationMessage(`App "${node.label}" is not running. Start now?`, 'Yes', 'No');
      if (selection === 'Yes') {
        const pid = await launch(node.device.id, node.data.identifier);
        bundleOrPid = ['--pid', pid.toString()];
      } else {
        return;
      }
    } else if ((node instanceof AppItem || node instanceof ProcessItem) && node.data.pid) {
      bundleOrPid = ['--pid', node.data.pid.toString()];
    }

    if (!bundleOrPid) {
      window.showErrorMessage(`Invalid target "${node.label}"`);
      return;
    }

    if (type === 'iOS' || type === 'Linux') {
      const py: string = join(__dirname, '..', '..', 'cmds', 'syslog.py');
      const args = [py, node.device.id.toString(), ...bundleOrPid];
      cmdChannel(`Output: ${node.data.name} (${node.device.name})`, 'python3', args).show();
    } else if (type === 'Android') {
      // todo: adb logcat
    } else {
      window.showErrorMessage(`Unknown type of device ${node.device.name}`);
    }
  }

  if (node instanceof AppItem || node instanceof ProcessItem) {
    work(node);
  }
}