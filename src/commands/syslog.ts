import * as cp from 'child_process';

import { TargetItem, AppItem, ProcessItem } from "../providers/devices";
import { devtype } from '../driver/frida';
import { window, OutputChannel } from 'vscode';
import { join } from 'path';

const active: {[key: string]: OutputChannel} = {};

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
    child.on('close', () => {
      window.showWarningMessage(`Console ${name} lost connection`);
      channel.dispose();
    });
    return channel;
  }

  if (node instanceof AppItem || node instanceof ProcessItem) {
    devtype(node.device.id).then(type => {     
      if (!node.data.pid) {
        window.showErrorMessage(`App ${node.data.name} is not running`);
        return;
      }

      if (type === 'iOS' || type === 'Linux') {
        const py: string = join(__dirname, '..', '..', 'cmds', 'syslog.py');
        const args = [py, node.device.id.toString(), '--pid', node.data.pid.toString()];
        cmdChannel(`Output: ${node.data.name} (${node.device.name})`, 'python3', args).show();
      } else if (type === 'Android') {
        // todo: adb logcat
      } else {
        window.showErrorMessage(`Unknown type of device ${node.device.name}`);
      }
    });

    // node.data.pid
  }
}