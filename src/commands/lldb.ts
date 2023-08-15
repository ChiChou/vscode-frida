import { window } from "vscode";

import { AppItem, ProcessItem, TargetItem } from "../providers/devices";
import { run } from '../term';
import { DeviceType } from "../types";
import { platform } from "os";


export async function debug(node: TargetItem): Promise<void> {
  if (platform() !== 'darwin') {
    window.showErrorMessage('This command is only avaliable on macOS');
    return;
  }

  // sanity check
  if (node instanceof AppItem || node instanceof ProcessItem) {
    if (node.device.os !== 'ios' || node.device.type !== DeviceType.USB) {
      window.showErrorMessage('this device does not support remote debugging with lldb');
      return;
    }
  } else {
    window.showErrorMessage('This command should be used in context menu');
    return;
  }

  const shellArgs = ['-D', node.device.id];
  if (node instanceof AppItem) {
    if (node.data.pid) {
      shellArgs.push('--attach', node.data.pid.toString());
    } else {
      shellArgs.push('--app', node.data.identifier);
    }
  } else if (node instanceof ProcessItem) {
    shellArgs.push('--attach', node.data.pid.toString());
  }

  const shellPath = 'ios-debug';

  return run({
    name: `lldb - ${node.data.name}`,
    shellArgs,
    shellPath,
    hideFromUser: true,
  });
}
