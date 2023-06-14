import { window } from "vscode";

import { AppItem, ProcessItem, TargetItem } from "../providers/devices";
import { run } from '../term';
import { DeviceType } from "../types";
import { executable } from "../utils";


export async function debug(node: TargetItem): Promise<void> {
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

  const args = ['-D', node.device.id];
  if (node instanceof AppItem) {
    if (node.data.pid) {
      args.push('attach', node.data.pid.toString());
    } else {
      args.push('app', node.data.identifier);
    }
  } else if (node instanceof ProcessItem) {
    args.push('attach', node.data.pid.toString());
  }

  const shellPath = executable('ios-debug');
  const shellArgs = ['attach'];

  return run({
    name: `lldb - ${node.data.name}`,
    shellArgs,
    shellPath,
    hideFromUser: true,
  });
}
