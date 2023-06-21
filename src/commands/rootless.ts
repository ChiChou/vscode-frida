import { window } from "vscode";

import { DeviceItem, TargetItem } from "../providers/devices";
import { cmd } from "../utils";
import { run } from '../term';


export async function start(node: TargetItem) {
  if (!(node instanceof DeviceItem) || node.data.os !== 'ios') {
    window.showErrorMessage('This command is only avaliable for iOS');
    return;
  }

  const shellPath = cmd('run-frida-server');
  const shellArgs = ['-D', node.data.id];

  return run({
    name: `frida-server - ${node.data.name}`,
    shellArgs,
    shellPath,
    hideFromUser: true,
  });
}
