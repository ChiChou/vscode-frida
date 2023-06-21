import { commands, window } from 'vscode';

import { os } from '../driver/frida';
import { DeviceItem, TargetItem } from '../providers/devices';
import { run } from '../term';
import { cmd, executable } from '../utils';


// https://github.com/ChiChou/fruity-frida
async function askToInstallDeployTool() {
  const selected = await window.showErrorMessage(
    'fruity-frida is not installed. Would you like to install it now?', 'Yes', 'No');
  
  if (selected === 'Yes') {
    return run({
      name: 'install fruity-frida',
      shellPath: cmd('npm'),
      shellArgs: ['install', '-g', 'fruity-frida'],
    })
  }
}

export async function shell(node: TargetItem) {
  if (!(node instanceof DeviceItem)) {
    window.showErrorMessage('This command is only avaliable on context menu');
    return;
  }

  if (node.data.id === 'local') {
    // execute command to open a new terminal
    commands.executeCommand('workbench.action.terminal.new');
    return;
  }

  const system = await os(node.data.id);
  const name = `SSH: ${node.data.name}`;
  let shellPath, shellArgs;

  if (system === 'ios') {
    shellPath = cmd('ios-shell');
    shellArgs = ['-D', node.data.id];
  } else if (system === 'android') {
    // todo: use adb.ts
    shellPath = executable('adb');
    shellArgs = ['-s', node.data.id, 'shell'];
  } else {
    window.showErrorMessage(`OS type "${system}" is not supported`);
    return;
  }

  return run({
    name,
    shellArgs,
    shellPath,
    hideFromUser: true,
  }).catch(err => {
    if (err.message === 'Command not found: ios-shell') {
      askToInstallDeployTool();
      return;
    }

    throw err;
  });
}