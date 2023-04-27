import * as vscode from 'vscode';

import { AppItem, TargetItem } from "../providers/devices";
import { executable } from '../utils';
import { DeviceType } from '../types';
import { homedir } from 'os';

export async function dump(target: TargetItem) {
  if (!(target instanceof AppItem)) {
    vscode.window.showErrorMessage('This command is only expected to be used in the context menu');
    return;
  }

  if (target.device.os !== 'ios') {
    vscode.window.showErrorMessage('This command is currently only supported on iOS');
    return;
  }

  const preferred = vscode.workspace.getConfiguration('frida').get('decryptOutput', homedir());
  const defaultUri = vscode.Uri.file(preferred);
  const destination = await vscode.window.showOpenDialog({
    defaultUri,
    canSelectFiles: false,
    canSelectFolders: true,
    canSelectMany: false,
    openLabel: 'Select',
    title: 'Select destination folder'
  });

  if (!destination?.length) return;

  const output = destination[0].fsPath;

  const shellArgs: string[] = [];
  switch(target.device.type) {
    case DeviceType.Remote:
    case DeviceType.TCP:
      shellArgs.push.apply(shellArgs, ['-H', target.device.id]);
      break;
    case DeviceType.USB:
      if (target.device.id !== 'usb')
        shellArgs.push.apply(shellArgs, ['-u', target.device.id]);
      break;
    default:
      vscode.window.showErrorMessage('Unsupported device type');
      return;
  }

  shellArgs.push.apply(shellArgs, [target.data.identifier]);

  // save preferred path
  vscode.workspace.getConfiguration('frida').update('decryptOutput', output, true);

  shellArgs.push.apply(shellArgs, ['-o', output]);

  const term = vscode.window.createTerminal({
    name: 'bagbak',
    shellPath: executable('bagbak'),
    shellArgs,
  });

  vscode.window.onDidCloseTerminal((e) => {
    if (e === term) {
      if (term.exitStatus?.code === 0) {
        vscode.window.showInformationMessage('bagbak completed successfully', 'Open', 'Dismiss').then((value) => {
          if (value === 'Open') {
            // open folder in finder/explorer)
            vscode.commands.executeCommand('revealFileInOS', vscode.Uri.file(output));
          }
        });
      } else {
        vscode.window.showInformationMessage('bagbak failed to dump application');
      }
    }
  });

  term.show();
}