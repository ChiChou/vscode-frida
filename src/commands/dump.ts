import { homedir } from 'os';
import * as vscode from 'vscode';

import ADB from '../driver/adb';
import { AppItem, TargetItem } from "../providers/devices";
import { DeviceType } from '../types';
import { cmd } from '../utils';

export default async function dump(target: TargetItem) {
  if (!(target instanceof AppItem)) {
    vscode.window.showErrorMessage('This command is only expected to be used in the context menu');
    return;
  }

  if (target.device.os !== 'ios' && target.device.os !== 'android') {
    vscode.window.showErrorMessage('This command only supports iOS or Android');
    return;
  }

  const preferred = vscode.workspace.getConfiguration('frida').get('decryptOutput', homedir());
  const defaultUri = vscode.Uri.file(preferred);
  const destinations = await vscode.window.showOpenDialog({
    defaultUri,
    canSelectFiles: false,
    canSelectFolders: true,
    canSelectMany: false,
    openLabel: 'Select',
    title: 'Select destination folder'
  });

  if (!destinations?.length) return;

  const destURI = destinations[0]
  const output = destURI.fsPath;

  // save preferred path
  vscode.workspace.getConfiguration('frida').update('decryptOutput', output, true);

  try {
    if (target.device.os === 'ios') {
      vscode.window.showErrorMessage('Having issues with iOS now :(, please wait for a fix');
      return;
      // await bagbak(target, output);
    } else if (target.device.os === 'android') {
      await pull(target, destURI);
    }
  } catch (e) {
    vscode.window.showInformationMessage(`failed to dump application:\n${(e as Error).message}`);
    return;
  }

  const option = await vscode.window.showInformationMessage(
    `Successfully pulled package ${target.data.identifier}`, 'Open', 'Dismiss')
  if (option === 'Open') {
    // open folder in finder/explorer)
    vscode.commands.executeCommand('revealFileInOS', destURI);
  }
}

async function pull(target: AppItem, output: vscode.Uri) {
  const adb = new ADB(target.device.id);
  const path = await adb.shell(['pm', 'path', target.data.identifier]);

  if (path.startsWith('package:')) {
    await adb.pull(path.substring(8).trimEnd(), output);
  } else {
    vscode.window.showErrorMessage(`Failed to get package path: ${path}`);
  }
}

async function bagbak(target: AppItem, output: string) {
  const shellArgs: string[] = [];
  switch (target.device.type) {
    case DeviceType.Remote:
      shellArgs.push.apply(shellArgs, ['-H', target.device.id]);
      break;
    case DeviceType.USB:
      if (target.device.id !== 'usb')
        shellArgs.push.apply(shellArgs, ['-D', target.device.id]);
      break;
    default:
      vscode.window.showErrorMessage('Unsupported device type');
      return;
  }

  shellArgs.push.apply(shellArgs, [target.data.identifier, '-o', output]);

  const term = vscode.window.createTerminal({
    name: 'bagbak',
    shellPath: cmd('bagbak'),
    shellArgs,
  });

  return new Promise<void>((resolve, reject) => {
    vscode.window.onDidCloseTerminal((e) => {
      if (e === term) {
        if (term.exitStatus?.code === 0) {
          resolve();
        } else {
          reject(new Error(`bagbak exited with code ${term.exitStatus?.code}`));
        }
      }
    });

    term.show();
  });

}