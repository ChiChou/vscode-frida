import { homedir } from 'os';
import * as vscode from 'vscode';

import ADB from '../driver/adb';
import { AppItem, TargetItem } from "../providers/devices";
import { DeviceType } from '../types';
import { cmd } from '../utils';
import path = require('path');

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

  let artifact: vscode.Uri;

  try {
    if (target.device.os === 'ios') {
      artifact = vscode.Uri.joinPath(destURI, `${target.data.identifier}.ipa`);
      await bagbak(target, artifact);
    } else if (target.device.os === 'android') {
      artifact = vscode.Uri.joinPath(destURI, `${target.data.identifier}.apk`);
      await pull(target, artifact);
    } else {
      vscode.window.showErrorMessage('This command only supports iOS or Android');
      return;
    }
  } catch (e) {
    vscode.window.showInformationMessage(`failed to dump application:\n${(e as Error).message}`);
    return;
  }

  const option = await vscode.window.showInformationMessage(
    `Successfully pulled package ${target.data.identifier}`, 'Open', 'Dismiss');
  if (option === 'Open') {
    vscode.commands.executeCommand('revealFileInOS', artifact);
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

async function bagbak(target: AppItem, output: vscode.Uri) {
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

  shellArgs.push.apply(shellArgs, [target.data.identifier, '-o', output.fsPath]);

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
