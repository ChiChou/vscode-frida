import * as backend from '../driver/backend';

import { run } from '../term';
import { commands, ProgressLocation, Uri, window, workspace } from "vscode";
import { devtype } from "../driver/frida";
import { ssh as proxySSH } from "../iproxy";
import { AppItem, DeviceItem, TargetItem } from "../providers/devices";
import { python3Path, showInFolder } from '../utils';
import { homedir } from 'os';
import { basename } from 'path';
import { Decryptor } from '../driver/decrypt';


export async function install(node: TargetItem): Promise<void> {
  if (!(node instanceof DeviceItem)) {
    // todo: select from devices
    window.showErrorMessage('This command should be used in context menu');
    return Promise.resolve();
  }

  const type = await devtype(node.data.id);
  if (type !== 'iOS') {
    window.showErrorMessage(`Unsupported device type: ${type}. This command is for iOS only`);
    return Promise.resolve();
  }

  const iproxy = await proxySSH(node.data.id);
  const py: string = backend.path('fruit', 'get-foul.py');
  const shellArgs = [py, iproxy.local.toString()];

  try {
    await run({
      name: 'FoulDecrypt installer',
      shellPath: python3Path(),
      shellArgs,
    });
  } catch(e) {
    window.showErrorMessage('Failed to install FoulDecrypt');
    return;
  } finally {
    iproxy.release();
  }
  window.showInformationMessage(`FoulDecrypt installed on ${node.data.name}`, 'Dismiss');
}


export async function decrypt(node: TargetItem): Promise<void> {
  if (!(node instanceof AppItem)) {
    window.showErrorMessage('This command should be used in context menu');
    return;
  }

  const preferred = workspace.getConfiguration('frida').get('decryptOutput') || homedir();
  const defaultUri = Uri.file(`${preferred}/${node.data.name}.ipa`);
  const destination = await window.showSaveDialog({
    defaultUri,
    filters: { Archive: ['ipa'] },
  });

  if (!destination) { return; }

  const folder = Uri.joinPath(destination, '..').fsPath;
  const name = `${basename(destination.fsPath)}.ipa`;

  // save preferred path
  workspace.getConfiguration('frida').update('decryptOutput', folder, true);

  const dec = new Decryptor(node.device.id);
  await window.withProgress({
    location: ProgressLocation.Notification,
    title: 'FoulDecrypt running',
    cancellable: false
  }, (progress) => dec.go(node.data.identifier, destination.fsPath, progress));

  const choice = await window.showInformationMessage(
    'FoulDecrypt successfully finished', 'Open Folder', `Open ${name}`, 'Dismiss');
  if (choice === `Open ${name}`) {
    commands.executeCommand('vscode.open', destination);
  } else if (choice === 'Open Folder') {
    showInFolder(destination);
  }
}