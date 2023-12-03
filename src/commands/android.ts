import * as vscode from 'vscode';

import ADB from '../driver/adb';
import { DeviceItem, TargetItem } from '../providers/devices';


export async function downloadServer(device: DeviceItem) {
  const adb = new ADB(device.data.id);
  const abi = await adb.shell(['getprop', 'ro.product.cpu.abi']);
  const mapping: { [key: string]: string } = {
    'arm64-v8a': 'arm64',
    'armeabi-v7a': 'arm',
    'x86_64': 'x86_64',
    'x86': 'x86',
  }

  const arch = mapping[abi.trim()];
  if (!arch) {
    vscode.window.showErrorMessage(`Unsupported architecture: ${abi}`);
    return;
  }

  const token = vscode.workspace.getConfiguration('frida').get('githubToken', undefined);
  if (!token) {
    vscode.window.showInformationMessage(
      'GitHub token is not set, your access is limited. Please consider setting "frida.githubToken" in your settings');
  }

  const predicate = (filename: string) => filename.startsWith('frida-server') && filename.endsWith(`-android-${arch}.xz`);

  // todo: download frida-server
}

export async function startServer(target: TargetItem) {
  if (!(target instanceof DeviceItem)) {
    vscode.window.showErrorMessage('This command is only expected to be used in the context menu');
    return;
  }

  const adb = new ADB(target.data.id);
  const term = adb.interactive();

  // todo: download frida-server
  setTimeout(() => {
    term.sendText('su', true);
    term.sendText('/data/local/tmp/frida-server', true);
  }, 500);
}
