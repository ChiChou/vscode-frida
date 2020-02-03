import * as vscode from 'vscode';

import { devtype } from '../driver/frida';
import { platform } from 'os';
import { AppItem } from "../providers/devices";

export async function dump(target: AppItem) {
  if (!target) {
    // todo: select from list
    return;
  }

  const title = `Dump App: ${target.label}`;
  if (await devtype(target.device.id) !== 'iOS') {
    vscode.window.showWarningMessage('This command is only applicable to iOS');
    return;
  }

  // todo: utils.platformize
  if (platform() === 'win32') {
    vscode.window.createTerminal(title, 'cmd.exe',
      ['/c', 'bagbak', '-f', '-u', target.device.id, target.data.identifier]).show();
  } else {
    vscode.window.createTerminal(title, 'bagbak',
      ['-f', '-u', target.device.id, target.data.identifier]).show();
  }
}