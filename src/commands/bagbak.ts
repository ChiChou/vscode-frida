import * as vscode from 'vscode';

import { devtype, platformize } from '../driver/frida';
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

  const [bin, args] = platformize('bagbak', ['-f', '-u', target.device.id, target.data.identifier]);
  vscode.window.createTerminal(title, bin, args).show();
}