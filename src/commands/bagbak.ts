import * as vscode from 'vscode';
import * as path from 'path';
import * as os from 'os';

import { devtype, platformize } from '../driver/frida';
import { AppItem } from "../providers/devices";

export async function dump(target: AppItem) {
  if (!target) {
    // todo: select from list
    return;
  }

  const name = `Dump App: ${target.label}`;
  if (await devtype(target.device.id) !== 'iOS') {
    vscode.window.showWarningMessage('This command is only applicable to iOS');
    return;
  }

  const { workspaceFolders } = vscode.workspace;
  const cwd = workspaceFolders ? workspaceFolders[0].uri.fsPath : os.homedir();
  const [shellPath, shellArgs] = platformize('bagbak', ['-f', '-u', target.device.id, target.data.identifier]);
  const term = vscode.window.createTerminal({
    cwd,
    name,
    shellPath,
    shellArgs
  });

  term.show();
  const dest = vscode.Uri.file(path.join(cwd, 'dump', target.data.identifier));
  const disposable = vscode.window.onDidCloseTerminal(async (t) => {
    if (t === term) {
      try {
        await vscode.workspace.fs.stat(dest);
        vscode.commands.executeCommand('vscode.openFolder', dest, true);
      } catch(e) {
        vscode.window.showErrorMessage('Dump failed.');
      }
      disposable.dispose();
    }
  });
}