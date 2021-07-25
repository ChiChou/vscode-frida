import * as vscode from 'vscode';
import * as path from 'path';

import { platformize } from '../driver/frida';
import { python3Path } from '../utils';


async function create(template: string) {
  let dest: vscode.Uri;

  const { workspaceFolders } = vscode.workspace;
  {
    if (workspaceFolders?.length) { dest = workspaceFolders[0].uri; }
  
    const fileUri = await vscode.window.showOpenDialog({
      canSelectFolders: true,
      canSelectMany: false,
      openLabel: 'Create Here'
    });
  
    if (fileUri?.length) {
      dest = fileUri[0];
    } else {
      vscode.window.showInformationMessage('You just cancelled the operation.');
      return;
    }
  }

  const py: string = path.join(__dirname, '..', '..', 'backend', 'pause.py');
  const args = [py, 'frida-create', template];
  const term = vscode.window.createTerminal({
    cwd: dest,
    name: 'Create Project',
    shellPath: python3Path(),
    shellArgs: args
  });
  term.show();

  const disposable = vscode.window.onDidCloseTerminal(terminal => {
    if (terminal !== term) { return; }
    if (!(workspaceFolders?.length)) {
      vscode.commands.executeCommand('vscode.openFolder', dest);
    }
    npmInstall(dest.path);
    disposable.dispose();
  });  
}

function npmInstall(cwd: string) {
  const [shellPath, shellArgs] = platformize('npm', ['install']);
  const name = `npm install on ${cwd}`;
  vscode.window.createTerminal({
    cwd,
    name,
    shellPath,
    shellArgs
  }).show();
}

export function agent() {
  return create('agent');
}

export function module() {
  return create('module');
}