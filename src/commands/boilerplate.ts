import * as vscode from 'vscode';

import { executable, python3Path } from '../utils';
import { run } from '../term';


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

  const args = ['-m', 'frida_tools.creator', template];

  await run({
    cwd: dest,
    name: 'Create Project',
    shellPath: python3Path(),
    shellArgs: args
  });

  if (!(workspaceFolders?.length)) {
    vscode.commands.executeCommand('vscode.openFolder', dest);
  }

  await run({
    cwd: dest.path,
    name: `npm install`,
    shellPath: executable('npm'),
    shellArgs: ['install']
  });
}

export function agent() {
  return create('agent');
}

export function module() {
  return create('module');
}