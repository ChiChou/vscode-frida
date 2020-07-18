import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as readline from 'readline';
import * as path from 'path';

import { platformize } from '../driver/frida';
import { Readable } from 'stream';
import { TextDecoder } from 'util';


async function gitClone(template: string) {
  let { rootPath } = vscode.workspace;
  if (!rootPath) {
    const fileUri = await vscode.window.showOpenDialog({
      canSelectFolders: true,
      canSelectMany: false,
      openLabel: 'Destination'
    });

    if (fileUri && fileUri.length === 1) {
      rootPath = fileUri[0].fsPath;
    } else {
      vscode.window.showInformationMessage('You just cancelled the operation.');
      return;
    }
  }

  const name = `frida-${template}-example`;
  const url = `https://github.com/oleavr/${name}.git`;
  const dest = path.join(rootPath, name);
  const [bin, args] = platformize('git', ['clone', url, '--progress', dest]);
  const uri = vscode.Uri.file(dest);

  // check for existence
  try {
    const st = await vscode.workspace.fs.stat(uri);
    if (st) {
      vscode.window.showWarningMessage(`Destination ${uri.fsPath} already exists`);
      return;
    }
  } catch (_) {

  }

  const proc = cp.execFile(bin, args, { cwd: vscode.workspace.rootPath });
  vscode.window.withProgress({
    location: vscode.ProgressLocation.Notification,
    title: `Frida Boilerplate`,
    cancellable: true
  }, (progress, token) => {
    if (!proc.stdout) {
      vscode.window.showErrorMessage('Fatal error: unable to launch git command');
      return Promise.reject();
    }

    token.onCancellationRequested(() => {
      proc.kill('SIGINT');
    });

    const rl = readline.createInterface(proc.stderr as Readable);
    rl.on('line', (input) => {
      progress.report({ message: input });
    });

    return new Promise((resolve, reject) => {
      proc
        .on('exit', async (code, signal) => {
          if (code !== 0) {
            if (signal === 'SIGINT') {
              vscode.workspace.fs.delete(uri, { recursive: true });
            } else {
              vscode.window.showErrorMessage(`Failed to clone example. Git exited with code ${code}`);
            }
            reject();
            return;
          }
          
          openFile(uri).catch(_ => {});
          npmInit(uri);
          resolve();
        })
        .on('error', (err) => {
          vscode.window.showErrorMessage(`Fatal error: unable to launch git command ${err}`);
          reject(err);
        });
    });
  });
}

function npmInit(cwd: vscode.Uri) {
  const [shellPath, shellArgs] = platformize('npm', ['install']);
  vscode.window.createTerminal({
    name: 'npm install',
    shellPath,
    shellArgs,
    cwd
  }).show();
}

async function openFile(root: vscode.Uri) {
  const meta = path.join(root.fsPath, 'package.json');
  const content = await vscode.workspace.fs.readFile(vscode.Uri.file(meta));
  const info = JSON.parse(new TextDecoder('utf-8').decode(content));
  const { main } = info;
  const mainSourceUri = vscode.Uri.file(path.join(root.fsPath, main));  
  vscode.commands.executeCommand('vscode.open', mainSourceUri);
}

export function agent() {
  return gitClone('agent');
}

export function module() {
  return gitClone('module');
}