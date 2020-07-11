import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as readline from 'readline';
import * as path from 'path';

import { platformize } from '../driver/frida';
import { Readable } from 'stream';


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
        .on('exit', (code, signal) => {
          if (code !== 0) {
            if (signal === 'SIGINT') {
              vscode.workspace.fs.delete(uri, { recursive: true });
            } else {
              vscode.window.showErrorMessage(`Failed to clone example. Git exited with code ${code}`);
            }
            reject();
            return;
          }
          resolve();
        })
        .on('error', (err) => {
          vscode.window.showErrorMessage(`Fatal error: unable to launch git command ${err}`);
          reject(err);
        });
    });
  });
}

export function agent() {
  return gitClone('agent');
}

export function module() {
  return gitClone('module');
}