import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as readline from 'readline';
import * as path from 'path';

import { platformize } from '../driver/frida';
import { Readable } from 'stream';
import { TextDecoder } from 'util';
import { executable } from '../utils';


async function gitClone(template: string) {
  let { rootPath } = vscode.workspace;
  if (!rootPath) {
    const fileUri = await vscode.window.showOpenDialog({
      canSelectFolders: true,
      canSelectMany: false,
      openLabel: 'Clone Here'
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
  const uri = vscode.Uri.file(dest);

  // check for existence
  let exists = false;
  try {
    exists = Boolean(await vscode.workspace.fs.stat(uri));
  } catch (_) {

  }

  if (exists) {
    const choice = await vscode.window.showWarningMessage(`Destination ${uri.fsPath} already exists`, 'Open File', 'Dismiss');
    if (choice === 'Open File') { openFile(uri); }
    return;
  }

  const bin = executable('git');
  const args = ['clone', url, '--progress', dest];
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

          openFile(uri).catch(_ => { });
          npmInstall(dest);
          resolve();
        })
        .on('error', (err) => {
          vscode.window.showErrorMessage(`Fatal error: unable to launch git command ${err}`);
          reject(err);
        });
    });
  });
}

function npmInstall(cwd: string) {
  const [bin, args] = platformize('npm', ['install']);
  const task = new vscode.Task({ type: 'shell' }, bin, 'npm install',
    new vscode.ShellExecution(bin, args, {
      cwd
    }));
  vscode.tasks.executeTask(task);
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