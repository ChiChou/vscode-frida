import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as readline from 'readline';
import * as path from 'path';

import { platformize } from '../driver/frida';
import { Readable } from 'stream';
import { TextDecoder } from 'util';
import { executable } from '../utils';


async function gitClone(template: string) {
  let root: vscode.Uri;

  {
    const { workspaceFolders } = vscode.workspace;
    if (workspaceFolders?.length) { root = workspaceFolders[0].uri; }
  
    const fileUri = await vscode.window.showOpenDialog({
      canSelectFolders: true,
      canSelectMany: false,
      openLabel: 'Clone Here'
    });
  
    if (fileUri?.length) {
      root = fileUri[0];
    } else {
      vscode.window.showInformationMessage('You just cancelled the operation.');
      return;
    }
  }

  const name = `frida-${template}-example`;
  const url = `https://github.com/oleavr/${name}.git`;
  const dest = vscode.Uri.joinPath(root, name);

  // check for existence
  let exists = false;
  try {
    exists = Boolean(await vscode.workspace.fs.stat(dest));
  } catch (_) {

  }

  if (exists) {
    const choice = await vscode.window.showWarningMessage(`Destination ${dest} already exists`, 'Open File', 'Dismiss');
    if (choice === 'Open File') { openFile(dest); }
    return;
  }

  const bin = executable('git');
  const args = ['clone', url, '--progress', dest.fsPath];
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
              vscode.workspace.fs.delete(dest, { recursive: true });
            } else {
              vscode.window.showErrorMessage(`Failed to clone example. Git exited with code ${code}`);
            }
            reject();
            return;
          }

          openFile(dest).catch(_ => { });
          npmInstall(dest.fsPath);
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
  const [shellPath, shellArgs] = platformize('npm', ['install']);
  const name = `npm install on ${cwd}`;
  vscode.window.createTerminal({
    cwd,
    name,
    shellPath,
    shellArgs
  }).show();
}

async function openFile(root: vscode.Uri) {
  const meta = vscode.Uri.joinPath(root, 'package.json');
  const content = await vscode.workspace.fs.readFile(meta);
  const info = JSON.parse(new TextDecoder('utf-8').decode(content));
  const { main } = info;
  const mainSource = vscode.Uri.joinPath(root, main);
  vscode.commands.executeCommand('vscode.open', mainSource);
}

export function agent() {
  return gitClone('agent');
}

export function module() {
  return gitClone('module');
}