import * as cp from 'child_process';
import * as vscode from 'vscode';
import { run } from '../term';
import { executable } from "../utils";

export default class ADB {
  path: string;

  constructor(private device: string) {
    this.path = executable('adb');

    if (!this.path) {
      const msg = vscode.l10n.t('Could not find command adb in $PATH');
      vscode.window.showErrorMessage(msg);
      throw new Error(msg);
    }
  }

  async cmd(action: string, ...args: string[]) {
    const shellPath = this.path;
    const shellArgs = ['-s', this.device, action, ...args];
    return run({
      shellPath,
      shellArgs
    });
  }

  async push(local: vscode.Uri, remote: string) {
    return this.cmd('push', local.fsPath, remote);
  }

  async pull(remote: string, local: vscode.Uri) {
    return this.cmd('pull', remote, local.fsPath);
  }

  interactive(...cmd: string[]) {
    const name = 'adb';
    const shellPath = this.path;
    const shellArgs = ['-s', this.device, 'shell', ...cmd];
    const term = vscode.window.createTerminal({
      name,
      shellPath,
      shellArgs
    });
    term.show();
    return term;
  }

  async shell(...cmd: string[]) {
    const shellPath = this.path;
    const shellArgs = ['-s', this.device, 'shell', ...cmd];

    return new Promise<string>((resolve, reject) => {
      cp.execFile(shellPath, shellArgs, (err, stdout, stderr) => {
        if (err) {
          reject(err);
        } else {
          resolve(stdout);
        }
      });
    });
  }
}