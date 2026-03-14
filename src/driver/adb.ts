import * as cp from 'child_process';
import * as vscode from 'vscode';
import { run } from '../term';
import { executable } from "../utils";
import { logger } from '../logger';

export default class ADB {
  path: string;

  constructor(private device: string) {
    this.path = executable('adb');

    if (!this.path) {
      const msg = vscode.l10n.t('Could not find command adb in $PATH');
      logger.appendLine(`Error: ${msg}`);
      vscode.window.showErrorMessage(msg);
      throw new Error(msg);
    }
  }

  async cmd(action: string, ...args: string[]) {
    logger.appendLine(`ADB ${action} ${args.join(' ')} on device ${this.device}`);
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

  async pull(...args: [...string[], vscode.Uri]) {
    const local = args.pop() as vscode.Uri;
    return this.cmd('pull', ...args as string[], local.fsPath);
  }

  async pmPath(pkg: string): Promise<string[]> {
    const output = await this.shell('pm', 'path', pkg);
    return output.split('\n')
      .map(line => line.trim())
      .filter(line => line.startsWith('package:'))
      .map(line => line.substring(8));
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