import * as cp from 'child_process';
import * as vscode from 'vscode';
import { run } from '../term';
import { executable } from "../utils";

export default class ADB {
  path: string;

  constructor(private device: string) {
    this.path = executable('adb');
  }

  async push(local: vscode.Uri, remote: string) {
    const shellPath = this.path;
    const shellArgs = ['-s', this.device, 'push', local.fsPath, remote];
    return run({
      shellPath,
      shellArgs
    })
  }

  async pull(remote: string, local: vscode.Uri) {
    const shellPath = this.path;
    const shellArgs = ['-s', this.device, 'pull', remote, local.fsPath];
    return run({
      shellPath,
      shellArgs
    })
  }

  interactive(cmd?: string[]) {
    const name = 'adb';
    const shellPath = this.path;
    const shellArgs = ['-s', this.device, 'shell'];
    if (cmd) {
      shellArgs.push.apply(shellArgs, cmd);
    }

    const term = vscode.window.createTerminal({
      name,
      shellPath,
      shellArgs
    });
    term.show();
    return term;
  }

  async shell(cmd?: string[]) {
    const shellPath = this.path;
    const shellArgs = ['-s', this.device, 'shell'];
    if (cmd) {
      shellArgs.push.apply(shellArgs, cmd);
    }

    return new Promise<string>((resolve, reject) => {
      cp.execFile(shellPath, shellArgs, (err, stdout, stderr) => {
        if (err)
          reject(err);
        else
          resolve(stdout);
      })
    })
  }
}