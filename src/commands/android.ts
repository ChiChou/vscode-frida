import * as vscode from 'vscode';
import * as cp from 'child_process';

import { Octokit } from '@octokit/rest';

import { DeviceItem, TargetItem } from '../providers/devices';
import { executable } from '../utils';
import { run } from '../term';

async function downloadServer(device: string) {
  const adb = new ADB(device);
  const abi = await adb.shell(['getprop', 'ro.product.cpu.abi']);
  const mapping: { [key: string]: string } = {
    'arm64-v8a': 'arm64',
    'armeabi-v7a': 'arm',
    'x86_64': 'x86_64',
    'x86': 'x86',
  }

  const arch = mapping[abi.trim()];
  if (!arch) {
    vscode.window.showErrorMessage(`Unsupported architecture: ${abi}`);
    return;
  }

  const token = vscode.workspace.getConfiguration('frida').get('githubToken');
  if (!token) {
    vscode.window.showInformationMessage(
      'GitHub token is not set, your access might be denied. Please consider setting "frida.githubToken" in your settings');
  }

  const octokit = new Octokit({
    auth: token,
  });

  const suffix = `-android-${arch}.xz`

  // use Octokit to access github api and get latest release from
  // https://api.github.com/repos/frida/frida/releases/latest

  const release = await octokit.repos.getLatestRelease({
    owner: 'frida',
    repo: 'frida',
  });

  const asset = release.data.assets.find(asset =>
    asset.name.startsWith('frida-server') && asset.name.endsWith(suffix))
  const url = asset?.browser_download_url;
  if (!url) {
    vscode.window.showErrorMessage(`Failed to find frida-server for ${abi}`);
    return;
  }
}

export async function startServer(target: TargetItem) {
  if (!(target instanceof DeviceItem)) {
    vscode.window.showErrorMessage('This command is only expected to be used in the context menu');
    return;
  }

  const adb = new ADB(target.data.id);
  const term = adb.interactive();

  // todo: download frida-server
  setTimeout(() => {
    term.sendText('su', true);
    term.sendText('/data/local/tmp/frida-server', true);
  }, 500);
}

class ADB {
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
