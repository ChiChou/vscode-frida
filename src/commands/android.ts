import * as vscode from 'vscode';
import * as cp from 'child_process';

import { Octokit } from '@octokit/rest';

import { DeviceItem, TargetItem } from '../providers/devices';
import { executable } from '../utils';
import { run } from '../term';

export async function server(target: TargetItem) {
  if (!(target instanceof DeviceItem)) {
    vscode.window.showErrorMessage('This command is only expected to be used in the context menu');
    return;
  }

  const device = target.data.id;
  const abi = await adbShell('getprop ro.product.cpu.abi', device);
  const mapping: {[key: string]: string} = {
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

  // todo: download
}

async function adbShell(cmd?: string, device?: string, interactive?: boolean): Promise<string> {
  const shellArgs = ['shell'];
  if (device) {
    shellArgs.unshift('-s', device);
  }

  if (cmd) {
    shellArgs.push(cmd);
  }

  if (interactive) {
    const shellPath = executable('adb');
    await run({
      name: 'adb',
      shellPath,
      shellArgs,
    });

    return Promise.resolve('');
  } else {
    return new Promise((resolve, reject) => {
      cp.execFile('adb', shellArgs, (err, stdout, stderr) => {
        resolve(stdout);
      })
    })
  }
}
