import * as vscode from 'vscode';

import { Octokit } from '@octokit/rest';

import ADB from '../driver/adb';
import { DeviceItem, TargetItem } from '../providers/devices';


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
