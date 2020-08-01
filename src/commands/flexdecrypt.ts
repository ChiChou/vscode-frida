
// todo: check commands
// async function checkEnviron() {
// }

import * as cp from 'child_process';
import { promisify } from 'util';
import { join, resolve } from 'path';
import { tmpdir, homedir } from 'os';
import { promises as fsp } from 'fs';
import { window, commands, Uri, workspace, Progress, ProgressLocation } from 'vscode';
import { TargetItem, AppItem, ProcessItem, DeviceItem } from '../providers/devices';
import { ssh as proxySSH } from '../iproxy';
import { platformize, devtype } from '../driver/frida';
import { executable } from '../utils';


const exec = promisify(cp.execFile);

const validated = new Map<string, Set<string>>();

const SHARED_ARGS = ['-o', 'StrictHostKeyChecking=no'];

class RemoteTool {
  port?: number;
  dependencies: string[] = [];

  constructor(public id: string, public app: string) { }

  async connect() {
    this.port = await proxySSH(this.id);
    await this.checkRequirement();
  }

  async exec(...cmd: string[]) {
    const [bin, args] = this.cmdSSH(...cmd);
    return exec(bin, args);
  }

  cmdSSH(...cmd: string[]): [string, string[]] {
    return [executable('ssh'), [...SHARED_ARGS, `-p${this.port}`, 'root@localhost', ...cmd]];
  }

  cmdDownload(remote: string, local: string): [string, string[]] {
    return [executable('scp'), [...SHARED_ARGS, `-P${this.port}`, `root@localhost:${remote}`, local]];
  }

  async checkRequirement(): Promise<Boolean> {
    const key = this.constructor.name;
    let registry = validated.get(key);
    if (!registry) {
      registry = new Set();
      validated.set(key, registry);
    }

    if (registry.has(this.id)) { return true; }

    const required = this.dependencies;
    // check for missing commands
    const remoteMissing = [];
    for (const tool of required) {
      try {
        await this.exec('which', tool);
      } catch (_) {
        remoteMissing.push(tool);
      }
    }

    if (remoteMissing.length) {
      throw new Error(`FlexDecrypt requires these command(s) to be installed on device: ${remoteMissing.join(', ')}`);
    }

    registry.add(this.id);
    return true;
  }

  async execInTerminal(shellPath: string, shellArgs: string[]): Promise<void> {
    const t = window.createTerminal({
      name: 'FlexDecrypt Utils',
      shellPath,
      shellArgs
    });

    t.show();

    return new Promise(resolve => {
      const disposable = window.onDidCloseTerminal(term => {
        if (term === t) {
          resolve();
          disposable.dispose();
        }
      });
    });
  }

  async download(remote: string): Promise<string> {
    const cwd = await fsp.mkdtemp(join(tmpdir(), 'flex-'));
    const local = join(cwd, 'archive.zip');
    const [bin, arg] = this.cmdDownload(remote, local);
    await this.execInTerminal(bin, arg);
    return local;
  }

}

const LLDB_PATH = '/usr/bin/debugserver';

class LLDB extends RemoteTool {
  dependencies = [LLDB_PATH, 'ldid'];

  async bridge(uuid: string): Promise<number> {
    // ['lldb', '--local-lldbinit']
    // this.exec(lldb, '-x', 'backboard')
    return 0;
  }

  async go(): Promise<void> {
    // todo:
  }

  async install() {
    // todo: progress
    await this.exec('cp', '/Developer/usr/bin/debugserver', LLDB_PATH);
    // todo: scp
    await this.exec('ldid', '-S/tmp/ent.xml', LLDB_PATH);
  }
}

class Decryptor extends RemoteTool {
  dependencies = ['zip', 'flexdecrypt'];

  async go(dest: string, progress: Progress<{ message?: string; increment?: number }>): Promise<void> {
    progress.report({ message: 'Starting iproxy' });
    await this.connect();
    progress.report({ message: `Fetching the path of ${this.app}` });
    const bundle = await this.bundlePath();
    progress.report({ message: `Creating bundle archive` });
    const cwd = (await this.exec('mktemp', '-d')).stdout.trim();
    const archive = `${cwd}/archive.zip`;
    await this.execInTerminal(...this.cmdSSH('zip', '-r', archive, bundle));
    progress.report({ message: `Downloading bundle archive` });
    const local = await this.download(`${cwd}/archive.zip`);
    progress.report({ message: 'Clean up device' });
    await this.execInTerminal(...this.cmdSSH('rm', archive));

    progress.report({ message: 'Decrypting MachO executables' });
    {
      const py: string = join(__dirname, '..', '..', 'backend', 'ios', 'decrypt.py');
      const [bin, args] = platformize('python3', [py, local, bundle, `${this.port}`, '-o', dest]);
      await this.execInTerminal(bin, args);
    }
  }

  async bundlePath(): Promise<string> {
    const py: string = join(__dirname, '..', '..', 'backend', 'ios', 'installer.py');
    const [bin, args] = platformize('python3', [py, this.app]);

    try {
      const result = await exec(bin, args);
      return result.stdout.trim();
    } catch (e) {
      throw new Error(`Error: App not found or unable to connect to lockdown service. \nReason:\n${e}`);
    }
  }
}

export async function install(node: TargetItem): Promise<void> {
  if (!(node instanceof DeviceItem)) {
    // todo: select from device
    window.showErrorMessage('This command should be used in context menu');
    return;
  }

  const type = await devtype(node.data.id);
  if (type !== 'iOS') {
    window.showErrorMessage(`Unsupported device type: ${type}`);
    return;
  }

  const port = await proxySSH(node.data.id);
  const py: string = join(__dirname, '..', '..', 'backend', 'ios', 'get-flex.py');
  const [shellPath, shellArgs] = platformize('python3', [py, port.toString()]);
  const t = window.createTerminal({
    name: 'FlexDecrypt installer',
    shellPath,
    shellArgs,
  });
  t.show();
  const disposable = window.onDidCloseTerminal(term => {
    if (term === t) {
      window.showInformationMessage(`FlexDecrypt installed on ${node.data.name}`, 'Dismiss');
      disposable.dispose();
    }
  });
}

export async function decrypt(node: TargetItem): Promise<void> {
  if (!(node instanceof AppItem)) {
    window.showErrorMessage('This command should be used in context menu');
    return;
  }

  const preferred = workspace.getConfiguration('frida').get('decryptOutput') || homedir();
  const defaultUri = Uri.file(`${preferred}/${node.data.name}.ipa`);
  const destination = await window.showSaveDialog({
    defaultUri,
    filters: { Archive: ['ipa'] },
  });

  if (!destination) { return; }

  // save preferred path
  workspace.getConfiguration('frida')
    .update('decryptOutput', resolve(join(destination.fsPath, '..')));

  const dec = new Decryptor(node.device.id, node.data.identifier);
  await window.withProgress({
    location: ProgressLocation.Notification,
    title: 'FlexDecrypt running',
    cancellable: false
  }, async (progress, token) => {
    try {
      await dec.go(destination.fsPath, progress);
    } catch (e) {
      window.showErrorMessage(e);
      return;
    }
  });

  const choice = await window.showInformationMessage(
    'FlexDecrypt successfully finished', `Open .ipa`, 'Dismiss');
  if (choice === 'Open .ipa') {
    commands.executeCommand('vscode.open', Uri.file(destination.fsPath));
  }
}

export async function debug(node: TargetItem): Promise<void> {
  if (node instanceof AppItem) {
    if (node.data.pid) {
      // attach
    } else {
      // springboard spawn
    }
  } else if (node instanceof ProcessItem) {
    // node.data.pid
  } else {
    window.showErrorMessage('This command should be used in context menu');
  }

}
