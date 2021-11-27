import * as cp from 'child_process';
import { promisify } from 'util';
import { join, basename } from 'path';
import { tmpdir, homedir } from 'os';
import { promises as fsp } from 'fs';
import { window, commands, Uri, workspace, Progress, ProgressLocation } from 'vscode';
import { TargetItem, AppItem, ProcessItem, DeviceItem } from '../providers/devices';
import { ssh as proxySSH, IProxy } from '../iproxy';
import { devtype, port, location, setupDebugServer } from '../driver/frida';
import { executable, python3Path, showInFolder } from '../utils';
import { logger } from '../logger';
import { run } from '../term';


const exec = promisify(cp.execFile);

const validated = new Map<string, Set<string>>();

const SHARED_ARGS = ['-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null'];

class RemoteTool {
  port?: number;
  dependencies: string[] = [];

  constructor(public id: string) { }

  async connect() {
    this.port = await proxySSH(this.id);
    await this.checkRequirement();
  }

  async exec(...cmd: string[]) {
    const [bin, args] = this.ssh(...cmd);
    return exec(bin, args);
  }

  ssh(...cmd: string[]): [string, string[]] {
    return [executable('ssh'), [...SHARED_ARGS, '-q', `-p${this.port}`, 'root@localhost', ...cmd]];
  }

  scp(src: string, dst: string, dir: 'up' | 'down' = 'down'): [string, string[]] {
    const prefix = 'root@localhost:';
    const pair = dir === 'down' ? [prefix + src, dst] : [src, prefix + dst];
    return [executable('scp'), [...SHARED_ARGS, `-P${this.port}`, ...pair]];
  }

  async checkRequirement(): Promise<Boolean> {
    const key = this.constructor.name;
    let registry = validated.get(key);
    if (!registry) {
      registry = new Set();
      validated.set(key, registry);
    }

    if (registry.has(this.id)) { return true; }

    try {
      await this.exec('id');
    } catch (_) {
      logger.appendLine(`Shell is not avaliable on ${this.id}`);
      logger.appendLine(`reason: ${_}`);

      window.showErrorMessage('Unable to establish SSH connection to device');
    }

    const required = this.dependencies;
    // check for missing commands
    const remoteMissing = [];
    for (const tool of required) {
      try {
        await this.exec('which', tool);
      } catch (_) {
        remoteMissing.push(tool);
        logger.appendLine(`[fouldecrypt] ERROR: failed to check the existence for ${tool}, reason:`);
        logger.appendLine(`${_}`);
      }
    }

    if (remoteMissing.length) {
      throw new Error(`FoulDecrypt requires these command(s) to be installed on device: ${remoteMissing.join(', ')}`);
    }

    registry.add(this.id);
    return true;
  }

  async execInTerminal(shellPath: string, shellArgs: string[]): Promise<void> {
    const t = window.createTerminal({
      name: 'FoulDecrypt Utils',
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
    const cwd = await fsp.mkdtemp(join(tmpdir(), 'foul-'));
    const local = join(cwd, 'archive.zip');
    const [bin, arg] = this.scp(remote, local);
    await this.execInTerminal(bin, arg);
    return local;
  }

}

const LLDB_PATH = '/usr/bin/debugserver';

function dbg() {
  return function (target: LLDB, propertyKey: string, descriptor: PropertyDescriptor) {
    const original = descriptor.value;
    descriptor.value = async function (this: LLDB, ...args: any[]) {
      await this.connect();
      await this.bridge();
      const server = await original.call(this, ...args) as cp.ChildProcess;

      await new Promise((resolve, reject) => {
        server.on('exit', (code) => {
          if (code !== 0) {
            reject(new Error(`debugserver exited with ${code}`));
          }
          this.teardown();
        });
        setTimeout(resolve, 1000);
      });

      this.debugServer = server;
      await this.execInTerminal('lldb', [
        '--one-line',
        `process connect connect://127.1:${this.serverPort}`,
        '--one-line',
        'bt',
        '--one-line',
        'reg read'
      ]);
    };
  };
}

class LLDB extends RemoteTool {
  dependencies = [LLDB_PATH, 'ldid'];
  iproxy?: IProxy;
  serverPort?: number;
  remotePort?: number;
  debugProxy?: cp.ChildProcess;
  debugServer?: cp.ChildProcess;

  async bridge(): Promise<void> {
    this.remotePort = await port(this.id);
    this.iproxy = new IProxy(this.remotePort, this.id);
    this.serverPort = await this.iproxy.start();
  }

  @dbg()
  async spawn(bundle: string): Promise<cp.ChildProcess> {
    const path = await location(this.id, bundle);
    const [bin, arg] = this.ssh(LLDB_PATH, '-x', 'backboard', `127.1:${this.remotePort}`, path);
    return cp.spawn(bin, arg);
  }

  @dbg()
  async attach(target: number | string): Promise<cp.ChildProcess> {
    const [bin, arg] = this.ssh(LLDB_PATH, `127.1:${this.remotePort}`, '-a', target.toString());
    return cp.spawn(bin, arg);
  }

  teardown() {
    if (this.iproxy) {
      this.iproxy.stop();
      this.iproxy = undefined;
    }

    if (this.debugServer) {
      this.debugServer.kill();
      this.remotePort = undefined;
      this.debugProxy = undefined;
    }
  }
}

type Bar = Progress<{ message?: string; increment?: number }>;

class Decryptor extends RemoteTool {
  dependencies = ['zip', 'fouldecrypt'];

  async go(bundle: string, dest: string, progress: Bar): Promise<void> {
    progress.report({ message: 'Starting iproxy' });
    await this.connect();
    progress.report({ message: `Fetching the path of ${bundle}` });
    const path = await location(this.id, bundle);
    progress.report({ message: `Creating bundle archive` });
    const cwd = (await this.exec('mktemp', '-d')).stdout.trim();
    const archive = `${cwd}/archive.zip`;
    await this.execInTerminal(...this.ssh('zip', '-r', archive, path));
    progress.report({ message: `Downloading bundle archive` });
    const local = await this.download(`${cwd}/archive.zip`);
    progress.report({ message: 'Clean up device' });
    await this.execInTerminal(...this.ssh('rm', archive));

    progress.report({ message: 'Decrypting MachO executables' });
    {
      const py: string = join(__dirname, '..', '..', 'backend', 'fruit', 'decrypt.py');
      const bin = python3Path();
      const args = [py, local, path, `${this.port}`, '-o', dest];
      await this.execInTerminal(bin, args);
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
  const py: string = join(__dirname, '..', '..', 'backend', 'fruit', 'get-foul.py');
  const shellArgs = [py, port.toString()];

  try {
    await run({
      name: 'FoulDecrypt installer',
      shellPath: python3Path(),
      shellArgs,
    });
  } catch(e) {
    window.showErrorMessage('Failed to install FoulDecrypt');
    return;
  }

  window.showInformationMessage(`FoulDecrypt installed on ${node.data.name}`, 'Dismiss');
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

  const folder = Uri.joinPath(destination, '..').fsPath;
  const name = `${basename(destination.fsPath)}.ipa`;

  // save preferred path
  workspace.getConfiguration('frida').update('decryptOutput', folder, true);

  const dec = new Decryptor(node.device.id);
  await window.withProgress({
    location: ProgressLocation.Notification,
    title: 'FoulDecrypt running',
    cancellable: false
  }, (progress) => dec.go(node.data.identifier, destination.fsPath, progress));

  const choice = await window.showInformationMessage(
    'FoulDecrypt successfully finished', 'Open Folder', `Open ${name}`, 'Dismiss');
  if (choice === `Open ${name}`) {
    commands.executeCommand('vscode.open', destination);
  } else if (choice === 'Open Folder') {
    showInFolder(destination);
  }
}

const lldbInstances = new Set<LLDB>();

export async function setupLLDBServer(node: TargetItem): Promise<void> {
  if (node instanceof DeviceItem) {
    if (await devtype(node.data.id) === 'iOS') {
      if (await setupDebugServer(node.data.id)) {
        window.showInformationMessage('Successfully resigned debugserver');
      }
    } else {
      window.showErrorMessage('This command is for iOS only');
    }
  } else {
    // todo: select from list
    window.showErrorMessage('Use the context menu instead');
  }
}

export async function debug(node: TargetItem): Promise<void> {
  if (!(node instanceof AppItem) && !(node instanceof ProcessItem)) {
    window.showErrorMessage('This command should be used in context menu');
    return;
  }

  if (node.device.id === 'local') {
    window.showErrorMessage('debug local process is not implemented yet');
    return;
  }

  const lldb = new LLDB(node.device.id);
  try {
    await lldb.connect();
  } catch (e) {
    if (await window.showErrorMessage(`${e}`, 'Deploy debugserver', 'Cancel') === 'Deploy debugserver') {
      setupDebugServer(node.device.id);
      return;
    }
  }

  lldbInstances.add(lldb);
  if (node instanceof AppItem) {
    if (node.data.pid) {
      await lldb.attach(node.data.pid);
    } else {
      await lldb.spawn(node.data.identifier);
    }
    lldbInstances.delete(lldb);
  } else if (node instanceof ProcessItem) {
    await lldb.attach(node.data.pid);
  }
  lldbInstances.delete(lldb);
}

export function cleanup() {
  for (const lldb of lldbInstances) {
    lldb.teardown();
  }
}
