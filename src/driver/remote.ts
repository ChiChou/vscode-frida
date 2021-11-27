import * as cp from 'child_process';

import { ssh as proxySSH } from '../iproxy';
import { promises as fsp } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { promisify } from "util";
import { window } from 'vscode';
import { IProxy } from "../iproxy";
import { logger } from '../logger';
import { executable } from '../utils';
import { run } from '../term';

const exec = promisify(cp.execFile);
const SHARED_ARGS = ['-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null'];

const validated = new Map<string, Set<string>>();

export class RemoteTool {
  dependencies: string[] = [];
  sshProxy?: IProxy;

  constructor(public id: string) { }

  async connect() {
    this.sshProxy = await proxySSH(this.id);
    await this.checkRequirement();
  }

  get port() {
    return this.sshProxy?.local
  }

  async exec(...cmd: string[]) {
    const [bin, args] = this.ssh(...cmd);
    return exec(bin, args);
  }

  ssh(...cmd: string[]): [string, string[]] {
    const escaped = cmd.map(s => {
      if (s.includes(' ') || s.includes('"'))
        return `"${s.replace(/"/g, '\\"')}"`;  
      return s;
    })
    return [executable('ssh'), [...SHARED_ARGS, '-q', `-p${this.port}`, 'root@localhost', ...escaped]];
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
    const escape = (args: string[]) => args.map(a => `"${a.replace(/"/g, '\\"')}"`).join(' ')
    logger.appendLine(`[fouldecrypt] Execute command: ${shellPath} ${escape(shellArgs)}`);
    return run({
      name: 'FoulDecrypt Utils',
      shellPath,
      shellArgs
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
