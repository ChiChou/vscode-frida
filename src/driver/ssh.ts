import * as cp from 'child_process';

import { promisify } from "util";
import { window } from 'vscode';

import { IProxy, useSSH } from '../iproxy';
import { logger } from '../logger';
import { run } from '../term';
import { executable } from '../utils';

const exec = promisify(cp.execFile);
const SHARED_ARGS = ['-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null'];

const validated = new Map<string, Set<string>>();

export class RemoteTool {
  dependencies: string[] = [];
  sshProxy?: IProxy;

  constructor(public id: string) { }

  async connect() {
    this.sshProxy = await useSSH(this.id);
    await this.checkRequirement();
  }

  get port() {
    return this.sshProxy?.local;
  }

  async exec(...cmd: string[]) {
    const [bin, args] = this.ssh(...cmd);
    return exec(bin, args);
  }

  ssh(...cmd: string[]): [string, string[]] {
    const escaped = cmd.map(s => {
      return (s.includes(' ') || s.includes('"')) ?
        `"${s.replace(/"/g, '\\"')}"` :
        s;
    });
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
        logger.appendLine(`[SSH] ERROR: failed to check the existence for ${tool}, reason:`);
        logger.appendLine(`${_}`);
      }
    }

    if (remoteMissing.length) {
      throw new Error(`These command(s) are required on the device: ${remoteMissing.join(', ')}`);
    }

    registry.add(this.id);
    return true;
  }

  async execInTerminal(shellPath: string, shellArgs: string[]): Promise<void> {
    const escape = (args: string[]) => args.map(a => `"${a.replace(/"/g, '\\"')}"`).join(' ');
    logger.appendLine(`[SSH] Execute command: ${shellPath} ${escape(shellArgs)}`);
    return run({
      name: 'SSH',
      shellPath,
      shellArgs
    });
  }
}
