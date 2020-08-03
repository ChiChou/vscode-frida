import { EventEmitter } from 'events';
import { createInterface } from 'readline';
import { spawn, ChildProcess } from 'child_process';
import { logger } from './logger';
import { idle, executable } from './utils';
import { SIGALRM } from 'constants';

let singleton: IProxy | null = null;

class IProxy extends EventEmitter {
  p?: ChildProcess;
  local = 0;
  ready = false;

  constructor(public remote: number, public uuid: string) { super(); }

  async start() {
    this.local = await idle();
    this.p = spawn(executable('iproxy'), [
      this.local.toString(), this.remote.toString(), this.uuid]);

    if (this.p.stderr) {
      const rl = createInterface({ input: this.p.stderr });
      rl.on('line', (line: string) => logger.appendLine(`[iproxy ${this.remote}] ${line}`));
    }

    this.p.on('close', () => {
      logger.appendLine('iproxy is unexpectly terminated');
      this.emit('close');
    });

    this.ready = true;
    this.emit('ready');
    
    return this.local;
  }

  stop() {
    if (this.p) { this.p.kill(); }
    this.ready = false;
  }
}

export async function ssh(uuid: string): Promise<number> {
  if (singleton) {
    if (singleton.ready) { return singleton.local; }
    return new Promise((resolve, reject) => {
      singleton!
        .on('ready', () => resolve(singleton!.local))
        .on('close', () => reject(new Error('iproxy abnormally terminated')));
    });
  }

  singleton = new IProxy(22, uuid);
  singleton.on('close', () => { singleton = null; });
  return singleton.start();
}

export function cleanup() {
  if (singleton) {
    singleton.stop();
    singleton = null;
  }
}
