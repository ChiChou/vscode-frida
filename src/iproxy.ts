import { EventEmitter } from 'events';
import { createInterface } from 'readline';
import { spawn, ChildProcess } from 'child_process';
import { logger } from './logger';
import { idle, executable, sleep, python3Path } from './utils';
import { join } from 'path';
import { createConnection } from 'net';

let singleton: IProxy | null = null;

export class IProxy extends EventEmitter {
  p?: ChildProcess;
  local = 0;

  constructor(public remote: number | string, public udid: string) { super(); }

  async start(): Promise<number> {
    this.local = await idle();

    const py: string = join(__dirname, '..', 'backend', 'fruit', 'iproxy.py');
    const pyArgs = [py, this.udid, this.remote.toString(), this.local.toString()];
    const p = spawn(python3Path(), pyArgs)
      .on('close', () => {
        logger.appendLine('iproxy is unexpectly terminated');
        this.emit('close');
      })
      .on('error', err => this.emit('error', err));

    if (p.stderr) {
      const rl = createInterface({ input: p.stderr });
      rl.on('line', (line: string) => logger.appendLine(`[iproxy ${this.remote}] ${line}`));
    }

    const MAX = 5;
    for (let i = 0; i < MAX; i++) {
      await sleep(100);

      try {
        // ping
        await new Promise<void>((resolve, reject) => {
          const socket = createConnection({ port: this.local }, () => {
            resolve();
            socket.end();
          }).on('error', (err) => {
            reject(err);
          });
        });

        break;
      } catch(e) {
        if (i === MAX - 1) {
          throw e;
        }
      }
    }

    return this.local;
  }

  stop() {
    if (this.p) { this.p.kill(); }
  }
}

export async function ssh(uuid: string): Promise<number> {
  if (singleton) { return singleton.local; }

  const iproxy = new IProxy('ssh', uuid);
  await iproxy.start();
  iproxy.on('close', () => { singleton = null; });
  singleton = iproxy;
  return singleton.local;
}

export function cleanup() {
  if (singleton) {
    singleton.stop();
    singleton = null;
  }
}
