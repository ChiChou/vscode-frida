import { EventEmitter } from 'events';
import { createInterface } from 'readline';
import { spawn, ChildProcess } from 'child_process';
import { logger } from './logger';
import { idle, sleep, python3Path } from './utils';
import { createConnection } from 'net';
import { fruit } from './driver/backend';

export class IProxy extends EventEmitter {
  p?: ChildProcess;
  local = 0;
  refCount = 0;

  constructor(public remote: number | string, public udid: string) { super(); }

  async start(): Promise<number> {
    this.local = await idle();

    const py: string = fruit('iproxy.py');
    const pyArgs = [py, this.udid, this.remote.toString(), this.local.toString()];
    const p = this.p = spawn(python3Path(), pyArgs)
      .on('close', () => {
        logger.appendLine('iproxy unexpectly terminated');
        this.emit('close');
      })
      .on('error', err => this.emit('error', err));

    if (p.stderr) {
      const rl = createInterface({ input: p.stderr });
      rl.on('line', (line: string) => logger.appendLine(`[iproxy ${this.remote}] ${line}`));
    }

    process.on('beforeExit', () => p.kill());

    const MAX = 50;
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
      } catch (e) {
        if (i === MAX - 1) {
          throw e;
        }
      }
    }

    this.refCount = 1;
    return this.local;
  }

  stop() {
    if (this.p) { this.p.kill(); }
    this.emit('close');
  }

  retain() {
    this.refCount++;
  }

  release() {
    this.refCount--;
    if (this.refCount <= 0) {
      this.stop();
    }
  }
}

const map = new Map<string, IProxy>();

export async function ssh(uuid: string): Promise<IProxy> {
  const existing = map.get(uuid)
  if (existing) {
    existing.retain();
    return existing;
  }

  const iproxy = new IProxy('ssh', uuid);
  map.set(uuid, iproxy);
  await iproxy.start();
  const remove = () => { map.delete(uuid) };
  iproxy.on('close', remove);
  iproxy.on('error', remove);
  return iproxy;
}

export function cleanup() {
  map.forEach(entry => entry.stop());
  map.clear();
}
