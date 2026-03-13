import { EventEmitter } from 'events';
import { spawn, ChildProcess } from 'child_process';
import { createInterface, Interface } from 'readline';

import { asParam } from './remote';
import { interpreter } from '@/utils';
import { logger } from '@/logger';
import { AppItem, ProcessItem, TargetItem } from '@/providers/devices';

const py = require('path').join(__dirname, '..', '..', 'backend', 'driver.py');

interface PendingCall {
  resolve: (value: any) => void;
  reject: (reason: any) => void;
}

export class InteractiveSession extends EventEmitter {
  private process: ChildProcess;
  private rl: Interface;
  private pending = new Map<number, PendingCall>();
  private nextId = 1;
  private closed = false;

  private constructor(proc: ChildProcess) {
    super();
    this.process = proc;
    this.rl = createInterface({ input: proc.stdout! });

    this.rl.on('line', (line: string) => {
      let msg: any;
      try {
        msg = JSON.parse(line);
      } catch {
        logger.appendLine(`[interactive] invalid JSON from backend: ${line}`);
        return;
      }

      if ('id' in msg) {
        const pending = this.pending.get(msg.id);
        if (pending) {
          this.pending.delete(msg.id);
          if ('error' in msg) {
            pending.reject(new Error(msg.error));
          } else {
            pending.resolve(msg.result);
          }
        }
      } else if (msg.type === 'send') {
        this.emit('message', msg.payload);
      } else if (msg.type === 'ready') {
        this.emit('ready');
      }
    });

    proc.stderr?.on('data', (chunk: Buffer) => {
      logger.appendLine(`[interactive] stderr: ${chunk.toString().trim()}`);
    });

    proc.on('exit', (code) => {
      this.closed = true;
      for (const [, pending] of this.pending) {
        pending.reject(new Error(`Process exited with code ${code}`));
      }
      this.pending.clear();
      this.emit('exit', code);
    });
  }

  static async create(target: TargetItem): Promise<InteractiveSession> {
    const pythonPath = await interpreter();
    const remoteDevices = asParam();

    let bundleOrPid: string[];
    if (target instanceof AppItem) {
      bundleOrPid = ['--app', target.data.identifier];
    } else if (target instanceof ProcessItem) {
      bundleOrPid = ['--pid', target.data.pid.toString()];
    } else {
      throw new Error('Invalid target');
    }

    const args = [py, ...remoteDevices, 'interactive', '--device', target.device.id, ...bundleOrPid];
    logger.appendLine(`[interactive] spawning: ${pythonPath} ${args.join(' ')}`);

    const proc = spawn(pythonPath, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const session = new InteractiveSession(proc);

    return new Promise<InteractiveSession>((resolve, reject) => {
      const onReady = () => {
        cleanup();
        resolve(session);
      };
      const onExit = (code: number) => {
        cleanup();
        reject(new Error(`Interactive backend exited with code ${code} before ready`));
      };
      const cleanup = () => {
        session.removeListener('ready', onReady);
        session.removeListener('exit', onExit);
      };
      session.once('ready', onReady);
      session.once('exit', onExit);
    });
  }

  call(method: string, ...args: any[]): Promise<any> {
    if (this.closed) {
      return Promise.reject(new Error('Session is closed'));
    }

    const id = this.nextId++;
    const cmd = JSON.stringify({ id, method, args }) + '\n';

    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.process.stdin!.write(cmd, (err) => {
        if (err) {
          this.pending.delete(id);
          reject(err);
        }
      });
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;

    for (const [, pending] of this.pending) {
      pending.reject(new Error('Session closed'));
    }
    this.pending.clear();

    try {
      this.process.stdin?.end();
    } catch {
      // stdin may already be destroyed
    }

    // Fallback: force-kill after 3 seconds if it doesn't exit
    const timer = setTimeout(() => {
      try { this.process.kill('SIGTERM'); } catch {}
    }, 3000);

    this.process.once('exit', () => clearTimeout(timer));
  }
}
