import { join } from 'path';

import { execFile, spawn } from 'child_process';
import { Device, App, Process } from '../types';

import * as os from 'os';

import { VSCodeWriteFileOptions } from '../providers/filesystem';

const py = join(__dirname, '..', '..', 'backend', 'driver.py');

export function platformize(tool: string, args: string[]): [string, string[]] {
  let bin = tool;
  let joint = args;
  if (os.platform() === 'win32') {
    bin = 'cmd.exe';
    joint = ['/c', 'frida', ...args];
  }
  return [bin, joint];
}

export function exec(...args: string[]): Promise<any> {
  return new Promise((resolve, reject) => {
    execFile('python3', [py, ...args], {}, (err, stdout, stderr) => {
      if (err) {
        reject(err);
      } else {
        resolve(JSON.parse(stdout));
      }
    });
  });
}

export function devices() {
  return exec('devices') as Promise<Device[]>;
}

export function apps(id: string) {
  return exec('apps', id) as Promise<App[]>;
}

export function ps(id: string) {
  return exec('ps', id) as Promise<Process[]>;
}

export function devtype(id: string) {
  return exec('type', id) as Promise<string>;
}

export async function launch(device: string, bundle: string): Promise<Number> {
  const params = ['-f', bundle, '--device', device, bundle, '--no-pause', '-q', '-e', 'Process.id'];
  const [bin, args] = platformize('frida', params);
  return new Promise((resolve, reject) => {
    execFile(bin, args, {}, (err, stdout) => {
      if (err) {
        reject(err);
      } else {
        const lines = stdout.split('\n');
        if (lines.length <= 2) {
          reject(new Error(`Unknown output: ${stdout}`));
        }
        resolve(parseInt(lines[1], 10));
      }
    });
  });
}

export function terminate(device: string, target: string) {
  const [bin, args] = platformize('frida-kill', ['--device', device, target]);

  return new Promise((resolve, reject) => {
    execFile(bin, args, {}, (err, stdout) => {
      if (err) {
        reject(err);
      } else {
        resolve(stdout);
      }
    });
  });
}

export namespace fs {
  export async function download(device: string, pid: number, uri: string): Promise<Uint8Array> {
    const args = [py, 'download', uri, '--device', device, '--pid', pid.toString()];

    return new Promise((resolve, reject) => {
      const p = spawn('python3', args);
      const parts: Buffer[] = [];
      p.stdout.on('data', data => parts.push(data));
      p.on('close', (code, signal) => {
        if (code === 0) {
          resolve(new Uint8Array(Buffer.concat(parts)));
        } else {
          reject(new Error(`process exited with code ${code}`));
        }
      });
    });
  }

  export async function upload(device: string, pid: number, uri: string, content: Uint8Array,
    options: VSCodeWriteFileOptions): Promise<void> {
    // todo: options
    const args = [py, 'upload', uri, '--device', device, '--pid', pid.toString()];
    return new Promise((resolve, reject) => {
      const p = spawn('python3', args);
      p.on('close', (code: number, signal: NodeJS.Signals) => {
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`process exited with code ${code}`));
        }
      });
      p.stdin.end(Buffer.from(content));
    });
  }
}
