import { join } from 'path';
import { execFile, spawn } from 'child_process';
import { Device, App, Process } from '../types';
import { logger } from '../logger';

import * as os from 'os';

import { VSCodeWriteFileOptions } from '../providers/filesystem';
import { python3Path } from '../utils';

const py = join(__dirname, '..', '..', 'backend', 'driver.py');

export function platformize(tool: string, args: string[]): [string, string[]] {
  let bin = tool;
  let joint = args;
  if (os.platform() === 'win32') {
    bin = 'cmd.exe';
    joint = ['/c', tool, ...args];
  }
  return [bin, joint];
}

export function exec(...args: string[]): Promise<any> {
  return new Promise((resolve, reject) => {
    execFile(python3Path(), [py, ...args], {}, (err, stdout, stderr) => {
      if (err) {
        logger.appendLine(`Error: Failed to execute driver, arguments: ${args.join(' ')}`);
        logger.appendLine(stdout);
        logger.appendLine(stderr);
        logger.appendLine(`Exited with ${err.code}`);
        reject(new Error(stdout));
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

export function port(id: string) {
  return exec('port', id) as Promise<number>;
}

export function location(id: string, bundle: string) {
  return exec('location', id, bundle);
}

export function copyid(id: string) {
  return exec('ssh-copy-id', id);
}

export function setupDebugServer(id: string) {
  return exec('sign-debugserver', id);
}

export async function launch(device: string, bundle: string): Promise<Number> {
  const params = ['-f', bundle, '--device', device, bundle, '--no-pause', '-q', '-e', 'Process.id'];
  const args = ['-m', 'frida_tools.repl', ...params];
  return new Promise((resolve, reject) => {
    execFile(python3Path(), args, {}, (err, stdout) => {
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
  const args = ['-m', 'frida_tools.kill', '--device', device, target];
  return new Promise((resolve, reject) => {
    execFile(python3Path(), args, {}, (err, stdout) => {
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
      const p = spawn(python3Path(), args);
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
      const p = spawn(python3Path(), args);
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
