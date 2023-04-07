import { join } from 'path';
import { execFile } from 'child_process';
import { Device, App, Process } from '../types';
import { logger } from '../logger';

import { python3Path } from '../utils';
import { run } from '../term';
import { window } from 'vscode';
import { asParam } from './remote';

const py = join(__dirname, '..', '..', 'backend', 'driver.py');

export function exec(...args: string[]): Promise<any> {
  const remoteDevices = asParam();
  return new Promise((resolve, reject) => {
    execFile(python3Path(), [py, ...remoteDevices, ...args], {}, (err, stdout, stderr) => {
      if (err) {
        if (stderr.includes('Unable to import frida')) {
          window.showErrorMessage('Frida python module not detected. Do you want to install now?', 'Install', 'Calcel')
            .then(selected => {
              if (selected === 'Install') {
                run({
                  shellPath: python3Path(),
                  shellArgs: ['-m', 'pip', 'install', 'frida-tools']
                });
              }
          });
        }
        logger.appendLine(`Error: Failed to execute driver, arguments: ${args.join(' ')}`);
        logger.appendLine(stderr);
        logger.appendLine(`Exited with ${err.code}`);
        reject(new Error(stderr));
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

export async function os(id: string) {
  interface result {
    os: {
      version: string;
      id: 'ios' | 'macos' | 'windows' | 'linux' | 'android';
      name: string;
    }
  }

  const result = await exec('info', id) as result;
  return result.os.id;
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

export function lockdownSyslog(id: string, bundleOrPid: string[]) {
  return run({
    name: `Syslog: ${bundleOrPid}`,
    shellPath: python3Path(),
    shellArgs: [py, 'syslog2', '--device', id, ...bundleOrPid]
  });
}

function deviceParam(device: string) {
  const prefix = 'socket@';
  return device.startsWith(prefix) ?
    ['-H', device.substring(prefix.length)] :
    ['--device', device];
}

export async function launch(device: string, bundle: string): Promise<Number> {
  const params = ['-f', bundle, ...deviceParam(device), bundle, '-q', '-e', 'Process.id'];
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
  const args = ['-m', 'frida_tools.kill', ...deviceParam(device), target];
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

