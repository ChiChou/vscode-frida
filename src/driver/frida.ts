import { join } from 'path';

import { execFile } from 'child_process';
import { Device, App, Process } from '../providers/devices';

const py: string = join(__dirname, '..', '..', 'cmds', 'driver.py');

function driver(...args: string[]) {
  return new Promise((resolve, reject) => {
    execFile('python3', [py, ...args], {}, (err, stdout, stderr) => {
      if (err) { reject(err); }
      resolve(JSON.parse(stdout.toString()));
    });
  });
}

export function devices() {
  return driver('devices') as Promise<Device[]>;
}

export function apps(id: string) {
  return driver('apps', id) as Promise<App[]>;
}

export function ps(id: string) {
  return driver('ps', id) as Promise<Process[]>;
}