import { join } from 'path';

import { execFile } from 'child_process';
import { Device, App, Process } from '../types';

const py: string = join(__dirname, '..', '..', 'cmds', 'driver.py');

function driver(...args: string[]) {
  return new Promise((resolve, reject) => {
    execFile('python3', [py, ...args], {}, (err, stdout, stderr) => {
      if (err) { 
        reject(new Error(stdout));
      } else {
        resolve(JSON.parse(stdout));
      }
    });
  });
}

export function devices() {
  return driver('devices') as Promise<Device[]>;
}

export function apps(id: string) {
  return driver('apps', '--device', id) as Promise<App[]>;
}

export function ps(id: string) {
  return driver('ps', '--device', id) as Promise<Process[]>;
}

export function rpc() {
  
}

export function devtype(id: string) {
  return driver('devtype', '--device', id) as Promise<string>;
}