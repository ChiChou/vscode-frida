import { join } from "path";
import { execFile } from 'child_process';

import { asParam } from './remote';
import { logger } from '../logger';
import { run } from '../term';
import { interpreter } from '../utils';
import { App, Device, Process } from '../types';
import { AppItem, ProcessItem, TargetItem } from '../providers/devices';

const base = join(__dirname, '..', '..', 'backend');
const py = join(base, 'driver.py');

export const driverScript = () => py;

export function exec(...args: string[]): Promise<any> {
  const remoteDevices = asParam();

  return interpreter().then(path => new Promise((resolve, reject) => {
    execFile(path, [py, ...remoteDevices, ...args], { maxBuffer: 1024 * 1024 * 20 }, (err, stdout, stderr) => {
      if (err) {
        logger.appendLine(`Error: Failed to execute driver, arguments: ${args.join(' ')}`);
        logger.appendLine(stderr);
        logger.appendLine(`Exited with ${err.code}`);
        reject(new Error(stderr));
      } else {
        resolve(JSON.parse(stdout));
      }
    });
  }));
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
  interface Result {
    os: {
      version: string;
      id: 'ios' | 'macos' | 'windows' | 'linux' | 'android';
      name: string;
    };
  };

  const result = await exec('info', id) as Result;
  return result.os.id;
}

export function location(id: string, bundle: string) {
  return exec('location', id, bundle);
}

export function rpc(target: TargetItem, method: string, ...args: string[]) {
  let bundleOrPid: string[];
  if (target instanceof AppItem) {
    bundleOrPid = ['--app', target.data.identifier];
  } else if (target instanceof ProcessItem) {
    bundleOrPid = ['--pid', target.data.pid.toString()];
  } else {
    throw new Error(`Invalid target "${target}"`);
  }

  return exec('rpc', '--device', target.device.id, ...bundleOrPid, method, ...args);
}

export async function lockdownSyslog(id: string, bundleOrPid: string[]) {
  const shellPath = await interpreter();
  return run({
    name: `Syslog: ${bundleOrPid}`,
    shellPath,
    shellArgs: [py, 'syslog2', '--device', id, ...bundleOrPid]
  });
}
