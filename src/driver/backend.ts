import { join } from "path";
import { execFile } from 'child_process';
import { OutputChannel, window } from 'vscode';

import { asParam } from './remote';
import { logger } from '../logger';
import { run } from '../term';
import { python3Path } from '../utils';
import { App, Device, Process } from '../types';
import { AppItem, DeviceItem, ProcessItem, TargetItem } from '../providers/devices';

const base = join(__dirname, '..', '..', 'backend');
const py = join(base, 'driver.py');

export const driverScript = () => py;

export function flags(node: TargetItem) {
  if (node instanceof DeviceItem) {
    return ['--device', node.data.id];
  } else if (node instanceof AppItem) {
    return ['--app', node.data.identifier];
  } else if (node instanceof ProcessItem) {
    return ['--pid', node.data.pid.toString()];
  }

  throw new Error(`Invalid target "${node}"`);
}

function askInstallFrida() {
  window.showErrorMessage(`Frida python module not detected. Please check your Python interpreter setting,
or pip install frida-tools. Do you want to install now?`, 'Install', 'Cancel')
    .then(selected => {
      if (selected === 'Install') {
        run({
          shellPath: python3Path(),
          shellArgs: ['-m', 'pip', 'install', 'frida-tools']
        });
      }
    });
}

export function exec(...args: string[]): Promise<any> {
  const remoteDevices = asParam();
  return new Promise((resolve, reject) => {
    execFile(python3Path(), [py, ...remoteDevices, ...args], {}, (err, stdout, stderr) => {
      if (err) {
        if (stderr.includes('Unable to import frida')) {
          askInstallFrida();
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

export function lockdownSyslog(id: string, bundleOrPid: string[]) {
  return run({
    name: `Syslog: ${bundleOrPid}`,
    shellPath: python3Path(),
    shellArgs: [py, 'syslog2', '--device', id, ...bundleOrPid]
  });
}
