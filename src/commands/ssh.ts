import { exec, spawn } from 'child_process';
import { commands, window } from 'vscode';

import { os } from '../driver/backend';
import { DeviceItem, TargetItem } from '../providers/devices';
import { run } from '../term';
import { DeviceType } from '../types';
import { cmd, executable } from '../utils';


class PortNotFoundError extends Error { }
class ToolNotFoundError extends Error { }
class InvalidProtocolError extends Error { }

const nc = executable('inetcat');

async function findSSHPort(device: DeviceItem) {
  function validate(port: number, ...args: string[]): Promise<boolean> {
    const magic = Buffer.from('SSH-2.0-');
    return new Promise((resolve, reject) => {
      const inetcat = spawn(nc, [port.toString(), ...args]);
      inetcat
        .on('error', (err) => {
          if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
            reject(new ToolNotFoundError('inetcat not found'));
          } else {
            reject(err);
          }
        })
        .on('close', (code) => {
          if (code !== 0) {
            reject(new InvalidProtocolError(`inetcat exited with code ${code}`));
          }
        });

      inetcat.stdout.once('data', (data) => {
        if (data.slice(0, magic.length).equals(magic)) {
          resolve(true);
        } else {
          reject(new InvalidProtocolError(`port ${port} did not return SSH banner`));
        }
        inetcat.stdin.end();
      });
    });
  }

  const candidates = [22, 44];
  const args = ['-u', device.data.id];
  if (device.data.type === DeviceType.Remote) {
    args.push('-n');
  }

  for (const port of candidates) {
    try {
      if (await validate(port, ...args)) {
        return port;
      }
    } catch (err) {
      if (err instanceof ToolNotFoundError) { throw err; }
      console.error((err as Error).message);
    }
  }

  throw new PortNotFoundError('No valid SSH port found');
}

export async function shell(node: TargetItem) {
  if (!(node instanceof DeviceItem)) {
    window.showErrorMessage('This command is only avaliable on context menu');
    return;
  }

  if (node.data.id === 'local') {
    // execute command to open a new terminal
    commands.executeCommand('workbench.action.terminal.new');
    return;
  }

  const system = await os(node.data.id);
  const name = `SSH: ${node.data.name}`;
  let shellPath, shellArgs;

  if (system === 'ios') {
    try {
      const port = await findSSHPort(node);
      shellPath = executable('ssh');
      shellArgs = [
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', `ProxyCommand='${nc}' 22`,
        `mobile@localhost`,  // todo: customize username
        '-p', port.toString()
      ];
    } catch (err) {
      if (err instanceof ToolNotFoundError) {
        window.showErrorMessage('inetcat command not present in $PATH');
        return;
      } else if (err instanceof PortNotFoundError) {
        window.showErrorMessage(`No valid SSH port found for device ${node.data.name}`);
        return;
      }
    }
  } else if (system === 'android') {
    // todo: use adb.ts
    shellPath = executable('adb');
    shellArgs = ['-s', node.data.id, 'shell'];
  } else {
    window.showErrorMessage(`OS type "${system}" is not supported`);
    return;
  }

  return run({
    name,
    shellArgs,
    shellPath,
    hideFromUser: true,
  });
}