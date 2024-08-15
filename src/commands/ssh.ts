import { spawn } from 'node:child_process';
import { commands, window } from 'vscode';

import { os } from '../driver/backend';
import { DeviceItem, TargetItem } from '../providers/devices';
import { run } from '../term';
import { DeviceType } from '../types';
import { executable } from '../utils';


class PortNotFoundError extends Error { }
class ToolNotFoundError extends Error { }
class InvalidProtocolError extends Error { }


const inetcat = executable('inetcat');

async function verifySSH(...args: string[]) {
  const magic = 'SSH-2.0-';

  return new Promise((resolve, reject) => {
    const cp = spawn(inetcat, args);
    cp
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

    cp.stdout.on('readable', () => {
      const trunk = cp.stdout.read();
      resolve(trunk && trunk.toString().startsWith(magic));
    });
  });
}

async function findSSHPort(args: string[] = []) {
  const candidates = [22, 44];

  for (const port of candidates) {
    try {
      if (await verifySSH(port.toString(), ...args)) {
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
    const args = ['-u', node.data.id];
    if (node.data.type === DeviceType.Remote) {
      args.push('-n');
    }

    try {
      const port = await findSSHPort(args);
      shellPath = executable('ssh');
      shellArgs = [
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'UserKnownHostsFile=/dev/null',
        // there is a potential command injection
        // {inetcat} is hardcoded, and the only risk is device uuid, 
        // looks impossible to inject arbitrary text
        '-o', `ProxyCommand=${inetcat} ${port} ${args.join(' ')}`,
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