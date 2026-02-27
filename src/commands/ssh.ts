import { spawn } from 'child_process';
import { commands, window, l10n } from 'vscode';

import { os } from '../driver/backend';
import { DeviceItem, TargetItem } from '../providers/devices';
import { run } from '../term';
import { DeviceType } from '../types';
import { executable } from '../utils';
import { logger } from '../logger';


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
            reject(new ToolNotFoundError(l10n.t('inetcat not found')));
          } else {
            reject(err);
          }
        })
        .on('close', (code) => {
          if (code !== 0) {
            reject(new InvalidProtocolError(l10n.t('inetcat exited with code {0}', `${code}`)));
          }
        });

      inetcat.stdout.once('data', (data) => {
        if (data.slice(0, magic.length).equals(magic)) {
          resolve(true);
        } else {
          reject(new InvalidProtocolError(l10n.t('Invalid protocol')));
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
      logger.appendLine(`Error: SSH port ${port} check failed - ${(err as Error).message}`);
    }
  }

  throw new PortNotFoundError(l10n.t('No valid SSH port found'));
}

export async function shell(node: TargetItem) {
  if (!(node instanceof DeviceItem)) {
    window.showErrorMessage(
      l10n.t('This command is only expected to be used in the context menu'));
    return;
  }

  if (node.data.id === 'local') {
    logger.appendLine('Shell: opening local terminal');
    commands.executeCommand('workbench.action.terminal.new');
    return;
  }

  const system = await os(node.data.id);
  const name = l10n.t('SSH: {0}', node.data.name);
  let shellPath, shellArgs;

  if (system === 'ios') {
    if (process.platform === 'win32') {
      window.showErrorMessage(
        l10n.t('This feature is not enabled on Windows due to lack of inetcat'));
      return
    }

    try {
      const port = await findSSHPort(node);
      logger.appendLine(`SSH port found: ${port} for device ${node.data.name}`);
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
        window.showErrorMessage(l10n.t('inetcat command not present in $PATH'));
        return;
      } else if (err instanceof PortNotFoundError) {
        window.showErrorMessage(l10n.t('No valid SSH port found for device {0}', node.data.name));
        return;
      }
    }
  } else if (system === 'android') {
    logger.appendLine(`Shell: ADB shell for device ${node.data.name}`);
    // todo: use adb.ts
    shellPath = executable('adb');
    shellArgs = ['-s', node.data.id, 'shell'];
  } else {
    window.showErrorMessage(l10n.t("OS type {0} is not supported", system));
    return;
  }

  return run({
    name,
    shellArgs,
    shellPath,
    hideFromUser: true,
  });
}