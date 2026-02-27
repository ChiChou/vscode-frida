import which from 'which';
import * as vscode from 'vscode';
import * as cp from 'child_process';
import { join } from 'path';
import { platform } from 'os';
import { DeviceType } from './types';
import { AppItem, ProcessItem } from './providers/devices';

import shebang from './shebang';
import { logger } from './logger';

export function resource(...paths: string[]): vscode.Uri {
  const file = join(__dirname, '..', 'resources', ...paths);
  return vscode.Uri.file(file);
}

export function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

export function refresh() {
  vscode.commands.executeCommand('frida.ps.refresh');
  vscode.commands.executeCommand('frida.apps.refresh');
}

export function cmd(name: string) {
  return name + (platform() === 'win32' ? '.cmd' : '');
}

export function executable(name: string) {
  return name + (platform() === 'win32' ? '.exe' : '');
}

interface PythonExtensionApi {
  settings: {
    getExecutionDetails(): { execCommand: string[] };
    get onDidChangeExecutionDetails(): vscode.Event<vscode.Uri | undefined>;
  };
}

async function virtualenv(): Promise<string> {
  const pyext = vscode.extensions.getExtension('ms-python.python');
  if (!pyext) {
    throw new Error(vscode.l10n.t('Python extension not found'));
  }

  const api = pyext.exports as PythonExtensionApi;
  const { execCommand } = api.settings.getExecutionDetails();
  if (!execCommand) {
    throw new Error(vscode.l10n.t('Python extension not activated'));
  }

  api.settings.onDidChangeExecutionDetails(() => {
    cache.clear();
  });

  const cmd = [...execCommand, '-c', 'import frida_tools;import sys;print(sys.executable)'];

  return new Promise((resolve, reject) => {
    cp.execFile(cmd[0], cmd.slice(1), {}, (err, stdout) => {
      if (err) {
        reject(err);
      } else {
        resolve(stdout.trim());
      }
    });
  });
}

const cache = new Map<string, string>();

export async function interpreter(cli = 'frida'): Promise<string> {
  if (cache.has(cli)) { return Promise.resolve(cache.get(cli) as string); }

  try {
    const path = await virtualenv();
    logger.appendLine(`Resolved Python interpreter (virtualenv): ${path}`);
    return path;
  } catch (_) {
    // fallback to global package
  }

  const where = await which(cli, { all: false, nothrow: true });
  if (!where) {
    const msg = vscode.l10n.t('Could not find command {0} in $PATH, have you installed it or activated the correct venv?', cli);
    throw new Error(msg);
  }

  const path = await shebang(where);
  logger.appendLine(`Resolved Python interpreter (PATH): ${path}`);
  cache.set(cli, path);
  return path;
}

export function expandDevParam(node: AppItem | ProcessItem) {
  switch (node.device.type) {
    case DeviceType.Local:
      return [];
    case DeviceType.Remote:
      return ['-H', node.device.id.substring('socket@'.length)];
    case DeviceType.USB:
    // return ['-U'];
    default:
      return ['--device', node.device.id];
  }
}
