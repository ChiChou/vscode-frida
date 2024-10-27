import * as vscode from 'vscode';
import { join } from 'path';
import { platform } from 'os';
import { DeviceType } from './types';
import { AppItem, ProcessItem } from './providers/devices';

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

export function python3Path(): string {
  interface Api {
    settings: {
      getExecutionDetails() : { execCommand: string[] }
    };
  }

  let interpreter = 'python3';
  try {
    const pyext = vscode.extensions.getExtension('ms-python.python');
    if (pyext) {
      const api = pyext.exports as Api;
      interpreter = api.settings.getExecutionDetails().execCommand[0];
    }
  } catch (_) {

  }

  if (platform() === 'win32' && !interpreter.endsWith('.exe')) {
    interpreter += '.exe';
  }

  return interpreter;
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
