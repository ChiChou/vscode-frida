import * as vscode from 'vscode';
import * as net from 'net';
import * as cp from 'child_process';
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

export function executable(cmd: string) {
  return cmd + (platform() === 'win32' ? '.exe' : '');
}

export function idle(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer()
      .on('error', reject)
      .listen(0, () => {
        const { port } = server.address() as net.AddressInfo;
        resolve(port);
        server.close();
      });
  });
}

export function python3Path(): string {
  let interpreter = 'python3';
  const pyext = vscode.extensions.getExtension('ms-python.python');
  if (pyext) { interpreter = pyext.exports.settings.getExecutionDetails().execCommand[0]; }
  if (platform() === 'win32' && !interpreter.endsWith('.exe')) { interpreter += '.exe'; }
  return interpreter;
}

export function showInFolder(destination: vscode.Uri): void {
  const o = platform();
  const detached = (bin: string, ...args: string[]) =>
    cp.spawn(bin, args, { detached: true, stdio: 'ignore' }).unref();

  const folder = vscode.Uri.joinPath(destination, '..').fsPath;
  if (o === 'win32') {
    detached('explorer.exe', '/select,', destination.fsPath);
    return
  } else if (o === 'linux') {
    for (const tool of ['xdg-open', 'gnome-open']) {
      try {
        detached(tool, folder)
        return
      } catch(e) {
        continue
      }
    }
  } else if (o === 'darwin') {
    detached('open', '-a', 'Finder', folder);
    return;
  }

  vscode.window.showWarningMessage('Your platform does not support this command');
}

export function expandDevParam(node: AppItem | ProcessItem) {
  switch (node.device.type) {
    case DeviceType.Local:
      return [];
    case DeviceType.Remote:
      return ['-H', node.device.id.substring('socket@'.length)];
    case DeviceType.USB:
      return ['-U'];
    default:
      return ['--device', node.device.id];
  }
}
