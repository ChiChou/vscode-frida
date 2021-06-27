import * as vscode from 'vscode';
import * as net from 'net';
import { join } from 'path';
import { platform } from 'os';

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
  // use settings from Python extension
  let python3Path = vscode.workspace.getConfiguration('python').get('pythonPath', 'python')

  if (platform() === 'win32' && !python3Path.endsWith('.exe')) {
    python3Path += '.exe'
  }
  return python3Path;
}