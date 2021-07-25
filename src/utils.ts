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
  let interpreter = 'python3';
  const pyext = vscode.extensions.getExtension('ms-python.python');
  if (pyext) { interpreter = pyext.exports.settings.getExecutionDetails().execCommand[0]; }
  if (platform() === 'win32' && !interpreter.endsWith('.exe')) { interpreter += '.exe'; }
  return interpreter;
}