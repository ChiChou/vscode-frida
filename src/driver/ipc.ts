import * as cp from 'child_process';
import * as path from 'path';

import { tmpdir } from 'os';
import { promises as fs } from 'fs';

import axios, { AxiosInstance } from 'axios';
import { App, Process, Device } from '../types';
import { window } from 'vscode';

let cwd: string;
let socketPath: string;
let client: AxiosInstance;
let server: cp.ChildProcess;
let ready = false;

export async function init() {
  cwd = await fs.mkdtemp(path.join(tmpdir(), 'vscode-frida-'));
  socketPath = path.join(cwd, 'ipc');
  client = axios.create({ socketPath });
  server = cp.spawn('vscode-frida-server', {
    env: Object.assign({
      SOCKET_PATH: socketPath
    }, process.env),
  });

  server.on('close', () => window.showErrorMessage('FATAL Error: vscode-frida-server unexpectly disconnected'));
  server.on('error', async e => {
    ready = false;
    if ((e as any).code === 'ENOENT') {
      const selected = await window.showErrorMessage(
        `vscode-frida-server has not been installed. Are you going to install it and reload VSCode?`,
        'Install Now', 'Cancel');
      if (selected === 'Install Now') {
        window.createTerminal(`npm`, 'npm', ['install', '-g', 'vscode-frida-server']).show();
      }
    } else {
      window.showErrorMessage(e.toString());
    }
  });
  
  return new Promise((resolve) => {
    server.stdout?.on('data', (data) => {
      if (data.toString() === '%SERVER_READY%') {
        ready = true;
        resolve();
      }
    });
  });
}

export function alive() {
  return ready;
}

export async function teardown() {
  server.kill();
  await fs.unlink(socketPath);
  await fs.unlink(cwd);
}

export function devices() {
  return client.get('/device/list').then(r => r.data) as Promise<Device[]>;
}

export function apps(id: string) {
  return client.get(`/device/${id}/apps`).then(r => r.data) as Promise<App[]>;
}

export function ps(id: string) {
  return client.get(`/device/${id}/ps`).then(r => r.data) as Promise<Process[]>;
}