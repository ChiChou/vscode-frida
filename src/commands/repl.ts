import * as vscode from 'vscode';

import { TargetItem, AppItem, ProcessItem } from '../providers/devices';
import { platform } from 'os';
import { DeviceType } from '../types';
import { terminate } from '../driver/frida';

let NEXT_TERM_ID = 1;

function repl(args: string[]) {
  const title = `Frida REPL #${NEXT_TERM_ID++}`;
  if (platform() === 'win32') {
    vscode.window.createTerminal(title, 'cmd.exe', ['/c', 'frida', ...args]).show();
  } else {
    vscode.window.createTerminal(title, 'frida', args).show();
  }
}

function refresh() {
  vscode.commands.executeCommand('frida.ps.refresh');
  vscode.commands.executeCommand('frida.apps.refresh');
}

export function spawn(node?: AppItem) {
  if (!node) {
    // todo: select from list
    return;
  }

  repl(['-f', node.data.identifier, '--device', node.device.id, '--no-pause']);
  refresh();
}

export function spawnSuspended(node?: AppItem) {
  if (!node) {
    // todo: select
    return;
  }

  repl(['-f', node.data.identifier, '--device', node.device.id]);
  refresh();
}

export function kill(node?: TargetItem) {
  if (!node) {
    return;
  }

  if ((node instanceof AppItem && node.data.pid) || node instanceof ProcessItem) {
    terminate(node.device.id, node.data.pid.toString());
    refresh();
  } else {
    vscode.window.showWarningMessage(`Target is not running`);
  }
}

export function attach(node?: TargetItem) {
  if (!node) {
    // todo: select from list
    return;
  }

  if (node instanceof AppItem || node instanceof ProcessItem) {
    if (!node.data.pid) {
      vscode.window.showErrorMessage(`App "${node.data.name}" must be running before attaching to it`);
    }

    const device = node.device.type === DeviceType.Local ? [] : ['--device', node.device.id];
    repl([node.data.pid.toString(), ...device]);
  }
}