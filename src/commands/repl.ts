import * as vscode from 'vscode';
import * as path from 'path';

import { TargetItem, AppItem, ProcessItem } from '../providers/devices';
import { DeviceType } from '../types';
import { terminate } from '../driver/frida';
import { refresh, python3Path } from '../utils';

const terminals = new Set<vscode.Terminal>();

function repl(args: string[], id: string) {
  const name = `Frida - ${id}`;
  const shellPath = python3Path();
  const py = path.join(__dirname, '..', '..', 'backend', 'pause.py');
  const shellArgs = [py, shellPath, '-m', 'frida_tools.repl', ...args];
  const term = vscode.window.createTerminal({
    name,
    shellPath,
    shellArgs,
    hideFromUser: true
  });
  term.show();
  terminals.add(term);
}

vscode.window.onDidCloseTerminal(t => terminals.delete(t));

export function spawn(node?: AppItem) {
  if (!node) {
    vscode.window.showInformationMessage('Please use this command in the context menu of frida sidebar');
    return;
  }

  repl(['-f', node.data.identifier, '--device', node.device.id, '--no-pause'], node.data.name);
  refresh();
}

export function spawnSuspended(node?: AppItem) {
  if (!node) {
    vscode.window.showInformationMessage('Please use this command in the context menu of frida sidebar');
    return;
  }

  repl(['-f', node.data.identifier, '--device', node.device.id], node.data.name);
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
    repl([node.data.pid.toString(), ...device], node.data.pid.toString());
  }
}
