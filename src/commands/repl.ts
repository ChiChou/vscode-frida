import * as vscode from 'vscode';
import * as path from 'path';

import { TargetItem, AppItem, ProcessItem, DeviceItem } from '../providers/devices';
import { DeviceType } from '../types';
import { terminate } from '../driver/frida';
import { connect, disconnect } from '../driver/remote';
import { refresh, python3Path, sleep } from '../utils';
import { EOL, platform } from 'os';
import { all } from '../driver/remote';

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

function expandDevParam(node: AppItem | ProcessItem) {
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

export function spawn(node?: AppItem) {
  if (!node) {
    vscode.window.showInformationMessage('Please use this command in the context menu of frida sidebar');
    return;
  }

  repl(['-f', node.data.identifier, ...expandDevParam(node), '--no-pause'], node.data.name);
  refresh();
}

export function spawnSuspended(node?: AppItem) {
  if (!node) {
    vscode.window.showInformationMessage('Please use this command in the context menu of frida sidebar');
    return;
  }

  repl(['-f', node.data.identifier, ...expandDevParam(node)], node.data.name);
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

    repl([node.data.pid.toString(), ...expandDevParam(node)], node.data.pid.toString());
  }
}

export async function exec() {
  const { activeTextEditor, activeTerminal, showErrorMessage } = vscode.window;
  if (!activeTextEditor) {
    showErrorMessage('No active document');
    return;
  }

  if (terminals.size === 0) {
    showErrorMessage('No active frida REPL');
    return;
  }

  let term: vscode.Terminal | null = null;
  if (activeTerminal && terminals.has(activeTerminal)) {
    term = activeTerminal;
  } else if (terminals.size === 1) {
    term = terminals.values().next().value as vscode.Terminal;
    term.show();
  } else {
    showErrorMessage('You have multiple REPL instances. Please activate one');
    return;
  }

  const { document } = activeTextEditor;
  const text = (() => {
    if (document.isDirty) { // not saved
      return document.getText();
    }

    const { fsPath } = document.uri;
    // escape \\ in path
    const escaped = platform() === 'win32' ? JSON.stringify(fsPath) : fsPath;
    return `%exec ${escaped}`;
  })();

  term.sendText(text);
  await sleep(100);
  term.sendText(EOL);
}

export async function addRemote() {
  const host = await vscode.window.showInputBox({
    placeHolder: "192.168.1.2:27042",
    prompt: "Host or IP of the remote device",
    value: ''
  });

  if (typeof host !== 'string' || host.length === 0) {
    return;
  }

  connect(host);
  refresh();
}

export async function delRemote(node?: TargetItem) {
  if (!node) {
    const selected = await vscode.window.showQuickPick(all());
    if (typeof selected === 'string') {
      disconnect(selected);
    }
  } else if (node instanceof DeviceItem && node.data.type === DeviceType.Remote) {
    disconnect(node.data.id.substring('socket@'.length));
  }
  refresh();
}
