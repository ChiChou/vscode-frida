import * as path from 'path';
import * as vscode from 'vscode';

import { terminate } from '../driver/frida';
import { all, connect, disconnect } from '../driver/remote';
import { AppItem, DeviceItem, ProcessItem, TargetItem } from '../providers/devices';
import { DeviceType } from '../types';
import { expandDevParam, interpreter, refresh } from '../utils';
import { logger } from '../logger';

const terminals = new Set<vscode.Terminal>();

async function repl(args: string[], id: string) {
  const name = vscode.l10n.t('Frida - {0}', id);
  const shellPath = await interpreter();
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
  if (!node) { return; }

  logger.appendLine(`Spawn ${node.data.identifier} on device ${node.device.id}`);
  repl(['-f', node.data.identifier, ...expandDevParam(node)], node.data.name);
  refresh();
}

export function spawnSuspended(node?: AppItem) {
  if (!node) { return; }

  logger.appendLine(`Spawn suspended ${node.data.identifier} on device ${node.device.id}`);
  repl(['-f', node.data.identifier, ...expandDevParam(node), '--pause'], node.data.name);
  refresh();
}

export function kill(node?: TargetItem) {
  if (!node) { return; }

  if ((node instanceof AppItem && node.data.pid) || node instanceof ProcessItem) {
    logger.appendLine(`Kill PID ${node.data.pid} on device ${node.device.id}`);
    terminate(node.device.id, node.data.pid.toString());
    refresh();
  } else {
    vscode.window.showWarningMessage(vscode.l10n.t('Target is not running'));
  }
}

export function attach(node?: TargetItem) {
  if (!node) { return; }

  if (node instanceof AppItem || node instanceof ProcessItem) {
    if (!node.data.pid) {
      vscode.window.showErrorMessage(
        vscode.l10n.t('App "{0}" must be running before attaching to it', node.data.name));
    }

    logger.appendLine(`Attach to PID ${node.data.pid} on device ${node.device.id}`);
    repl([node.data.pid.toString(), ...expandDevParam(node)], node.data.pid.toString());
  }
}

export async function addRemote() {
  const host = await vscode.window.showInputBox({
    placeHolder: '192.168.1.2:27042',
    prompt: vscode.l10n.t('Host or IP of the remote device'),
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
