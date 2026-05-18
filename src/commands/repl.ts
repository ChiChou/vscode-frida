import * as path from 'path';
import * as vscode from 'vscode';

import { terminate } from '../driver/frida';
import { all, connect, disconnect } from '../driver/remote';
import { AppItem, DeviceItem, ProcessItem, TargetItem } from '../providers/devices';
import { DeviceType } from '../types';
import { expandDevParam, interpreter, refresh, sudo } from '../utils';
import { logger } from '../logger';

const terminals = new Set<vscode.Terminal>();

async function repl(args: string[], id: string, elevated = false) {
  const name = vscode.l10n.t('Frida - {0}', id);
  const shellPath = await interpreter();

  if (elevated) {
    const sudoPath = await sudo();
    const term = vscode.window.createTerminal({
      name,
      shellPath: sudoPath,
      shellArgs: [shellPath, '-m', 'frida_tools.repl', ...args],
      hideFromUser: false
    });
    term.show();
    terminals.add(term);
    return;
  }

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

export async function spawn(node?: AppItem) {
  if (!node) { return; }

  logger.appendLine(`Spawn ${node.data.identifier} on device ${node.device.id}`);
  await repl(['-f', node.data.identifier, ...expandDevParam(node)], node.data.name);
  refresh();
}

export async function spawnSuspended(node?: AppItem) {
  if (!node) { return; }

  logger.appendLine(`Spawn suspended ${node.data.identifier} on device ${node.device.id}`);
  await repl(['-f', node.data.identifier, ...expandDevParam(node), '--pause'], node.data.name);
  refresh();
}

export async function kill(node?: TargetItem) {
  if (!node) { return; }

  if ((node instanceof AppItem && node.data.pid) || node instanceof ProcessItem) {
    logger.appendLine(`Kill PID ${node.data.pid} on device ${node.device.id}`);
    await terminate(node.device.id, node.data.pid.toString());
    refresh();
  } else {
    vscode.window.showWarningMessage(vscode.l10n.t('Target is not running'));
  }
}

async function attachWithOptions(node: TargetItem | undefined, elevated: boolean) {
  if (!node) { return; }

  if (node instanceof AppItem || node instanceof ProcessItem) {
    if (!node.data.pid) {
      vscode.window.showErrorMessage(
        vscode.l10n.t('App "{0}" must be running before attaching to it', node.data.name));
      return;
    }

    logger.appendLine(`${elevated ? 'Attach elevated' : 'Attach'} to PID ${node.data.pid} on device ${node.device.id}`);
    await repl([node.data.pid.toString(), ...expandDevParam(node)], node.data.pid.toString(), elevated);
  }
}

export async function attach(node?: TargetItem) {
  return attachWithOptions(node, false);
}

export function attachElevated(node?: TargetItem) {
  if ((node instanceof AppItem || node instanceof ProcessItem) && node.device.type !== DeviceType.Local) {
    vscode.window.showWarningMessage(vscode.l10n.t('Elevated attach is only available for local targets'));
    return;
  }

  return attachWithOptions(node, true);
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
