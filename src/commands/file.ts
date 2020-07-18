import * as vscode from 'vscode';
import { AppItem, ProcessItem } from '../providers/devices';

export function browse(target: AppItem | ProcessItem) {
  let uri;
  let name;

  if (target instanceof AppItem) {
    uri = `frida-app://${target.device.id}/${target.data.identifier}/~`;
    name = `Browse sandbox: ${target.label}`;
  } else if (target instanceof ProcessItem) {
    uri = `frida-pid://${target.device.id}/${target.data.pid}/~`;
    name = `Browse sandbox: ${target.label} (${target.data.pid})`;
  }

  if (uri && name) {
    vscode.commands.executeCommand('vscode.openFolder', vscode.Uri.parse(uri), true);
  }
}