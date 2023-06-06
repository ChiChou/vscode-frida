import * as vscode from 'vscode';

import { launch } from '../driver/frida';
import { AppItem, ProcessItem, TargetItem } from "../providers/devices";
import { run } from '../term';
import { DeviceType } from '../types';
import { python3Path } from '../utils';

export async function explore(target: TargetItem) {
  if (!target) {
    vscode.window.showErrorMessage('This command is only expected to be used in the context menu');
    return;
  }

  const name = `Objection - ${target.label}`;

  if (target instanceof AppItem || target instanceof ProcessItem) {
    let device: string[];
    switch (target.device.type) {
      case DeviceType.TCP:
      case DeviceType.Remote:
        // todo: support remote connection
        device = ['-N', '-h', target.device.id];
        break;
      case DeviceType.Local:
        device = [];
        vscode.window.showErrorMessage('This command is not applicable to the local device');
        return;
      case DeviceType.USB:
      default:
        device = [];
    }

    let { pid } = target.data;
    let gadget = pid.toString();
    if (target instanceof AppItem && !pid) {
      try {
        gadget = (await launch(target.device.id, target.data.identifier)).toString();
      } catch (e) {
        vscode.window.showWarningMessage(`Warning: failed to launch App ${target.data.identifier}\n${e}`);
        gadget = target.data.name;
      }
    }

    const shellArgs = ['-m', 'objection.console.cli', '-g', gadget, ...device, 'explore'];
    const shellPath = python3Path();
    run({
      name,
      shellArgs,
      shellPath,
    });
  }
}