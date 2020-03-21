import * as vscode from 'vscode';

import { platformize, launch } from '../driver/frida';
import { TargetItem, AppItem, ProcessItem } from "../providers/devices";
import { DeviceType } from '../types';

export async function explore(target: TargetItem) {
  if (!target) {
    // todo: select from list
    return;
  }

  const title = `Objection - ${target.label}`;

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
        gadget = await launch(target.device.id, target.data.identifier).toString();
      } catch(e) {
        vscode.window.showWarningMessage(`Warning: failed to launch App ${target.data.identifier}`);
        gadget = target.data.name;
      }
    }

    const [bin, args] = platformize('objection', ['-g', gadget, ...device, 'explore']);
    vscode.window.createTerminal(title, bin, args).show();    
  }
}