import * as vscode from 'vscode';
import { l10n } from 'vscode';

import { launch } from '../driver/frida';
import { AppItem, ProcessItem, TargetItem } from "../providers/devices";
import { run } from '../term';
import { DeviceType } from '../types';
import { interpreter } from '../utils';
import { logger } from '../logger';

export async function explore(target: TargetItem) : Promise<void> {
  if (!target) {
    vscode.window.showErrorMessage(l10n.t('This command is only expected to be used in the context menu'));
    return;
  }

  if (!(target instanceof AppItem || target instanceof ProcessItem)) {
    vscode.window.showErrorMessage(l10n.t('This command is not applicable to the selected item'));
    return;
  }

  const name = `Objection - ${target.label}`;

  let device: string[];
  switch (target.device.type) {
    case DeviceType.TCP:
    case DeviceType.Remote:
      // todo: support remote connection
      device = ['-N', '-h', target.device.id];
      break;
    case DeviceType.Local:
      device = [];
      vscode.window.showErrorMessage(l10n.t('This command is not applicable to the local device'));
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
      vscode.window.showWarningMessage(
        l10n.t('Warning: failed to launch App {0}\n{1}', target.data.identifier, `${e}`));
      logger.appendLine(`Objection: falling back to app name ${target.data.name} after launch failure`);
      gadget = target.data.name;
    }
  }

  logger.appendLine(`Objection explore ${gadget} on device ${target.device.id}`);
  const shellArgs = ['-m', 'objection.console.cli', '-g', gadget, ...device, 'explore'];
  const shellPath = await interpreter('objection');
  run({
    name,
    shellArgs,
    shellPath,
  });
}