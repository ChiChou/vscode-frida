import { env, l10n, window } from 'vscode';
import { TargetItem, AppItem, ProcessItem, DeviceItem } from "../providers/devices";

export function copy(item: TargetItem) {
  const getText = (item: TargetItem) => {
    if (item instanceof AppItem) {
      return item.data.identifier;
    } else if (item instanceof ProcessItem) {
      return item.data.name;
    } else if (item instanceof DeviceItem) {
      return item.data.id;
    }

    return undefined;
  }

  const text = getText(item);
  if (text === undefined) {
    window.showWarningMessage(l10n.t('Unsupported item type'));
    return;
  }

  env.clipboard.writeText(text);
}

export function copyPid(item: AppItem | ProcessItem) {
  if (item instanceof AppItem || item instanceof ProcessItem) {
    env.clipboard.writeText(item.data.pid.toString());
    return;
  }

  window.showWarningMessage(l10n.t('Unsupported item type'));
}
