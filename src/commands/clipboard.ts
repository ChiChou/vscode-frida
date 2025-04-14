import { env, l10n } from 'vscode';
import { TargetItem, AppItem, ProcessItem, DeviceItem } from "../providers/devices";

export function copy(item: TargetItem) {
  let text: string;
  if (item instanceof AppItem) {
    text = item.data.identifier;
  } else if (item instanceof ProcessItem) {
    text = item.data.name;
  } else if (item instanceof DeviceItem) {
    text = item.data.id;
  } else {
    throw new Error(l10n.t('Unsupported item type'));
  }

  env.clipboard.writeText(text);
}
