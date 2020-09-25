import { env } from 'vscode';
import { TargetItem, AppItem, ProcessItem } from "../providers/devices";

export function copy(item: TargetItem) {
  if (item instanceof AppItem) {
    env.clipboard.writeText(item.data.identifier);
  } else if (item instanceof ProcessItem) {
    env.clipboard.writeText(item.data.name);
  }
}
