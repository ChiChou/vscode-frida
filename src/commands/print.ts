import * as vscode from 'vscode';
import { TargetItem } from '../providers/devices';
import { ModulesPanel } from '../webview/ModulesPanel';
import { ClassesPanel } from '../webview/ClassesPanel';

let extensionUri: vscode.Uri;

export function init(context: vscode.ExtensionContext) {
  extensionUri = context.extensionUri;
}

export function modules(target: TargetItem) {
  const panel = new ModulesPanel(extensionUri, target);
  panel.show();
}

export function classes(target: TargetItem) {
  const panel = new ClassesPanel(extensionUri, target);
  panel.show();
}
