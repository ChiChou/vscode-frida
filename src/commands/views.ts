import * as vscode from 'vscode';
import { TargetItem } from '../providers/devices';
import { ModulesPanel } from '../webview/ModulesPanel';
import { ClassesPanel } from '../webview/ClassesPanel';
import { HierarchyPanel } from '../webview/HierarchyPanel';
import { PackageTreePanel } from '../webview/PackageTreePanel';

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

export function hierarchy(target: TargetItem) {
  new HierarchyPanel(extensionUri, target).show();
}

export function packages(target: TargetItem) {
  new PackageTreePanel(extensionUri, target).show();
}
