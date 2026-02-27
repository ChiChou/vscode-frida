import * as vscode from 'vscode';
import { TargetItem } from '../providers/devices';
import { ModulesPanel } from '../webview/ModulesPanel';
import { ClassesPanel } from '../webview/ClassesPanel';
import { HierarchyPanel } from '../webview/HierarchyPanel';
import { PackageTreePanel } from '../webview/PackageTreePanel';
import { logger } from '../logger';

let extensionUri: vscode.Uri;

export function init(context: vscode.ExtensionContext) {
  extensionUri = context.extensionUri;
}

export function modules(target: TargetItem) {
  logger.appendLine(`Open modules panel for ${target.label}`);
  const panel = new ModulesPanel(extensionUri, target);
  panel.show();
}

export function classes(target: TargetItem) {
  logger.appendLine(`Open classes panel for ${target.label}`);
  const panel = new ClassesPanel(extensionUri, target);
  panel.show();
}

export function hierarchy(target: TargetItem) {
  logger.appendLine(`Open hierarchy panel for ${target.label}`);
  new HierarchyPanel(extensionUri, target).show();
}

export function packages(target: TargetItem) {
  logger.appendLine(`Open packages panel for ${target.label}`);
  new PackageTreePanel(extensionUri, target).show();
}
