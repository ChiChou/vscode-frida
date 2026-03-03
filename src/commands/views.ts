import * as vscode from 'vscode';
import { rpc } from '../driver/backend';
import { AppItem, DeviceItem, ProcessItem, TargetItem } from '../providers/devices';
import { ModulesPanel } from '../webview/ModulesPanel';
import { ClassesPanel } from '../webview/ClassesPanel';
import { HierarchyPanel } from '../webview/HierarchyPanel';
import { PackageTreePanel } from '../webview/PackageTreePanel';
import { DeviceDashboardPanel } from '../webview/DeviceDashboardPanel';
import { MemoryPanel } from '../webview/MemoryPanel';
import { MemoryScannerPanel } from '../webview/MemoryScannerPanel';
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

export function detail(device: DeviceItem) {
  logger.appendLine(`Open device detail for ${device.data.name}`);
  new DeviceDashboardPanel(extensionUri, device).show();
}

export function memory(target: TargetItem) {
  logger.appendLine(`Open memory panel for ${target.label}`);
  new MemoryPanel(extensionUri, target).show();
}

export function scanner(target: TargetItem) {
  logger.appendLine(`Open memory scanner for ${target.label}`);
  new MemoryScannerPanel(extensionUri, target).show();
}

async function fetchAndShow(target: TargetItem, method: string, filename: string) {
  logger.appendLine(`Fetching ${method} for ${target.label}`);
  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: vscode.l10n.t('Loading...') },
    async () => {
      try {
        const xml = await rpc(target, method) as string;
        const dir = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '';
        const uri = vscode.Uri.parse(`untitled:${vscode.Uri.joinPath(vscode.Uri.file(dir), filename).fsPath}`);
        const doc = await vscode.workspace.openTextDocument(uri);
        const editor = await vscode.window.showTextDocument(doc);
        await editor.edit(edit => {
          edit.insert(new vscode.Position(0, 0), xml);
        });
        vscode.languages.setTextDocumentLanguage(doc, 'xml');
      } catch (err: any) {
        logger.appendLine(`Error: failed to load ${method} - ${err.message}`);
        vscode.window.showErrorMessage(err.message);
      }
    }
  );
}

export function manifest(target: TargetItem) {
  return fetchAndShow(target, 'manifest', 'AndroidManifest.xml');
}

export function infoPlist(target: TargetItem) {
  return fetchAndShow(target, 'info_plist', 'Info.plist');
}
