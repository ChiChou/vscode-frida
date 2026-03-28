import * as vscode from 'vscode';
import { rpc } from '../driver/backend';
import { DeviceItem, TargetItem } from '../providers/devices';
import { openUntitledDocument } from '../utils';
import { logger } from '../logger';

let extensionUri: vscode.Uri;

export function init(context: vscode.ExtensionContext) {
  extensionUri = context.extensionUri;
}

export async function modules(target: TargetItem) {
  if (!target) { return; }
  logger.appendLine(`Open modules panel for ${target.label}`);
  const { ModulesPanel } = await import('../webview/ModulesPanel');
  new ModulesPanel(extensionUri, target).show();
}

export async function classes(target: TargetItem) {
  if (!target) { return; }
  logger.appendLine(`Open classes panel for ${target.label}`);
  const { ClassesPanel } = await import('../webview/ClassesPanel');
  new ClassesPanel(extensionUri, target).show();
}

export async function protocols(target: TargetItem) {
  if (!target) { return; }
  logger.appendLine(`Open protocols panel for ${target.label}`);
  const { ProtocolsPanel } = await import('../webview/ProtocolsPanel');
  new ProtocolsPanel(extensionUri, target).show();
}

export async function detail(device: DeviceItem) {
  if (!device) { return; }
  logger.appendLine(`Open device detail for ${device.data.name}`);
  const { DeviceDashboardPanel } = await import('../webview/DeviceDashboardPanel');
  new DeviceDashboardPanel(extensionUri, device).show();
}

export async function memory(target: TargetItem) {
  if (!target) { return; }
  logger.appendLine(`Open memory panel for ${target.label}`);
  const { MemoryPanel } = await import('../webview/MemoryPanel');
  new MemoryPanel(extensionUri, target).show();
}

export async function scanner(target: TargetItem) {
  if (!target) { return; }
  logger.appendLine(`Open memory scanner for ${target.label}`);
  const { MemoryScannerPanel } = await import('../webview/MemoryScannerPanel');
  new MemoryScannerPanel(extensionUri, target).show();
}

async function fetchAndShow(target: TargetItem, method: string, filename: string) {
  if (!target) { return; }
  logger.appendLine(`Fetching ${method} for ${target.label}`);
  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: vscode.l10n.t('Loading...') },
    async () => {
      try {
        const xml = await rpc(target, method) as string;
        await openUntitledDocument(filename, xml, 'xml');
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

export function entitlements(target: TargetItem) {
  return fetchAndShow(target, 'entitlements', 'Entitlements.plist');
}
