import { homedir } from 'os';
import * as vscode from 'vscode';

import ADB from '@/driver/adb';
import { AppItem, TargetItem } from "@/providers/devices";

export default async function dump(target: TargetItem) {
  if (!(target instanceof AppItem)) {
    vscode.window.showErrorMessage(vscode.l10n.t('This command is only expected to be used in the context menu'));
    return;
  }

  if (target.device.os !== 'android') {
    vscode.window.showErrorMessage(vscode.l10n.t('This command only supports Android'));
    return;
  }

  const adb = new ADB(target.device.id);
  const remotePaths = await adb.pmPath(target.data.identifier);

  if (remotePaths.length === 0) {
    vscode.window.showErrorMessage(vscode.l10n.t('Failed to get package path for {0}', target.data.identifier));
    return;
  }

  const preferred = vscode.workspace.getConfiguration('frida').get('decryptOutput', homedir());
  const defaultUri = vscode.Uri.file(preferred);

  let dest: vscode.Uri;

  if (remotePaths.length === 1) {
    const result = await vscode.window.showSaveDialog({
      defaultUri: vscode.Uri.joinPath(defaultUri, `${target.data.identifier}.apk`),
      filters: { 'APK': ['apk'] },
      title: vscode.l10n.t('Save APK as'),
    });

    if (!result) { return; }
    dest = result;
  } else {
    const results = await vscode.window.showOpenDialog({
      defaultUri,
      canSelectFiles: false,
      canSelectFolders: true,
      canSelectMany: false,
      openLabel: vscode.l10n.t('Select'),
      title: vscode.l10n.t('Select destination folder for {0} APKs', remotePaths.length),
    });

    if (!results?.length) { return; }
    dest = results[0];
  }

  vscode.workspace.getConfiguration('frida').update('decryptOutput',
    remotePaths.length === 1 ? vscode.Uri.joinPath(dest, '..').fsPath : dest.fsPath, true);

  try {
    await adb.pull(...remotePaths, dest);
  } catch (e) {
    vscode.window.showInformationMessage(
      vscode.l10n.t('failed to pull application:\n{0}', (e as Error).message));
    return;
  }

  const actionOpen = vscode.l10n.t('Open');
  const option = await vscode.window.showInformationMessage(
    vscode.l10n.t('Successfully pulled package {0}', target.data.identifier),
    actionOpen,
    vscode.l10n.t('Dismiss'));

  if (option === actionOpen) {
    vscode.commands.executeCommand('revealFileInOS', dest);
  }
}
