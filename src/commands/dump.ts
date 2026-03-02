import { homedir } from 'os';
import * as vscode from 'vscode';

import ADB from '../driver/adb';
import { AppItem, TargetItem } from "../providers/devices";

export default async function dump(target: TargetItem) {
  if (!(target instanceof AppItem)) {
    vscode.window.showErrorMessage(vscode.l10n.t('This command is only expected to be used in the context menu'));
    return;
  }

  if (target.device.os !== 'android') {
    vscode.window.showErrorMessage(vscode.l10n.t('This command only supports Android'));
    return;
  }

  const preferred = vscode.workspace.getConfiguration('frida').get('decryptOutput', homedir());
  const defaultUri = vscode.Uri.file(preferred);
  const destinations = await vscode.window.showOpenDialog({
    defaultUri,
    canSelectFiles: false,
    canSelectFolders: true,
    canSelectMany: false,
    openLabel: vscode.l10n.t('Select'),
    title: vscode.l10n.t('Select destination folder')
  });

  if (!destinations?.length) { return; }

  const destURI = destinations[0];
  const output = destURI.fsPath;

  vscode.workspace.getConfiguration('frida').update('decryptOutput', output, true);

  const artifact = vscode.Uri.joinPath(destURI, `${target.data.identifier}.apk`);

  try {
    await pull(target, artifact);
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
    vscode.commands.executeCommand('revealFileInOS', artifact);
  }
}

async function pull(target: AppItem, output: vscode.Uri) {
  const adb = new ADB(target.device.id);
  const path = await adb.shell('pm', 'path', target.data.identifier);

  if (path.startsWith('package:')) {
    await adb.pull(path.substring(8).trimEnd(), output);
  } else {
    vscode.window.showErrorMessage(vscode.l10n.t('Failed to get package path: {0}', path));
  }
}
