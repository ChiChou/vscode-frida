/* eslint-disable @typescript-eslint/naming-convention */
import * as vscode from 'vscode';
import { join } from 'path';
import { tmpdir } from 'os';

import ADB from '../driver/adb';
import { DeviceItem, TargetItem } from '../providers/devices';
import { logger } from '../logger';
import { interpreter, sleep } from '../utils';
import { run } from '../term';

function getServerPath() {
  return vscode.workspace.getConfiguration('frida')
    .get('androidServerPath', '/data/local/tmp/frida-server');
}

export async function startServer(target: TargetItem) {
  if (!(target instanceof DeviceItem)) {
    vscode.window.showErrorMessage(vscode.l10n.t('This command is only expected to be used in the context menu'));
    return;
  }

  const server = getServerPath();
  const adb = new ADB(target.data.id);
  const installed = await adb.shell(server, '--version').then((ver: string) => {
    logger.appendLine(vscode.l10n.t('sanity check: frida-server version on device {0}', ver));
    return true;
  }).catch(() => {
    logger.appendLine(vscode.l10n.t('frida-server not found on device, downloading...'));
    return false;
  });

  if (!installed) {
    const abi = (await adb.shell('getprop', 'ro.product.cpu.abi')).trimEnd();
    const py = join(__dirname, '..', '..', 'backend', 'android', 'get-frida.py');
    const tmp = join(tmpdir(), `frida-server-${abi}`);

    const shellPath = await interpreter();
    await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: vscode.l10n.t('Downloading frida-server'),
      cancellable: false
    }, async (progress) => {
      await run({
        name: `Download frida-server`,
        shellPath,
        shellArgs: [py, abi, tmp]
      });
      progress.report({ message: vscode.l10n.t('Done') });
    });

    const uri = vscode.Uri.file(tmp);
    await adb.push(uri, server);

    vscode.window.showInformationMessage(vscode.l10n.t('frida-server deployed to {0} successfully', server));
    await adb.shell('chmod', '755', server);
  }

  const term = adb.interactive();
  await sleep(1000);
  term.sendText('su', true);
  await sleep(500);
  term.sendText(server, true);
}
