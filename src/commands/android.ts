/* eslint-disable @typescript-eslint/naming-convention */
import * as vscode from 'vscode';
import { join } from 'path';
import { tmpdir } from 'os';

import ADB from '../driver/adb';
import { DeviceItem, TargetItem } from '../providers/devices';
import { logger } from '../logger';
import { python3Path, sleep } from '../utils';
import { run } from '../term';

function getServerPath() {
  return vscode.workspace.getConfiguration('frida')
    .get('androidServerPath', '/data/local/tmp/frida-server');
}

export async function startServer(target: TargetItem) {
  if (!(target instanceof DeviceItem)) {
    vscode.window.showErrorMessage('This command is only expected to be used in the context menu');
    return;
  }

  const server = getServerPath();
  const adb = new ADB(target.data.id);
  const installed = await adb.shell(server, '--version').then((ver: string) => {
    logger.appendLine(`sanity check: frida-server version on device ${ver}`);
    return true;
  }).catch(() => {
    logger.appendLine('frida-server not found on device, downloading...');
    return false;
  });

  if (!installed) {
    const abi = (await adb.shell('getprop', 'ro.product.cpu.abi')).trimEnd();
    const py = join(__dirname, '..', '..', 'backend', 'android', 'get-frida.py');
    const tmp = join(tmpdir(), `frida-server-${abi}`);

    await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: 'Downloading frida-server',
      cancellable: false
    }, async (progress) => {
      await run({
        name: `Download frida-server`,
        shellPath: python3Path(),
        shellArgs: [py, abi, tmp]
      });
      progress.report({ message: 'Done' });
    });

    const uri = vscode.Uri.file(tmp);
    await adb.push(uri, server);

    vscode.window.showInformationMessage(`frida-server deployed to ${server} successfully`);
    await adb.shell('chmod', '755', server);
  }

  const term = adb.interactive();
  await sleep(1000);
  term.sendText('su', true);
  await sleep(500);
  term.sendText(server, true);
}
