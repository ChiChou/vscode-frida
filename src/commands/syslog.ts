import * as cp from 'child_process';
import { l10n, OutputChannel, window } from 'vscode';

import { driverScript, lockdownSyslog, os } from '../driver/backend';
import { AppItem, ProcessItem, TargetItem } from "../providers/devices";
import { DeviceType } from '../types';
import { interpreter, refresh } from '../utils';

const active: { [key: string]: OutputChannel } = {};

export function vacuum() {
  for (const channel of Object.values(active)) {
    channel.dispose();
  }
}

export async function show(node: TargetItem) {
  function cmdChannel(name: string, bin: string, args: string[]) {
    if (name in active) {
      return active[name];
    }

    const channel = window.createOutputChannel(name);
    const child = cp.spawn(bin, args);
    const write = (data: Buffer) => channel.append(data.toString());
    child.stdout.on('data', write);
    child.stderr.on('data', write);

    const actionClose = l10n.t('Close Console');
    const actionIgnore = l10n.t('Dismiss');
    const question = l10n.t('Console {0} is already open, do you want to close it?', name);

    child.on('close', () =>
      window.showWarningMessage(
        question, actionClose, actionIgnore).then(option => {
          if (option === actionClose) {
            channel.dispose();
          }
          refresh();
        }));
    return channel;
  }

  let bundleOrPid: string[];
  if (node instanceof AppItem) {
    bundleOrPid = ['--app', node.data.identifier];
  } else if (node instanceof ProcessItem) {
    bundleOrPid = ['--pid', node.data.pid.toString()];
  } else {
    window.showErrorMessage(l10n.t('Invalid target {0}', `${node.label}`));
    return;
  }

  const type = await os(node.device.id);
  if (type === 'ios' && node.device.type === DeviceType.USB) {
    lockdownSyslog(node.device.id, bundleOrPid);
  } else if (type === 'linux' || type === 'macos') {
    const args = [driverScript(), 'syslog', '--device', node.device.id, ...bundleOrPid];
    const python3 = await interpreter();
    const title = l10n.t('Output: {0} ({1})', node.data.name, node.device.name);
    cmdChannel(title, python3, args).show();
  } else if (type === 'android') {
    if (node.data.pid > 0) {
      const args = ['-s', node.device.id, 'logcat', `--pid=${node.data.pid}`];
      const title = l10n.t('Output: {0} ({1})', node.data.name, node.device.name);
      cmdChannel(title, 'adb', args).show();
    } else {
      // todo: 
      // adb shell monkey -p BUNDLE 1
      // adb shell pidof BUNDLE
      window.showErrorMessage(l10n.t('{0} ({1}) is not running', node.data.name, node.device.name));
    }
  } else {
    window.showErrorMessage(l10n.t('Unsupported device type {0}', node.device.type));
  }
}