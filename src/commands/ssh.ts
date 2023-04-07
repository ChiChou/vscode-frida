import { promises as fsp } from 'fs';
import { window } from 'vscode';
import { DeviceItem, TargetItem } from '../providers/devices';
import { os, copyid as fridaCopyId } from '../driver/frida';
import { IProxy, ssh as proxySSH } from '../iproxy';
import { executable } from '../utils';
import { run } from '../term';
import { keyPath } from '../libs/ssh';


export async function keygen(): Promise<boolean> {
  const path = keyPath();

  try {
    await fsp.access(path);
    window.showInformationMessage(`Private key (${path}) already exists`);
    return Promise.resolve(true);
  } catch(err) {

  }

  const choice = await window.showErrorMessage(
    'SSH key pair not found. Generate now?', 'Yes', 'Cancel');
  
  if (choice === 'Yes') {
    try {
      await run({
        name: 'ssh-keygen',
        shellPath: executable('ssh-keygen'),
        shellArgs: ['-f', path],
      });
    } catch(_) {
      throw new Error('Failed to generate SSH key pair');
    }

    return true;
  } else {
    return false;
  }
}

export async function copyid(node: TargetItem) {
  if (!(node instanceof DeviceItem)) {
    window.showErrorMessage('This command is only avaliable on context menu');
    return;
  }

  await keygen();

  const deviceType = await os(node.data.id);
  if (deviceType !== 'ios') {
    window.showErrorMessage(`Device type "${deviceType}" is not supported`);
    return;
  }

  const result = await fridaCopyId(node.data.id);
  if (result) {
    window.showInformationMessage(`Succesfully installed SSH public key on "${node.data.name}"`);
  } else {
    window.showErrorMessage(`Failed to deploy SSH key to ${node.data.name}`);
  }
}

export async function shell(node: TargetItem) {
  if (!(node instanceof DeviceItem)) {
    window.showErrorMessage('This command is only avaliable on context menu');
    return;
  }

  const deviceType = await os(node.data.id);
  const name = `SSH: ${node.data.name}`;
  let shellPath, shellArgs;
  let iproxy: IProxy | null = null;

  if (deviceType === 'ios') {
    iproxy = await proxySSH(node.data.id);
    shellPath = executable('ssh');
    shellArgs = ['-q', `-p${iproxy.local}`, 'root@localhost', '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null'];
  } else if (deviceType === 'android') {
    shellPath = executable('adb');
    shellArgs = ['-s', node.data.id, 'shell'];
  } else {
    window.showErrorMessage(`OS type "${deviceType}" is not supported`);
    return;
  }

  try {
    await run({
      name,
      shellArgs,
      shellPath,
      hideFromUser: true,
    });
  } finally {
    if (iproxy)
      iproxy.release();
  }
}