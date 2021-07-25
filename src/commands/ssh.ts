import { homedir } from 'os';
import { join } from 'path';
import { promises as fsp } from 'fs';
import { window } from 'vscode';
import { DeviceItem, TargetItem } from '../providers/devices';
import { devtype, copyid as fridaCopyId } from '../driver/frida';
import { ssh as proxySSH } from '../iproxy';
import { executable } from '../utils';


async function keygen(path: string): Promise<boolean> {
  const choice = await window.showErrorMessage(
    'SSH key pair not found. Generate now?', 'Yes', 'Cancel');
  
  if (choice === 'Yes') {
    const term = window.createTerminal({
      name: 'ssh-keygen',
      shellPath: 'ssh-keygen',
      shellArgs: ['-f', path],
      hideFromUser: true,
    });
    term.show();
    await new Promise<void>((resolve, reject) => {
      const disposable = window.onDidCloseTerminal(t => {
        if (t === term) {
          if (t.exitStatus?.code === 0) {
            resolve();
          } else {
            reject(new Error('Failed to generate SSH key pair'));
          }
          disposable.dispose();
        }
      });
    });

    return true;
  } else {
    return false;
  }
}

export async function doCopyId(id: string) {
  const privateKey = join(homedir(), '.ssh', 'id_rsa');

  try {
    await fsp.access(privateKey);
  } catch(err) {
    if (!await keygen(privateKey)) {
      return false;
    }
  }

  return fridaCopyId(id);
}

export async function sshcopyid(node: TargetItem) {
  if (!(node instanceof DeviceItem)) {
    window.showErrorMessage('This command is only avaliable on context menu');
    return;
  }

  const deviceType = await devtype(node.data.id);
  if (deviceType !== 'iOS') {
    window.showErrorMessage(`Device type "${deviceType}" is not supported`);
    return;
  }

  const result = await doCopyId(node.data.id);
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

  const deviceType = await devtype(node.data.id);
  const name = `SSH: ${node.data.name}`;
  if (deviceType === 'iOS') {
    const port = await proxySSH(node.data.id);
    const shellPath = executable('ssh');
    const shellArgs = ['-q', `-p${port}`, 'root@localhost', '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null'];
    window.createTerminal({
      name,
      shellArgs,
      shellPath,
      hideFromUser: true,
    }).show();
  } else if (deviceType === 'Android') {
    const shellPath = executable('adb');
    const shellArgs = ['-s', node.data.id, 'shell'];
    window.createTerminal({
      name,
      shellArgs,
      shellPath,
      hideFromUser: true,
    }).show();
  } else {
    window.showErrorMessage(`Device type "${deviceType}" is not supported`);
  }
}