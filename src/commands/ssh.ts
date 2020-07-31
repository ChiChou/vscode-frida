import { window, Task, TaskDefinition, ShellExecution, tasks } from 'vscode';
import { DeviceItem, TargetItem } from "../providers/devices";
import { devtype, platformize } from '../driver/frida';
import { run as runIProxy } from '../iproxy';
import { platform } from 'os';
import { executable } from '../utils';

export async function copyid(node: TargetItem) {
  if (platform() === 'win32') {
    window.showErrorMessage('This command is not avaliable on Windows');
    return;
  }

  if (!(node instanceof DeviceItem)) {
    window.showErrorMessage('This command is only avaliable on context menu');
    return;
  }

  // todo: decorator
  const deviceType = await devtype(node.data.id);
  if (deviceType !== 'iOS') {
    window.showErrorMessage(`Device type "${deviceType}" is not supported`);
    return;
  }

  const port = await runIProxy(node.data.id);
  const defination: TaskDefinition = {
    label: 'ssh-copy-id',
    type: 'shell',
  };

  const args =[`-p${port}`, 'root@localhost', '-o', 'StrictHostKeyChecking=no'];

  const task = new Task(
    defination,
    'Copy SSH pubkey',
    'frida extension',
    new ShellExecution('ssh-copy-id', args)
  );
  tasks.executeTask(task);
}

export async function shell(node: TargetItem) {
  if (!(node instanceof DeviceItem)) {
    window.showErrorMessage('This command is only avaliable on context menu');
    return;
  }

  const deviceType = await devtype(node.data.id);
  const name = `SSH: ${node.data.name}`;
  if (deviceType === 'iOS') {
    const port = await runIProxy(node.data.id);
    const shellPath = executable('ssh');
    const shellArgs = [`-p${port}`, 'root@localhost', '-o', 'StrictHostKeyChecking=no'];
    window.createTerminal({
      name,
      shellArgs,
      shellPath
    }).show();
  } else if (deviceType === 'Android') {
    const shellPath = executable('adb');
    const shellArgs = ['-s', node.data.id, 'shell'];
    window.createTerminal({
      name,
      shellArgs,
      shellPath
    }).show();
  } else {
    window.showErrorMessage(`Device type "${deviceType}" is not supported`);
  }
}