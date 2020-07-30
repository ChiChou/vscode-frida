import { window, Task, TaskDefinition, ShellExecution, tasks } from 'vscode';
import { DeviceItem, TargetItem } from "../providers/devices";
import { devtype, platformize } from '../driver/frida';
import { freePort } from '../utils';

let iproxy: Task | null;
let iproxyPort: number;

// todo: common module
async function runIProxy(): Promise<number> {
  if (iproxy) { return iproxyPort; }
  const port = await freePort();
  const cmd = `iproxy ${port} 22`; // command injection? nope
  const defination: TaskDefinition = {
    label: 'iproxy',
    type: 'shell',
  };

  const task = new Task(defination, 'iproxy', 'frida extension', new ShellExecution(cmd));
  task.isBackground = true;
  tasks.executeTask(task);

  await new Promise(resolve => {
    const handler = tasks.onDidStartTask(e => {
      if (e.execution.task === task) {
        resolve();
        handler.dispose();
      }
    });
  });

  iproxy = task;
  iproxyPort = port;

  // no, this ain't the task port you want
  const disposable = tasks.onDidEndTask(e => {
    if (e.execution.task === iproxy) {
      iproxy = null;
      iproxyPort = -1;
      disposable.dispose();
    }
  });

  return port;
}

export async function copyid(node: TargetItem) {
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

  const port = await runIProxy();
  const defination: TaskDefinition = {
    label: 'ssh-copy-id',
    type: 'shell',
  };

  const [bin, arg] = platformize('ssh-copy-id',
    [`-p${port}`, 'root@localhost', '-o', 'StrictHostKeyChecking=no']);

  const task = new Task(
    defination,
    'Copy SSH pubkey',
    'frida extension',
    new ShellExecution(bin, arg)
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
    const port = await runIProxy();
    const [shellPath, shellArgs] = platformize('ssh',
      [`-p${port}`, 'root@localhost', '-o', 'StrictHostKeyChecking=no']);
    window.createTerminal({
      name,
      shellArgs,
      shellPath
    }).show();
  } else if (deviceType === 'Android') {
    const [shellPath, shellArgs] = platformize('adb', ['-s', node.data.id, 'shell']);
    window.createTerminal({
      name,
      shellArgs,
      shellPath
    }).show();
  } else {
    window.showErrorMessage(`Device type "${deviceType}" is not supported`);
  }
}