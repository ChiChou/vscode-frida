import { Task, TaskDefinition, ShellExecution, tasks } from 'vscode';
import { idle, executable } from './utils';

let iproxy: Task | null;
let iproxyPort: number;

export async function ssh(uuid: string): Promise<number> {
  if (iproxy) { return iproxyPort; }
  const port = await idle();
  const defination: TaskDefinition = {
    label: 'iproxy',
    type: 'shell',
  };

  const bin = executable('iproxy');
  const task = new Task(defination, bin, 'frida extension',
    new ShellExecution('iproxy', [port.toString(), '22', uuid]));
  task.isBackground = true;
  tasks.executeTask(task);

  await new Promise(resolve => {
    const handler = tasks.onDidStartTaskProcess(e => {
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
