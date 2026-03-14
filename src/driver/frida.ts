import { l10n } from 'vscode';
import { execFile } from 'child_process';
import { interpreter } from '../utils';
import { logger } from '../logger';


function deviceParam(device: string) {
  const prefix = 'socket@';
  return device.startsWith(prefix) ?
    ['-H', device.substring(prefix.length)] :
    ['--device', device];
}

export async function launch(device: string, bundle: string): Promise<Number> {
  logger.appendLine(`Launch ${bundle} on device ${device}`);
  const params = ['-f', bundle, ...deviceParam(device), bundle, '-q', '-e', 'Process.id'];
  const py3 = await interpreter();
  const args = ['-m', 'frida_tools.repl', ...params];

  return new Promise((resolve, reject) => {
    execFile(py3, args, {}, (err, stdout) => {
      if (err) {
        logger.appendLine(`Error: failed to launch ${bundle} on device ${device} - ${err.message}`);
        reject(err);
      } else {
        const lines = stdout.split('\n');
        if (lines.length <= 2) {
            reject(new Error(l10n.t('Unknown output: {0}', stdout)));
        }
        const pid = parseInt(lines[1], 10);
        logger.appendLine(`Launched ${bundle} with PID ${pid}`);
        resolve(pid);
      }
    });
  });
}

export async function terminate(device: string, target: string) {
  logger.appendLine(`Terminate ${target} on device ${device}`);
  const py3 = await interpreter('frida-kill');
  const args = ['-m', 'frida_tools.kill', ...deviceParam(device), target];
  return new Promise((resolve, reject) => {
    execFile(py3, args, {}, (err, stdout) => {
      if (err) {
        logger.appendLine(`Error: failed to terminate ${target} on device ${device} - ${err.message}`);
        reject(err);
      } else {
        resolve(stdout);
      }
    });
  });
}

