import { execFile } from 'child_process';
import { interpreter } from '../utils';


function deviceParam(device: string) {
  const prefix = 'socket@';
  return device.startsWith(prefix) ?
    ['-H', device.substring(prefix.length)] :
    ['--device', device];
}

export async function launch(device: string, bundle: string): Promise<Number> {
  const params = ['-f', bundle, ...deviceParam(device), bundle, '-q', '-e', 'Process.id'];
  const py3 = await interpreter();
  const args = ['-m', 'frida_tools.repl', ...params];

  return new Promise((resolve, reject) => {
    execFile(py3, args, {}, (err, stdout) => {
      if (err) {
        reject(err);
      } else {
        const lines = stdout.split('\n');
        if (lines.length <= 2) {
          reject(new Error(`Unknown output: ${stdout}`));
        }
        resolve(parseInt(lines[1], 10));
      }
    });
  });
}

export async function terminate(device: string, target: string) {
  const py3 = await interpreter('frida-kill');
  const args = ['-m', 'frida_tools.kill', ...deviceParam(device), target];
  return new Promise((resolve, reject) => {
    execFile(py3, args, {}, (err, stdout) => {
      if (err) {
        reject(err);
      } else {
        resolve(stdout);
      }
    });
  });
}

