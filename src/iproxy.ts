import { spawn, ChildProcess } from 'child_process';
import { idle, executable } from './utils';
import { logger }from './logger';
import { createInterface } from 'readline';

let thePort: number;
let singleton: ChildProcess | null = null;

export async function ssh(uuid: string): Promise<number> {
  if (singleton) { return thePort; }

  const port = await idle();
  singleton = spawn(executable('iproxy'), [port.toString(), '22', uuid]);

  if (singleton.stderr) {
    const rl = createInterface({ input: singleton.stderr });
    rl.on('line', (line: string) => logger.appendLine(`[iproxy] ${line}`));
  }

  singleton.on('close', () => {
    logger.appendLine('iproxy is unexpectly terminated');
    thePort = -1;
    singleton = null;
  });

  return (thePort = port);
}

export function cleanup() {
  if (singleton) {
    singleton.kill();
    singleton = null;
    thePort = -1;
  }
}
