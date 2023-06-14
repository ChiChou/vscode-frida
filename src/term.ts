import { TerminalOptions, window } from "vscode";

export class CommandNotFoundError extends Error {
  constructor(cmd: string) {
    super(`Command not found: ${cmd}`);
  }
}

export function run(opt: TerminalOptions) {
  const ext: TerminalOptions = { hideFromUser: true };
  return new Promise<void>((resolve, reject) => {
    const term = window.createTerminal(Object.assign(opt, ext));

    const disposable = window.onDidCloseTerminal(terminal => {
      if (terminal !== term) { return; }

      if (term.exitStatus?.code === undefined && opt.shellPath) {
        reject(new CommandNotFoundError(opt.shellPath));
      } else if (term.exitStatus?.code !== 0) {
        reject(new Error(`Terminal exited with status ${term.exitStatus?.code}`));
      } else {
        resolve();
      }
      disposable.dispose();
    });
    term.show();
  });
}