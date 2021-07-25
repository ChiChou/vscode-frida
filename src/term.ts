import { TerminalOptions, window } from "vscode";

export function run(opt: TerminalOptions) {
  return new Promise<void>((resolve, reject) => {
    const ext: TerminalOptions = { hideFromUser: true };
    const term = window.createTerminal(Object.assign(opt, ext));

    const disposable = window.onDidCloseTerminal(terminal => {
      if (terminal !== term) { return; }
      if (term.exitStatus?.code !== 0) {
        reject(new Error(`Terminal exited with status ${term.exitStatus?.code}`));
      } else {
        resolve();
      }
      disposable.dispose();
    });
    term.show();
  });
}