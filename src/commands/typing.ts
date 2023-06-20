import { createWriteStream, promises as fsp } from 'fs';
import { get as httpGet } from 'https';
import { join } from 'path';
import { Position, ProgressLocation, window, workspace } from 'vscode';
import { executable } from '../utils';

const URL = 'https://raw.githubusercontent.com/DefinitelyTyped/DefinitelyTyped/master/types/frida-gum/index.d.ts';
const NAME = 'frida-gum.d.ts';

function npmInstall() {
  const name = `npm`;
  const shellPath = executable('npm');
  const shellArgs = ['install', '@types/frida-gum', '--save'];
  const term = window.createTerminal({
    name,
    shellPath,
    shellArgs,
  });
  window.onDidCloseTerminal(t => {
    if (t === term && t.exitStatus?.code === 0) {
      window.showInformationMessage('@types/frida-gum has been successfully installed');
    }
  })
  term.show();
}


export async function init() {
  if (workspace.workspaceFolders?.length) {
    npmInstall();
    return;
  }

  const editor = window.activeTextEditor;
  if (!editor) {
    window.showErrorMessage('The command requires a workspace or an active document');
    return;
  }

  const doc = editor.document;
  if (!['javascript', 'typescript'].includes(doc.languageId)) {
    window.showErrorMessage('This document is not Javascript or TypeScript');
    return;
  }

  const fileUri = doc.uri;
  if (!fileUri) {
    window.showErrorMessage('The current document is unsaved');
    return;
  }

  const folder = workspace.getWorkspaceFolder(fileUri);
  const cwd = folder ? folder.uri.fsPath : join(fileUri.fsPath, '..');

  // todo: refactor

  // will override existing one
  const dest = join(cwd, NAME);
  const stream = createWriteStream(dest);

  window.withProgress({
    location: ProgressLocation.Notification,
    title: `Downloading typing info for frida-gum`,
    cancellable: false,
  }, (progress, token) => {
    return new Promise<void>(resolve => {
      const req = httpGet(URL, resp => {
        const rawLen = resp.headers['content-length'];
        const len = rawLen ? parseInt(rawLen, 10) : NaN;
        resp.pipe(stream);

        if (rawLen) {
          resp.on('data', chunk =>
            progress.report({
              increment: chunk.length / len * 100
            })
          );
        }
      });

      req
        .on('finish', async () => {
          resolve();
          await editor.edit(e => {
            e.insert(new Position(0, 0), `/// <reference path="${NAME}" />\n`);
          });
          editor.document.save();
        })
        .on('error', (err) => {
          stream.close();
          window.showErrorMessage(`Failed to download typing info: ${err}`);
          fsp.unlink(dest);
        });
    });
  })

}