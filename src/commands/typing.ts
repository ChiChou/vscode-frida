import { createWriteStream, promises as fsp, constants } from 'fs';
import { get as httpGet } from 'https';
import { join } from 'path';
import { workspace, Uri, window, ProgressLocation, Position } from 'vscode';

const URL = 'https://raw.githubusercontent.com/DefinitelyTyped/DefinitelyTyped/master/types/frida-gum/index.d.ts';
const NAME = 'frida-gum.d.ts';

export async function init() {
  const editor = window.activeTextEditor;
  if (!editor) {
    window.showErrorMessage('The command requires an active document');
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