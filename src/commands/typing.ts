import { createWriteStream, promises as fsp } from 'fs';
import { get as httpGet } from 'https';
import { join } from 'path';
import { Position, ProgressLocation, window, workspace, l10n } from 'vscode';
import { cmd } from '../utils';
import { logger } from '../logger';

function npmInstall() {
  logger.appendLine('Installing @types/frida-gum via npm');
  const name = l10n.t('Install typescript typings');
  const shellPath = cmd('npm');
  const shellArgs = ['install', '@types/frida-gum', '--save'];
  const term = window.createTerminal({
    name,
    shellPath,
    shellArgs,
  });
  window.onDidCloseTerminal(t => {
    if (t === term && t.exitStatus?.code === 0) {
      window.showInformationMessage(
        l10n.t('@types/frida-gum has been successfully installed'));
    }
  })
  term.show();
}

async function downloadTypeHint(cwd: string) {
  const URL = 'https://raw.githubusercontent.com/DefinitelyTyped/DefinitelyTyped/master/types/frida-gum/index.d.ts';
  const NAME = 'frida-gum.d.ts';

  logger.appendLine(`Downloading typing info to ${cwd}`);
  // will override existing one
  const dest = join(cwd, NAME);
  const stream = createWriteStream(dest);

  await window.withProgress({
    location: ProgressLocation.Notification,
    title: l10n.t("Downloading typing info for frida-gum"),
    cancellable: false,
  }, (progress, token) => {
    return new Promise<string>(resolve => {
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
          logger.appendLine('Typing download completed');
          resolve(NAME);
        })
        .on('error', (err) => {
          logger.appendLine(`Error: typing download failed - ${err.message}`);
          stream.close();
          window.showErrorMessage(
            l10n.t('Failed to download typing info for frida-gum: {0}', err.message));
          fsp.unlink(dest);
        });
    });
  });

  return dest;
}


export async function init() {
  if (workspace.workspaceFolders?.length) {
    npmInstall();
    return;
  }

  const editor = window.activeTextEditor;
  if (!editor) {
    window.showErrorMessage(l10n.t('The command requires a workspace or an active document'));
    return;
  }

  const doc = editor.document;
  if (!['javascript', 'typescript'].includes(doc.languageId)) {
    window.showErrorMessage(l10n.t('This document is not Javascript or TypeScript'));
    return;
  }

  const fileUri = doc.uri;
  if (!fileUri) {
    window.showErrorMessage(l10n.t('The current document is unsaved'));
    return;
  }

  const folder = workspace.getWorkspaceFolder(fileUri);
  const cwd = folder ? folder.uri.fsPath : join(fileUri.fsPath, '..');
  const name = await downloadTypeHint(cwd);
  await editor.edit(e => {
    e.insert(new Position(0, 0), `/// <reference path="${name}" />\n`);
  });
  editor.document.save();
}
