import { createReadStream, createWriteStream, promises as fsp } from 'fs';
import { join as joinPath } from 'path';
import * as vscode from 'vscode';

import { AppItem, ProcessItem } from '../providers/devices';
import { run } from '../term';
import { cmd, expandDevParam, interpreter, resource } from '../utils';
import { logger } from '../logger';


async function create(template: string) {
  let dest: vscode.Uri;

  const { workspaceFolders } = vscode.workspace;
  {
    if (workspaceFolders?.length) { dest = workspaceFolders[0].uri; }

    const fileUri = await vscode.window.showOpenDialog({
      canSelectFolders: true,
      canSelectMany: false,
      openLabel: vscode.l10n.t('Create Here')
    });

    if (fileUri?.length) {
      dest = fileUri[0];
    } else {
      vscode.window.showInformationMessage(
        vscode.l10n.t('You must select a folder to create the project'));
      return;
    }
  }

  logger.appendLine(`Create boilerplate project: ${template} in ${dest.fsPath}`);
  const args = ['-m', 'frida_tools.creator', '-t', template];
  const shellPath = await interpreter();
  await run({
    cwd: dest,
    name: vscode.l10n.t('Create Project'),
    shellPath,
    shellArgs: args
  });

  if (!(workspaceFolders?.length)) {
    vscode.commands.executeCommand('vscode.openFolder', dest);
  }

  await run({
    cwd: dest.path,
    name: `npm install`,
    shellPath: cmd('npm'),
    shellArgs: ['install']
  });
}

export function agent() {
  return create('agent');
}

export function module() {
  return create('module');
}

function* tokenize(cmd: string) {
  let inQuote = false;
  let buf = [];
  for (const c of cmd) {
    if (c === '\"') {
      inQuote = !inQuote;
    } else if (c === ' ' && !inQuote) {
      yield buf.join('');
      buf.length = 0;
    } else {
      buf.push(c);
    }
  }

  yield buf.join('');
}

export async function debug(node?: AppItem | ProcessItem) {
  if (!node) { return; }

  const { activeTextEditor, showInformationMessage, showInputBox } = vscode.window;
  const { workspaceFolders } = vscode.workspace;

  if (!workspaceFolders?.length) {
    showInformationMessage(
      vscode.l10n.t('This command only works in a workspace. Please open a workspace first'));
    return;
  }

  const FILE_LAUNCH = 'launch.json';
  const FILE_TASKS = 'tasks.json';

  const dest = workspaceFolders[0].uri;

  const folder = joinPath(dest.fsPath, '.vscode');
  const launchJSON = joinPath(folder, FILE_LAUNCH);
  const tasksJSON = joinPath(folder, FILE_TASKS);

  const isDir = (path: string) =>
    fsp.stat(path).then(stat => stat.isDirectory()).catch(() => false);

  const isFile = (path: string) =>
    fsp.stat(path).then(stat => stat.isFile()).catch(() => false);

  if (await isDir(folder)) {
    // check if launch.json exists    
    for (const file of [launchJSON, tasksJSON]) {
      if (await isFile(file)) {
        const msg = vscode.l10n.t('{0} already exists. Do you want to overwrite it?', file);
        const y = vscode.l10n.t('Yes');
        const n = vscode.l10n.t('No');
        const answer = await showInformationMessage(msg, y, n);
        if (answer === n) { return; }
        if (answer === y) { break; } // only have to answer yes once
      }
    }
  } else {
    await fsp.mkdir(folder);
  }

  const quote = (s: string) => s.includes(' ') ? `"${s}"` : s;

  let cmd: string[] = [];
  // create debug command line
  cmd.push(...expandDevParam(node));

  if (node instanceof AppItem) {
    if (node.data.pid) {
      cmd.push(quote(node.data.name)); // attach to app
    } else {
      cmd.push('-f', quote(node.data.identifier)); // spawn
    }
  } else if (node instanceof ProcessItem) {
    cmd.push(node.data.pid.toString()); // attach to pid
  }

  // attach current document to the target
  if (activeTextEditor && !activeTextEditor.document.isDirty) {
    cmd.push('-l', quote(activeTextEditor.document.uri.fsPath));
  }

  // enable v8 debug
  cmd.push('--runtime=v8', '--debug');

  const placeHolder = cmd.join(' ');
  const userInput = await showInputBox({
    placeHolder,
    prompt: vscode.l10n.t('Debug Command'),
    value: placeHolder,
  });

  // user cancelled
  if (!userInput) { return; }

  // copy launch.json to workspace
  await new Promise<boolean>((resolve, reject) => {
    createReadStream(resource('templates', FILE_LAUNCH).fsPath)
      .pipe(createWriteStream(launchJSON))
      .on('finish', () => resolve(true))
      .on('error', (err) => reject(err));
  });

  const tasksTemplatePath = resource('templates', FILE_TASKS).fsPath;
  const content = JSON.parse(await fsp.readFile(tasksTemplatePath, 'utf8'));
  // replace the command line in tasks.json
  content.tasks[0].args = [...tokenize(userInput)];
  await fsp.writeFile(tasksJSON, JSON.stringify(content, null, 2));

  showInformationMessage(
    vscode.l10n.t('Debug configuration created. You can now start debugging by pressing F5')
  );
}
