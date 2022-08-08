import * as vscode from 'vscode';
import { join as joinPath } from 'path';
import { promises as fsp, constants as fsc, createReadStream, createWriteStream } from 'fs';

import { executable, expandDevParam, python3Path, resource } from '../utils';
import { AppItem, ProcessItem } from '../providers/devices';
import { run } from '../term';


async function create(template: string) {
  let dest: vscode.Uri;

  const { workspaceFolders } = vscode.workspace;
  {
    if (workspaceFolders?.length) { dest = workspaceFolders[0].uri; }

    const fileUri = await vscode.window.showOpenDialog({
      canSelectFolders: true,
      canSelectMany: false,
      openLabel: 'Create Here'
    });

    if (fileUri?.length) {
      dest = fileUri[0];
    } else {
      vscode.window.showInformationMessage('You just cancelled the operation.');
      return;
    }
  }

  const args = ['-m', 'frida_tools.creator', template];

  await run({
    cwd: dest,
    name: 'Create Project',
    shellPath: python3Path(),
    shellArgs: args
  });

  if (!(workspaceFolders?.length)) {
    vscode.commands.executeCommand('vscode.openFolder', dest);
  }

  await run({
    cwd: dest.path,
    name: `npm install`,
    shellPath: executable('npm'),
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
    showInformationMessage('You must open a workspace first.');
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
        const msg = `${file} already exists. Do you want to overwrite it?`;
        const answer = await showInformationMessage(msg, 'Yes', 'No');
        if (answer === 'No') { return; }
        if (answer === 'Yes') { break; } // only have to answer yes once
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
      cmd.push('-f', quote(node.data.identifier), '--no-pause'); // spawn
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
    prompt: "Debug Command",
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

  showInformationMessage('Debug config added to workspace. Press F5 to start debugging.');
}
