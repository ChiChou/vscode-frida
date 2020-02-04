import { posix } from 'path';
import * as vscode from 'vscode';

import { exec, fs } from '../driver/frida';

interface TargetInfo {
  pid: number;
  device: string;
  app: string;
  path: string;
}


function parseRemoteUri(uri: vscode.Uri): TargetInfo {
  /**
   * uri example:
   * 
   * frida-app://device/com.apple.app/~/tmp/1
   * frida-pid://device/1/etc/passwd
   */

  const device = uri.authority;
  const index = uri.path.indexOf('/', 1);
  const target = uri.path.substr(1, index - 1);
  const path = uri.path.substr(index + 1);

  let pid, app;
  if (uri.scheme === 'frida-app') {
    pid = 0;
    app = target;
  } else if (uri.scheme === 'frida-pid') {
    pid = parseInt(target, 10);
    app = '';
  } else {
    throw new Error(`invalid scheme ${uri.scheme}`);
  }

  return {
    pid,
    app,
    device,
    path
  };
}

function sameOriginCheck(a: TargetInfo, b: TargetInfo) {
  if (!(a.app === b.app && a.device === b.device && a.pid === b.pid)) {
    throw new Error('Cross-App resouce access is not allowed');
  }
}

export class FileSystemProvider implements vscode.FileSystemProvider {

  watch(uri: vscode.Uri, options: { recursive: boolean; excludes: string[]; }): vscode.Disposable {
    // TODO: 
    // https://stackoverflow.com/questions/11355144/file-monitoring-using-grand-central-dispatch
    // https://developer.android.com/reference/android/os/FileObserver
    return new vscode.Disposable(() => { });
  }

  private _emitter = new vscode.EventEmitter<vscode.FileChangeEvent[]>();
  private _bufferedEvents: vscode.FileChangeEvent[] = [];
  private _fireSoonHandle?: NodeJS.Timer;
  readonly onDidChangeFile: vscode.Event<vscode.FileChangeEvent[]> = this._emitter.event;

  private pids: { [key: string]: number } = {};
  async ensureRunning(info: TargetInfo): Promise<TargetInfo> {
    const { device, app, pid } = info;
    let result = info;
    if (!pid) {
      const key = [device, app].join('/');
      let newPid;
      if (key in this.pids) {
        newPid = this.pids[key];
      } else {
        newPid = await exec('rpc', 'ping', '--device', device, '--app', app);
        this.pids[key] = newPid;
      }
      result = Object.assign(info, { pid: newPid });
    }
    return result;
  }

  async stat(uri: vscode.Uri): Promise<vscode.FileStat> {
    const info = parseRemoteUri(uri);
    await this.ensureRunning(info);
    return exec('fs', 'stat', info.path,
      '--pid', info.pid.toString(), '--device', info.device);
  }

  async readDirectory(uri: vscode.Uri): Promise<[string, vscode.FileType][]> {
    const info = parseRemoteUri(uri);
    await this.ensureRunning(info);
    return exec('fs', 'ls', info.path, '--pid', info.pid.toString(), '--device', info.device);
  }

  async createDirectory(uri: vscode.Uri): Promise<void> {
    const info = parseRemoteUri(uri);
    await this.ensureRunning(info);

    const dirname = uri.with({ path: posix.dirname(uri.path) });
    this._fireSoon(
      { type: vscode.FileChangeType.Changed, uri: dirname },
      { type: vscode.FileChangeType.Created, uri });

    return exec('fs', 'mkdir', info.path, '--pid', info.pid.toString(), '--device', info.device);
  }

  async readFile(uri: vscode.Uri): Promise<Uint8Array> {
    const { device, pid, path } = await this.ensureRunning(parseRemoteUri(uri));
    return fs.download(device, pid, path);
  }

  async writeFile(uri: vscode.Uri, content: Uint8Array, options: VSCodeWriteFileOptions): Promise<void> {
    const dirname = uri.with({ path: posix.dirname(uri.path) });
    this._fireSoon(
      { type: vscode.FileChangeType.Changed, uri: dirname },
      { type: vscode.FileChangeType.Created, uri });

    const { device, pid, path } = await this.ensureRunning(parseRemoteUri(uri));
    fs.upload(device, pid, path, content, options);
    this._fireSoon({ type: vscode.FileChangeType.Deleted, uri });
  }

  async delete(uri: vscode.Uri, options: { recursive: boolean; }): Promise<void> {
    const info = parseRemoteUri(uri);
    await this.ensureRunning(info);
    const result = exec('fs', 'rm', info.path, JSON.stringify(options),
      '--pid', info.pid.toString(), '--device', info.device);

    const dirname = uri.with({ path: posix.dirname(uri.path) });
    this._fireSoon(
      { type: vscode.FileChangeType.Changed, uri: dirname },
      { type: vscode.FileChangeType.Deleted, uri });
    return result;
  }

  async rename(oldUri: vscode.Uri, newUri: vscode.Uri, options: { overwrite: boolean; }): Promise<void> {
    const src = parseRemoteUri(oldUri);
    const dst = parseRemoteUri(newUri);
    sameOriginCheck(src, dst);
    await this.ensureRunning(src);
    const result = exec('fs', 'mv', src.path, dst.path, JSON.stringify(options),
      '--pid', src.pid.toString(), '--device', src.device);

    const dirnameOld = oldUri.with({ path: posix.dirname(oldUri.path) });
    const dirnameNew = oldUri.with({ path: posix.dirname(oldUri.path) });
    this._fireSoon(
      { type: vscode.FileChangeType.Changed, uri: dirnameOld },
      { type: vscode.FileChangeType.Deleted, uri: oldUri },
      { type: vscode.FileChangeType.Changed, uri: dirnameNew },
      { type: vscode.FileChangeType.Created, uri: newUri });

    return result;
  }

  private _fireSoon(...events: vscode.FileChangeEvent[]): void {
    this._bufferedEvents.push(...events);

    if (this._fireSoonHandle) {
      clearTimeout(this._fireSoonHandle);
    }

    this._fireSoonHandle = setTimeout(() => {
      this._emitter.fire(this._bufferedEvents);
      this._bufferedEvents.length = 0;
    }, 5);
  }

}
