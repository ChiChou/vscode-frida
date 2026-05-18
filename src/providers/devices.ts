import * as vscode from 'vscode';

import * as ipc from '../driver/backend';

import { resource } from '../utils';
import { ProviderType, App, Process, Device, DeviceType } from '../types';
import { logger } from '../logger';

export class DevicesProvider implements vscode.TreeDataProvider<TargetItem> {

  private _onDidChangeTreeData: vscode.EventEmitter<TargetItem | undefined> = new vscode.EventEmitter<TargetItem | undefined>();
  readonly onDidChangeTreeData: vscode.Event<TargetItem | undefined> = this._onDidChangeTreeData.event;

  constructor(
    public readonly type: ProviderType
  ) {

  }

  refresh(): void {
    this._onDidChangeTreeData.fire(undefined);
  }

  getTreeItem(element: TargetItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: TargetItem): Thenable<TargetItem[]> {
    if (element) {
      return element.children();
    } else {
      return ipc.devices().then(devices => {
        return devices.map(device => new DeviceItem(device, this.type, this));
      });
    }
  }

  processes(device: Device): Thenable<TargetItem[]> {
    return ipc.ps(device.id)
      .then(processes => this.processItems(processes, device))
      .catch(e => {
        logger.appendLine(`Error: failed to list processes on device ${device.id} - ${e.message}`);
        return [new NotFound(e, device)];
      });
  }

  private processItems(processes: Process[], device: Device): TargetItem[] {
    const items: TargetItem[] = [];
    const limited = processes.some(p => p.metadataStatus === 'limited');

    if (device.type === DeviceType.Local && limited) {
      const reason = processes.find(p => p.metadataError)?.metadataError;
      items.push(new ProcessAccessItem(device, reason));
    }

    return items.concat(processes.map(p => new ProcessItem(p, device)));
  }
}

export abstract class TargetItem extends vscode.TreeItem {
  abstract children(): Thenable<TargetItem[]>;
  abstract tooltip?: string | vscode.MarkdownString;
  abstract description?: string;
  abstract iconPath?: string | vscode.IconPath | undefined;
  abstract contextValue?: string | undefined;
}

export class DeviceItem extends TargetItem {
  constructor(
    public readonly data: Device,
    public readonly type: ProviderType,
    private readonly provider?: DevicesProvider,
  ) {
    super(data.name, vscode.TreeItemCollapsibleState.Collapsed);
  }

  get tooltip(): string {
    return `${this.data.id} (${this.data.type})`;
  }

  get description(): string {
    return this.data.id;
  }

  get iconPath() {
    return {
      light: resource('light', `${this.data.type}.svg`),
      dark: resource('dark', `${this.data.type}.svg`),
    };
  }

  children(): Thenable<TargetItem[]> {
    const device = this.data;
    if (this.type === ProviderType.Apps) {
      return ipc.apps(device.id)
        .then(apps => apps.map(app => new AppItem(app, device)))
        .catch(e => {
          logger.appendLine(`Error: failed to list apps on device ${device.id} - ${e.message}`);
          return [new NotFound(e, device)];
        });
    } else if (this.type === ProviderType.Processes) {
      return this.provider?.processes(device) ?? Promise.resolve([]);
    }
    return Promise.resolve([]);
  }

  get contextValue() {
    const { type, os } = this.data;
    return `device|${type}|${os}`;
  }

}

enum AppState {
  Running = 'running',
  Dead = 'dead',
};

export class NotFound extends TargetItem {
  constructor(
    public readonly reason: Error,
    public readonly device: Device,
  ) {
    super(reason.message, vscode.TreeItemCollapsibleState.None);
  }

  children(): Thenable<TargetItem[]> {
    return Promise.resolve([]);
  }

  get tooltip() { return this.reason.message; }

  iconPath = {
    dark: resource('dark', 'error.svg'),
    light: resource('light', 'error.svg')
  };

  contextValue = 'empty';

  description = '';
}

export class ProcessAccessItem extends TargetItem {
  constructor(
    public readonly data: Device,
    private readonly reason?: string,
  ) {
    super(vscode.l10n.t('Process metadata is limited'), vscode.TreeItemCollapsibleState.None);
  }

  children(): Thenable<TargetItem[]> {
    return Promise.resolve([]);
  }

  get tooltip(): string {
    const hint = vscode.l10n.t('Some process metadata is unavailable.');
    return this.reason ? `${hint}\n${this.reason}` : hint;
  }

  get description(): string {
    return vscode.l10n.t('limited');
  }

  iconPath = {
    dark: resource('dark', 'error.svg'),
    light: resource('light', 'error.svg')
  };

  get contextValue() {
    return `notice|processAccess|${this.data.type}|${this.data.os}`;
  }
}

export class AppItem extends TargetItem {
  constructor(
    public readonly data: App,
    public readonly device: Device,
  ) {
    super(data.name, vscode.TreeItemCollapsibleState.None);
  }

  get tooltip(): string {
    return `${this.label} (${this.data.pid || vscode.l10n.t('Not Running')})`;
  }

  get description(): string {
    return this.data.identifier;
  }

  children(): Thenable<TargetItem[]> {
    return Promise.resolve([]);
  }

  get iconPath() {
    return this.data.icon ? vscode.Uri.parse(this.data.icon) : resource('terminal.png');
  }

  get contextValue() {
    return `app|${this.data.pid ? AppState.Running : AppState.Dead}|${this.device.type}|${this.device.os}`;
  }
}

export class ProcessItem extends TargetItem {
  constructor(
    public readonly data: Process,
    public readonly device: Device,
  ) {
    super(data.name, vscode.TreeItemCollapsibleState.None);
  }

  get tooltip(): string {
    const lines = [
      `${this.label} (${this.data.pid})`,
    ];

    if (this.data.path) {
      lines.push(vscode.l10n.t('Path: {0}', this.data.path));
    }
    if (this.data.cwd) {
      lines.push(vscode.l10n.t('Working Directory: {0}', this.data.cwd));
    }
    if (this.data.user) {
      lines.push(vscode.l10n.t('User: {0}', this.data.user));
    }
    if (this.data.ppid) {
      lines.push(vscode.l10n.t('Parent PID: {0}', this.data.ppid));
    }
    if (this.data.argv?.length) {
      lines.push(vscode.l10n.t('Arguments: {0}', this.data.argv.join(' ')));
    }
    if (this.data.metadataStatus === 'limited') {
      lines.push(vscode.l10n.t('Some metadata is unavailable.'));
    }

    return lines.join('\n');
  }

  get description(): string {
    const parts = [this.data.pid.toString()];
    if (this.data.user) {
      parts.push(this.data.user);
    } else if (this.data.metadataStatus === 'limited') {
      parts.push(vscode.l10n.t('limited'));
    }
    return parts.join(' - ');
  }

  children(): Thenable<TargetItem[]> {
    return Promise.resolve([]);
  }

  get iconPath() {
    return this.data.icon ? vscode.Uri.parse(this.data.icon) : resource('terminal.png');
  }

  get contextValue() {
    return `process|${this.data.pid ? AppState.Running : AppState.Dead}|${this.device.type}|${this.data.metadataStatus}|${this.device.os}`;
  }
}
