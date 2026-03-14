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
      logger.appendLine('Enumerating devices');
      return ipc.devices().then(devices => {
        logger.appendLine(`Found ${devices.length} device(s)`);
        return devices.map(device => new DeviceItem(device, this.type));
      });
    }
  }
}

export abstract class TargetItem extends vscode.TreeItem {
  abstract children(): Thenable<TargetItem[]>;
  abstract tooltip?: string;
  abstract description?: string;
  abstract iconPath?: string | vscode.IconPath | undefined;
  abstract contextValue?: string | undefined;
}

export class DeviceItem extends TargetItem {
  constructor(
    public readonly data: Device,
    public readonly type: ProviderType,
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
      return ipc.ps(device.id)
        .then(ps => ps.map(p => new ProcessItem(p, device)))
        .catch(e => {
          logger.appendLine(`Error: failed to list processes on device ${device.id} - ${e.message}`);
          return [new NotFound(e, device)];
        });
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
    return `app|${this.data.pid ? AppState.Running : AppState.Dead}|${this.device.os}`;
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
    return `${this.label} (${this.data.pid})`;
  }

  get description(): string {
    return this.data.pid.toString();
  }

  children(): Thenable<TargetItem[]> {
    return Promise.resolve([]);
  }

  get iconPath() {
    return this.data.icon ? vscode.Uri.parse(this.data.icon) : resource('terminal.png');
  }

  get contextValue() {
    return `process|${this.data.pid ? AppState.Running : AppState.Dead}|${this.device.os}`;
  }
}