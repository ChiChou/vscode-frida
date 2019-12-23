import * as vscode from 'vscode';
import * as path from 'path';

import * as driver from '../driver/frida';
import { resource } from '../utils';
import { ProviderType, App, Process, Device } from '../types';

export class DevicesProvider implements vscode.TreeDataProvider<TargetItem> {

  private _onDidChangeTreeData: vscode.EventEmitter<TargetItem | undefined> = new vscode.EventEmitter<TargetItem | undefined>();
	readonly onDidChangeTreeData: vscode.Event<TargetItem | undefined> = this._onDidChangeTreeData.event;

  constructor(
    public readonly type: ProviderType
  ) {

  }
  
  refresh(): void {
    this._onDidChangeTreeData.fire();
	}

	getTreeItem(element: TargetItem): vscode.TreeItem {
		return element;
  }
  
  getChildren(element?: TargetItem): Thenable<TargetItem[]> {
    if (element) {
      return element.children();
    } else {
      return driver.devices().then(devices => devices.map(device => new DeviceItem(device, this.type)));
    }
	}
}

export abstract class TargetItem extends vscode.TreeItem {
  abstract children() : Thenable<TargetItem[]>;
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
    if (this.type === ProviderType.Apps) {
      return driver.apps(this.data.id).then(apps => apps.map(app => new AppItem(app)));
    } else if (this.type === ProviderType.Processes) {
      return driver.ps(this.data.id).then(ps => ps.map(p => new ProcessItem(p)));
    }
    return Promise.resolve([]);
  }

	contextValue = 'device';
}

export class AppItem extends TargetItem {
  constructor(
    public readonly data: App
  ) {
    super(data.name, vscode.TreeItemCollapsibleState.None);
  }

  get tooltip(): string {
    return `${this.label} (${this.data.pid || 'Not Running'})`;
  }

  get description(): string {
    return this.data.identifier;
  }

  children(): Thenable<TargetItem[]> {
    return Promise.resolve([]);
  }

  get iconPath() {
    const img = this.data.pid ? 'statusRun.svg' : 'statusStop.svg';
    return {
      dark: resource('dark', img),
      light: resource('light', img)
    };
  }

  contextValue = 'app';
}

export class ProcessItem extends TargetItem {
  constructor(
    public readonly data: Process
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
    const img = this.data.pid ? 'statusRun.svg' : 'statusStop.svg';
    return {
      dark: resource('dark', img),
      light: resource('light', img)
    };
  }

  contextValue = 'process';
}