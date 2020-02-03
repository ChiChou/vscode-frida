// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';

import { DevicesProvider } from './providers/devices';
import { ProviderType } from './types';
import * as repl from './commands/repl';
import * as syslog from './commands/syslog';
import * as file from './commands/file';
import * as bagbak from './commands/bagbak';
import { FileSystemProvider } from './providers/filesystem';

export function activate(context: vscode.ExtensionContext) {
	const fs = new FileSystemProvider();
	context.subscriptions.push(vscode.workspace.registerFileSystemProvider('frida-app', fs, { isCaseSensitive: true }));
	context.subscriptions.push(vscode.workspace.registerFileSystemProvider('frida-pid', fs, { isCaseSensitive: true }));

	const appsProvider = new DevicesProvider(ProviderType.Apps);
	vscode.window.registerTreeDataProvider('fridaApps', appsProvider);
	context.subscriptions.push(vscode.commands.registerCommand('frida.apps.refresh', () => appsProvider.refresh()));
	
	const psProvider = new DevicesProvider(ProviderType.Processes);
	vscode.window.registerTreeDataProvider('fridaPs', psProvider);
	context.subscriptions.push(vscode.commands.registerCommand('frida.ps.refresh', () => psProvider.refresh()));
	context.subscriptions.push(vscode.commands.registerCommand('frida.spawn', repl.spawn));
	context.subscriptions.push(vscode.commands.registerCommand('frida.spawn.suspended', repl.spawnSuspended));
	context.subscriptions.push(vscode.commands.registerCommand('frida.attach', repl.attach));
	context.subscriptions.push(vscode.commands.registerCommand('frida.kill', repl.kill));

	context.subscriptions.push(vscode.commands.registerCommand('frida.syslog', syslog.show));
	context.subscriptions.push(vscode.commands.registerCommand('frida.syslog.vacuum', syslog.vacuum));

	context.subscriptions.push(vscode.commands.registerCommand('frida.browse', file.browse));
	context.subscriptions.push(vscode.commands.registerCommand('frida.bagbak', bagbak.dump));
}

// this method is called when your extension is deactivated
export function deactivate() {
	
}
