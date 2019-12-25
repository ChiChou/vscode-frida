// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';

import { DevicesProvider } from './providers/devices';
import { ProviderType } from './types';

export function activate(context: vscode.ExtensionContext) {
	let NEXT_TERM_ID = 1;

	const appsProvider = new DevicesProvider(ProviderType.Apps);
	vscode.window.registerTreeDataProvider('fridaApps', appsProvider);
	context.subscriptions.push(vscode.commands.registerCommand('extension.frida.apps.refresh', () => appsProvider.refresh()));
	
	const psProvider = new DevicesProvider(ProviderType.Processes);
	vscode.window.registerTreeDataProvider('fridaPs', psProvider);
	context.subscriptions.push(vscode.commands.registerCommand('extension.frida.ps.refresh', () => psProvider.refresh()));

	context.subscriptions.push(vscode.commands.registerCommand('extension.frida.repl', () => {
		const term = vscode.window.createTerminal(`Frida Terminal #${NEXT_TERM_ID++}`, 'frida', ['Finder']);
		term.show();
	}));

	context.subscriptions.push(vscode.commands.registerCommand('extension.frida.run', () => {
		// TODO:
		const term = vscode.window.createTerminal(`Frida Terminal #${NEXT_TERM_ID++}`, 'frida', ['Finder']);
		term.show();
	}));
}

// this method is called when your extension is deactivated
export function deactivate() {}
