// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';

import { DevicesProvider, TargetItem, AppItem, ProcessItem } from './providers/devices';
import { ProviderType, Process } from './types';

export function activate(context: vscode.ExtensionContext) {
	let NEXT_TERM_ID = 1;

	function repl(args: string[]) {
		const term = vscode.window.createTerminal(`Frida REPL #${NEXT_TERM_ID++}`, 'frida', args);
		term.show();
	}

	const appsProvider = new DevicesProvider(ProviderType.Apps);
	vscode.window.registerTreeDataProvider('fridaApps', appsProvider);
	context.subscriptions.push(vscode.commands.registerCommand('frida.apps.refresh', () => appsProvider.refresh()));
	
	const psProvider = new DevicesProvider(ProviderType.Processes);
	vscode.window.registerTreeDataProvider('fridaPs', psProvider);
	context.subscriptions.push(vscode.commands.registerCommand('frida.ps.refresh', () => psProvider.refresh()));

	context.subscriptions.push(vscode.commands.registerCommand('frida.spawn', (node?: TargetItem) => {
		if (!node) {
			// todo: select from list
			return;
		}

		if (node instanceof AppItem) {
			repl(['-f', node.data.identifier, '--device', node.device.id]);
		}
	}));

	context.subscriptions.push(vscode.commands.registerCommand('frida.attach', (node?: TargetItem) => {
		if (!node) {
			// todo: select from list
			return;
		}

		if (node instanceof AppItem || node instanceof ProcessItem) {
			repl([node.data.pid.toString(), '--device', node.device.id]);
		}
	}));

	context.subscriptions.push(vscode.commands.registerCommand('frida.passionfruit', (node?: AppItem) => {
		if (!node) {
			return;
		}

		const webview = vscode.window.createWebviewPanel(
			'passionfruit',
			`${node.data.identifier} - Passionfruit`,
			vscode.ViewColumn.One,
			{
				enableScripts: true
			});
		webview.webview.html = `
			<style>
			body{ height:100vh; }
			html, body {
				overflow: auto;
				min-height: 100%;
			}
			</style>
			<embed type="text/html" width="100%" height="100%"
				src="http://localhost:31337/app/${node.device.id}/${node.data.identifier}/general">
		`;
	}));
}

// this method is called when your extension is deactivated
export function deactivate() {}
