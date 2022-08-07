// The module 'vscode' contains the VS Code extensibility API
// Import the module and reference it with the alias vscode in your code below
import * as vscode from 'vscode';

import { ProviderType } from './types';
import { DevicesProvider } from './providers/devices';

import * as iproxy from './iproxy';
import * as ssh from './commands/ssh';
import * as file from './commands/file';
import * as repl from './commands/repl';
import * as syslog from './commands/syslog';
import * as typing from './commands/typing';
import * as lldb from './commands/lldb';
import * as foul from './commands/fouldecrypt';
import * as objection from './commands/objection';
import * as clipboard from './commands/clipboard';
import * as boilerplate from './commands/boilerplate';

export function activate(context: vscode.ExtensionContext) {
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
	context.subscriptions.push(vscode.commands.registerCommand('frida.snippet.execute', repl.exec));
	context.subscriptions.push(vscode.commands.registerCommand('frida.remote.add', repl.addRemote));
	context.subscriptions.push(vscode.commands.registerCommand('frida.remote.remove', repl.delRemote));

	context.subscriptions.push(vscode.commands.registerCommand('frida.syslog', syslog.show));
	context.subscriptions.push(vscode.commands.registerCommand('frida.syslog.vacuum', syslog.vacuum));

	context.subscriptions.push(vscode.commands.registerCommand('frida.browse', file.browse));
	context.subscriptions.push(vscode.commands.registerCommand('frida.bundle.copy', clipboard.copy));
	context.subscriptions.push(vscode.commands.registerCommand('frida.name.copy', clipboard.copy));
	
	context.subscriptions.push(vscode.commands.registerCommand('frida.external.objection', objection.explore));
	context.subscriptions.push(vscode.commands.registerCommand('frida.external.installfoul', foul.install));
	context.subscriptions.push(vscode.commands.registerCommand('frida.external.fouldecrypt', foul.decrypt));

	context.subscriptions.push(vscode.commands.registerCommand('frida.external.setuplldb', lldb.setup));
	context.subscriptions.push(vscode.commands.registerCommand('frida.external.lldb', lldb.debug));

	context.subscriptions.push(vscode.commands.registerCommand('frida.external.shell', ssh.shell));
	context.subscriptions.push(vscode.commands.registerCommand('frida.external.copyid', ssh.copyid));
	context.subscriptions.push(vscode.commands.registerCommand('frida.external.sshkeygen', ssh.keygen));

	context.subscriptions.push(vscode.commands.registerCommand('frida.boilerplate.agent', boilerplate.agent));
	context.subscriptions.push(vscode.commands.registerCommand('frida.boilerplate.module', boilerplate.module));
	context.subscriptions.push(vscode.commands.registerCommand('frida.debug.setup', boilerplate.debug));

	context.subscriptions.push(vscode.commands.registerCommand('frida.typing.init', typing.init));
}

// this method is called when your extension is deactivated
export function deactivate() {
	iproxy.cleanup();
	lldb.cleanup();
}
