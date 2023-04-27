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
import * as objection from './commands/objection';
import * as clipboard from './commands/clipboard';
import * as boilerplate from './commands/boilerplate';
import * as android from './commands/android';

export function activate(context: vscode.ExtensionContext) {
	const register = (cmd: string, cb: (...args: any[]) => any) => vscode.commands.registerCommand(cmd, cb);
	const push = (item: vscode.Disposable) => context.subscriptions.push(item);

	const appsProvider = new DevicesProvider(ProviderType.Apps);
	vscode.window.registerTreeDataProvider('fridaApps', appsProvider);

	push(register('frida.apps.refresh', () => appsProvider.refresh()));

	const psProvider = new DevicesProvider(ProviderType.Processes);
	vscode.window.registerTreeDataProvider('fridaPs', psProvider);

	push(register('frida.ps.refresh', () => psProvider.refresh()));
	push(register('frida.spawn', repl.spawn));
	push(register('frida.spawn.suspended', repl.spawnSuspended));
	push(register('frida.attach', repl.attach));
	push(register('frida.kill', repl.kill));
	push(register('frida.snippet.execute', repl.exec));
	push(register('frida.remote.add', repl.addRemote));
	push(register('frida.remote.remove', repl.delRemote));

	push(register('frida.syslog', syslog.show));
	push(register('frida.syslog.vacuum', syslog.vacuum));

	push(register('frida.browse', file.browse));
	push(register('frida.bundle.copy', clipboard.copy));
	push(register('frida.name.copy', clipboard.copy));
	push(register('frida.device.copy', clipboard.copy));
	
	push(register('frida.device.androidserver', android.startServer));
	push(register('frida.external.objection', objection.explore));
	// push(register('frida.external.bagbak', bagbak.dump));

	push(register('frida.external.setuplldb', lldb.setup));
	push(register('frida.external.lldb', lldb.debug));

	push(register('frida.external.shell', ssh.shell));
	push(register('frida.external.copyid', ssh.copyid));
	push(register('frida.external.sshkeygen', ssh.keygen));

	push(register('frida.boilerplate.agent', boilerplate.agent));
	push(register('frida.boilerplate.module', boilerplate.module));
	push(register('frida.debug.setup', boilerplate.debug));

	push(register('frida.typing.init', typing.init));
}

// this method is called when your extension is deactivated
export function deactivate() {
	iproxy.cleanup();
	lldb.cleanup();
}
