import * as vscode from 'vscode';
import * as cp from 'child_process';
import { join } from 'path';
import { interpreter } from '../utils';
import { logger } from '../logger';
import { l10n } from 'vscode';

const lspScript = join(__dirname, '..', '..', 'backend', 'lsp.py');

type Runtime = 'Java' | 'ObjectiveC' | 'Generic';

interface LspResponse {
	id: number | null;
	result?: any;
	error?: string;
	ready?: boolean;
	runtime?: Runtime;
}

type CacheKey = 'classes' | 'modules' | `exports:${string}` | `methods:${string}`;

interface TriggerMatch {
	cacheKey: CacheKey;
	method: string;
	params?: Record<string, string>;
	kind: vscode.CompletionItemKind;
	requires?: 'Java' | 'ObjectiveC';
	/** Column where the completable text starts (e.g. after opening quote) */
	replaceStart: number;
}

export class FridaCompletionProvider implements vscode.CompletionItemProvider, vscode.Disposable {
	private process: cp.ChildProcess | null = null;
	private ready = false;
	private starting = false;
	private cache = new Map<CacheKey, string[]>();
	private pendingRequests = new Map<number, {
		resolve: (value: any) => void;
		reject: (reason: any) => void;
	}>();
	private nextId = 1;
	private buffer = '';
	private workspaceRoot: string | undefined;
	private readyResolve: (() => void) | null = null;
	private runtime: Runtime = 'Generic';
	private stderrChunks: string[] = [];
	private configWatcher: vscode.FileSystemWatcher | undefined;

	constructor() {
		this.workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
		if (this.workspaceRoot) {
			const pattern = new vscode.RelativePattern(this.workspaceRoot, '.vscode/frida.json');
			this.configWatcher = vscode.workspace.createFileSystemWatcher(pattern);
			this.configWatcher.onDidChange(() => this.reload());
			this.configWatcher.onDidCreate(() => this.reload());
			this.configWatcher.onDidDelete(() => this.killProcess());
		}
	}

	dispose(): void {
		this.killProcess();
		this.configWatcher?.dispose();
	}

	reload(): void {
		this.killProcess();
		this.ensureProcess().catch(() => {});
	}

	private async ensureProcess(): Promise<boolean> {
		if (this.ready && this.process) {
			return true;
		}

		if (this.starting) {
			return false;
		}

		if (!this.workspaceRoot) {
			return false;
		}

		const configUri = vscode.Uri.joinPath(
			vscode.Uri.file(this.workspaceRoot),
			'.vscode', 'frida.json'
		);
		try {
			await vscode.workspace.fs.stat(configUri);
		} catch {
			return false;
		}

		this.starting = true;
		this.stderrChunks = [];

		try {
			const pythonPath = await interpreter();
			this.process = cp.spawn(pythonPath, [lspScript, this.workspaceRoot], {
				stdio: ['pipe', 'pipe', 'pipe'],
				env: { ...process.env, PYTHONUNBUFFERED: '1' },
			});

			this.process.stdout!.on('data', (data: Buffer) => {
				this.onStdoutData(data);
			});

			this.process.stderr!.on('data', (data: Buffer) => {
				const text = data.toString().trimEnd();
				this.stderrChunks.push(text);
				logger.appendLine(`[frida-lsp] ${text}`);
			});

			this.process.on('exit', (code, _signal) => {
				this.ready = false;
				this.starting = false;
				this.process = null;

				for (const [, pending] of this.pendingRequests) {
					pending.reject(new Error('Process exited'));
				}
				this.pendingRequests.clear();

				if (code && code !== 0) {
					this.showStartupError();
				}
			});

			await new Promise<void>((resolve, reject) => {
				const timeout = setTimeout(() => {
					reject(new Error('Timeout waiting for frida-lsp ready'));
				}, 30000);

				this.readyResolve = () => {
					clearTimeout(timeout);
					resolve();
				};
			});

			return true;
		} catch (e: any) {
			logger.appendLine(`[frida-lsp] Failed to start: ${e.message}`);
			this.starting = false;
			return false;
		}
	}

	private killProcess(): void {
		if (this.process) {
			this.process.kill();
			this.process = null;
		}
		this.ready = false;
		this.starting = false;
		this.runtime = 'Generic';
		this.cache.clear();
		this.pendingRequests.clear();
	}

	private showStartupError(): void {
		const stderr = this.stderrChunks.join('\n').trim();
		const detail = stderr || l10n.t('Unknown error');
		const actionOpen = l10n.t('Open frida.json');
		vscode.window.showErrorMessage(
			l10n.t('Frida LSP: {0}', detail),
			actionOpen
		).then(choice => {
			if (choice === actionOpen && this.workspaceRoot) {
				const configPath = join(this.workspaceRoot, '.vscode', 'frida.json');
				vscode.window.showTextDocument(vscode.Uri.file(configPath));
			}
		});
	}

	private onStdoutData(data: Buffer): void {
		this.buffer += data.toString();
		const lines = this.buffer.split('\n');
		this.buffer = lines.pop() || '';

		for (const line of lines) {
			if (!line.trim()) { continue; }
			try {
				const msg: LspResponse = JSON.parse(line);

				if (msg.ready) {
					this.ready = true;
					this.starting = false;
					this.runtime = msg.runtime || 'Generic';
					logger.appendLine(`[frida-lsp] Connected, runtime=${this.runtime}`);
					if (this.readyResolve) {
						this.readyResolve();
						this.readyResolve = null;
					}
					continue;
				}

				if (msg.id !== null && msg.id !== undefined) {
					const pending = this.pendingRequests.get(msg.id);
					if (pending) {
						this.pendingRequests.delete(msg.id);
						if (msg.error) {
							pending.reject(new Error(msg.error));
						} else {
							pending.resolve(msg.result);
						}
					}
				}
			} catch (e) {
				logger.appendLine(`[frida-lsp] Parse error: ${line}`);
			}
		}
	}

	private sendRequest(method: string, params?: Record<string, string>): Promise<any> {
		return new Promise((resolve, reject) => {
			if (!this.process?.stdin) {
				reject(new Error('Process not running'));
				return;
			}

			const id = this.nextId++;
			this.pendingRequests.set(id, { resolve, reject });
			this.process.stdin.write(JSON.stringify({ id, method, params }) + '\n');
		});
	}

	private fetchAndCache(key: CacheKey, method: string, params?: Record<string, string>): void {
		this.sendRequest(method, params).then(result => {
			if (Array.isArray(result)) {
				this.cache.set(key, result);
			}
		}).catch((e: Error) => {
			logger.appendLine(`[frida-lsp] Fetch failed for ${key}: ${e.message}`);
		});
	}

	private matchTrigger(lineText: string, position: vscode.Position): TriggerMatch | null {
		const text = lineText.substring(0, position.character);

		// ObjC.classes.SomeClass['  →  method names
		const objcMethodMatch = text.match(/ObjC\.classes\.(\w+)\[['"`]([^'"`]*)$/);
		if (objcMethodMatch) {
			return {
				cacheKey: `methods:${objcMethodMatch[1]}`,
				method: 'methods',
				params: { className: objcMethodMatch[1] },
				kind: vscode.CompletionItemKind.Method,
				requires: 'ObjectiveC',
				replaceStart: position.character - objcMethodMatch[2].length,
			};
		}

		// ObjC.classes.  →  class names
		const objcClassMatch = text.match(/ObjC\.classes\.(\w*)$/);
		if (objcClassMatch) {
			return {
				cacheKey: 'classes',
				method: 'classes',
				kind: vscode.CompletionItemKind.Class,
				requires: 'ObjectiveC',
				replaceStart: position.character - objcClassMatch[1].length,
			};
		}

		// Java.use(" or Java.choose("  →  class names
		const javaMatch = text.match(/Java\.(?:use|choose)\(['"`]([^'"`]*)$/);
		if (javaMatch) {
			return {
				cacheKey: 'classes',
				method: 'classes',
				kind: vscode.CompletionItemKind.Class,
				requires: 'Java',
				replaceStart: position.character - javaMatch[1].length,
			};
		}

		// Process.getModuleByName(' or Process.findModuleByName('
		const moduleMatch = text.match(/Process\.(?:get|find)ModuleByName\(['"`]([^'"`]*)$/);
		if (moduleMatch) {
			return {
				cacheKey: 'modules',
				method: 'modules',
				kind: vscode.CompletionItemKind.Module,
				replaceStart: position.character - moduleMatch[1].length,
			};
		}

		return null;
	}

	async provideCompletionItems(
		document: vscode.TextDocument,
		position: vscode.Position,
		_token: vscode.CancellationToken,
		_context: vscode.CompletionContext,
	): Promise<vscode.CompletionItem[] | undefined> {

		const lineText = document.lineAt(position.line).text;
		const trigger = this.matchTrigger(lineText, position);
		if (!trigger) {
			return undefined;
		}

		// disable GitHub Copilot inline suggestions for 1 minute, 
		// to avoid conflicts and confusion
		vscode.commands.executeCommand('editor.action.inlineSuggest.snooze', 1);

		// Check runtime compatibility if we already know the runtime
		if (trigger.requires && this.runtime !== 'Generic' && this.runtime !== trigger.requires) {
			logger.appendLine(`[frida-lsp] Skip ${trigger.cacheKey}: runtime=${this.runtime}, requires=${trigger.requires}`);
			return undefined;
		}

		const cached = this.cache.get(trigger.cacheKey);
		if (cached) {
			logger.appendLine(`[frida-lsp] Cache hit: ${trigger.cacheKey} (${cached.length} items)`);
			const range = new vscode.Range(position.line, trigger.replaceStart, position.line, position.character);
			return cached.map(name => {
				const item = new vscode.CompletionItem(name, trigger.kind);
				item.range = range;
				item.filterText = name;
				return item;
			});
		}

		// Not cached — start process if needed and fire async fetch
		const processReady = await this.ensureProcess();
		if (!processReady) {
			logger.appendLine(`[frida-lsp] Process not ready for ${trigger.cacheKey}`);
			return undefined;
		}

		// Re-check runtime after process is ready
		if (trigger.requires && this.runtime !== trigger.requires) {
			logger.appendLine(`[frida-lsp] Skip ${trigger.cacheKey}: runtime=${this.runtime}, requires=${trigger.requires}`);
			return undefined;
		}

		logger.appendLine(`[frida-lsp] Fetching ${trigger.cacheKey}`);
		this.fetchAndCache(trigger.cacheKey, trigger.method, trigger.params);
		return undefined;
	}
}
