import * as vscode from 'vscode';
import * as cp from 'child_process';
import ts from 'typescript';

import { l10n } from 'vscode';
import { join } from 'path';

import { interpreter } from '../utils';
import { logger } from '../logger';

const lspScript = join(__dirname, '..', '..', 'backend', 'lsp.py');

type Runtime = 'Java' | 'ObjectiveC' | 'Generic';

interface LspResponse {
	id: number | null;
	result?: any;
	error?: string;
	ready?: boolean;
	runtime?: Runtime;
}

type CacheKey = 'classes' | 'modules' | `exports:${string}` | `methods:${string}` | `members:${string}`;

interface TriggerMatch {
	cacheKey: CacheKey;
	method: string;
	params?: Record<string, string>;
	kind: vscode.CompletionItemKind;
	requires?: 'Java' | 'ObjectiveC';
	/** Column where the completable text starts (e.g. after opening quote) */
	replaceStart: number;
	/** Optional filter+transform applied to raw results before creating items */
	mapNames?: (names: string[]) => string[];
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

	private async fetchAndCache(key: CacheKey, method: string, params?: Record<string, string>): Promise<string[] | { methods: string[]; fields: string[] } | null> {
		try {
			const result = await this.sendRequest(method, params);
			if (Array.isArray(result)) {
				this.cache.set(key, result);
				return result;
			} else if (result && typeof result === 'object') {
				this.cache.set(key, result as any);
				return result as { methods: string[]; fields: string[] };
			}
			return null;
		} catch (e: any) {
			logger.appendLine(`[frida-lsp] Fetch failed for ${key}: ${e.message}`);
			return null;
		}
	}

	private createCompletionItems(
		result: string[] | { methods: string[]; fields: string[] },
		trigger: TriggerMatch,
		position: vscode.Position
	): vscode.CompletionItem[] {
		const range = new vscode.Range(position.line, trigger.replaceStart, position.line, position.character);
		const isMemberCache = trigger.cacheKey.startsWith('members:');

		if (isMemberCache && typeof result === 'object' && !Array.isArray(result)) {
			const memberCache = result as { methods: string[]; fields: string[] };
			const items: vscode.CompletionItem[] = [];
			for (const name of memberCache.methods) {
				const item = new vscode.CompletionItem(name, vscode.CompletionItemKind.Method);
				item.range = range;
				item.filterText = name;
				items.push(item);
			}
			for (const name of memberCache.fields) {
				const item = new vscode.CompletionItem(name, vscode.CompletionItemKind.Field);
				item.range = range;
				item.filterText = name;
				items.push(item);
			}
			return items;
		}

		let names = result as string[];
		if (trigger.mapNames)
			names = trigger.mapNames(names);

		return names.map(name => {
			const item = new vscode.CompletionItem(name, trigger.kind);
			item.range = range;
			item.filterText = name;
			return item;
		});
	}

	private findJavaClassForVariable(document: vscode.TextDocument, position: vscode.Position, varName: string): string | null {
		const sourceFile = ts.createSourceFile(
			document.fileName,
			document.getText(),
			ts.ScriptTarget.Latest,
			true
		);

		const offset = document.offsetAt(position);

		const node = this.findNodeAtPosition(sourceFile, offset);
		if (!node) return null;

		const scope = this.findEnclosingScope(node);
		if (!scope) return null;

		return this.findVariableAssignmentInScope(scope, varName, offset);
	}

	private findNodeAtPosition(sourceFile: ts.SourceFile, position: number): ts.Node | null {
		let result: ts.Node | null = null;

		const visit = (node: ts.Node) => {
			const start = node.getStart(sourceFile);
			const end = node.getEnd();

			if (position >= start && position <= end) {
				result = node;
				ts.forEachChild(node, visit);
			}
		};

		ts.forEachChild(sourceFile, visit);
		return result;
	}

	private findEnclosingScope(node: ts.Node): ts.Node | null {
		let current: ts.Node = node;
		while (current) {
			if (
				ts.isFunctionDeclaration(current) ||
				ts.isFunctionExpression(current) ||
				ts.isArrowFunction(current) ||
				ts.isMethodDeclaration(current) ||
				ts.isConstructorDeclaration(current) ||
				ts.isBlock(current) ||
				ts.isSourceFile(current)
			) {
				return current;
			}
			current = current.parent;
		}
		return null;
	}

	private findVariableAssignmentInScope(scope: ts.Node, varName: string, cursorOffset: number): string | null {
		const checkNode = (node: ts.Node): string | null => {
			if (ts.isVariableDeclaration(node)) {
				if (ts.isIdentifier(node.name) && node.name.text === varName) {
					const init = node.initializer;
					if (init && ts.isCallExpression(init) && this.isJavaUseCall(init)) {
						return this.extractClassNameFromJavaUse(init);
					}
				}
			}
			return null;
		};

		const visit = (node: ts.Node): string | null => {
			if (ts.isVariableStatement(node)) {
				for (const decl of node.declarationList.declarations) {
					const result = checkNode(decl);
					if (result) return result;
				}
			}

			if (ts.isVariableDeclaration(node)) {
				const result = checkNode(node);
				if (result) return result;
			}

			return ts.forEachChild(node, visit) ?? null;
		};

		const result = visit(scope);
		if (result) return result;

		if (scope.parent && !ts.isSourceFile(scope)) {
			const parentScope = this.findEnclosingScope(scope.parent);
			if (parentScope) {
				return this.findVariableAssignmentInScope(parentScope, varName, cursorOffset);
			}
		}

		return null;
	}

	private isJavaUseCall(node: ts.Node): boolean {
		if (!ts.isCallExpression(node)) return false;

		const expr = node.expression;
		if (!ts.isPropertyAccessExpression(expr)) return false;

		const obj = expr.expression;
		const prop = expr.name.text;

		return ts.isIdentifier(obj) && obj.text === 'Java' && (prop === 'use' || prop === 'choose');
	}

	private extractClassNameFromJavaUse(node: ts.CallExpression): string | null {
		const arg = node.arguments[0];
		if (!arg) return null;

		if (ts.isStringLiteral(arg)) {
			return arg.text;
		}

		return null;
	}

	private matchTrigger(lineText: string, position: vscode.Position, document?: vscode.TextDocument): TriggerMatch | null {
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

		// ObjC.classes.SomeClass.  →  public class method names as JS properties
		const objcDotMethodMatch = text.match(/ObjC\.classes\.(\w+)\.(\w*)$/);
		if (objcDotMethodMatch) {
			return {
				cacheKey: `methods:${objcDotMethodMatch[1]}`,
				method: 'methods',
				params: { className: objcDotMethodMatch[1] },
				kind: vscode.CompletionItemKind.Method,
				requires: 'ObjectiveC',
				replaceStart: position.character - objcDotMethodMatch[2].length,
				mapNames: (names) => names
					.filter(n => n.startsWith('+ ') && !n.startsWith('+ _'))
					.map(n => n.substring(2).replace(/:/g, '_')),
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

		// Java.use("SomeClass"). or Java.choose("SomeClass").  →  methods and fields
		const javaMemberMatch = text.match(/Java\.(?:use|choose)\(['"`]([^'"`]+)['"`]\)\.\w*$/);
		if (javaMemberMatch) {
			const className = javaMemberMatch[1];
			const afterDot = text.split('.').pop() || '';
			return {
				cacheKey: `members:${className}`,
				method: 'classMembers',
				params: { className },
				kind: vscode.CompletionItemKind.Method,
				requires: 'Java',
				replaceStart: position.character - afterDot.length,
			};
		}

		// variableName.  →  methods and fields (if variable was assigned from Java.use/choose)
		const varMemberMatch = text.match(/(\w+)\.\w*$/);
		if (varMemberMatch && document) {
			const varName = varMemberMatch[1];
			const className = this.findJavaClassForVariable(document, position, varName);
			if (className) {
				const afterDot = text.split('.').pop() || '';
				return {
					cacheKey: `members:${className}`,
					method: 'classMembers',
					params: { className },
					kind: vscode.CompletionItemKind.Method,
					requires: 'Java',
					replaceStart: position.character - afterDot.length,
				};
			}
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
		const trigger = this.matchTrigger(lineText, position, document);
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
			logger.appendLine(`[frida-lsp] Cache hit: ${trigger.cacheKey}`);
			return this.createCompletionItems(cached, trigger, position);
		}

		// Not cached — start process if needed and fetch
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
		const result = await this.fetchAndCache(trigger.cacheKey, trigger.method, trigger.params);

		if (!result) {
			return undefined;
		}

		return this.createCompletionItems(result, trigger, position);
	}
}
