import * as vscode from 'vscode';
import { rpc } from '../driver/backend';
import { TargetItem } from '../providers/devices';
import { generateObjCHooks, generateJavaHooks, MethodSelection } from './hooks';

interface MethodInfo {
  name: string;
  display: string;
  args: Array<{ type: string; isObject: boolean }>;
  returnType: string;
  isReturnObject: boolean;
  isStatic: boolean;
}

export class ClassesPanel {
  private panel: vscode.WebviewPanel | undefined;
  private disposables: vscode.Disposable[] = [];
  private methodsCache = new Map<string, MethodInfo[]>();
  private superClassesCache = new Map<string, string[]>();
  private runtime = 'Generic';

  constructor(
    private readonly extensionUri: vscode.Uri,
    private readonly target: TargetItem,
  ) { }

  show() {
    if (this.panel) {
      this.panel.reveal();
      return;
    }

    this.panel = vscode.window.createWebviewPanel(
      'fridaClasses',
      `Classes - ${this.target.label}`,
      vscode.ViewColumn.One,
      {
        enableScripts: true,
        localResourceRoots: [vscode.Uri.joinPath(this.extensionUri, 'resources', 'webview')],
        retainContextWhenHidden: true,
      }
    );

    this.panel.webview.html = this.getHtml(this.panel.webview);

    this.panel.webview.onDidReceiveMessage(
      msg => this.onMessage(msg),
      undefined,
      this.disposables
    );

    this.panel.onDidDispose(() => {
      this.disposables.forEach(d => d.dispose());
      this.disposables = [];
      this.methodsCache.clear();
      this.superClassesCache.clear();
      this.panel = undefined;
    });
  }

  private post(message: any) {
    this.panel?.webview.postMessage(message);
  }

  private async onMessage(msg: any) {
    switch (msg.type) {
      case 'ready':
        await this.loadClasses();
        break;
      case 'loadMethods':
        await this.loadMethods(msg.className, msg.ownOnly ?? true);
        await this.loadSuperClasses(msg.className);
        break;
      case 'generateHook':
        this.generateHook(msg.selections as MethodSelection[]);
        break;
      case 'navigateClass':
        this.post({ type: 'selectClass', className: msg.className });
        break;
    }
  }

  private async loadClasses() {
    try {
      this.post({ type: 'setLoading', loading: true, area: 'master' });

      const [classes, runtime] = await Promise.all([
        rpc(this.target, 'classes') as Promise<string[]>,
        rpc(this.target, 'runtime') as Promise<string>,
      ]);

      this.runtime = runtime;
      this.post({ type: 'setRuntime', runtime });
      this.post({ type: 'setClasses', classes });
    } catch (err: any) {
      this.post({ type: 'error', message: err.message });
    } finally {
      this.post({ type: 'setLoading', loading: false, area: 'master' });
    }
  }

  private async loadMethods(className: string, ownOnly: boolean) {
    const cacheKey = `${className}:${ownOnly ? 'own' : 'all'}`;
    if (this.methodsCache.has(cacheKey)) {
      this.post({ type: 'setMethods', className, methods: this.methodsCache.get(cacheKey)! });
      return;
    }

    try {
      this.post({ type: 'setLoading', loading: true, area: 'detail' });
      // note: frida python has a implicit name convention to map js names,
      // own_methods_of -> ownMethodsOf, methods_of -> methodsOf
      const method = ownOnly ? 'own_methods_of' : 'methods_of';
      const methods = await rpc(this.target, method, className) as MethodInfo[];
      const result = methods ?? [];
      this.methodsCache.set(cacheKey, result);
      this.post({ type: 'setMethods', className, methods: result });
    } catch (err: any) {
      this.post({ type: 'error', message: err.message });
    } finally {
      this.post({ type: 'setLoading', loading: false, area: 'detail' });
    }
  }

  private async loadSuperClasses(className: string) {
    if (this.superClassesCache.has(className)) {
      this.post({ type: 'setSuperClasses', className, superClasses: this.superClassesCache.get(className)! });
      return;
    }

    try {
      const superClasses = await rpc(this.target, 'super_classes', className) as string[];
      const result = superClasses ?? [];
      this.superClassesCache.set(className, result);
      this.post({ type: 'setSuperClasses', className, superClasses: result });
    } catch (_) {
      // Non-critical, just skip
    }
  }

  private generateHook(selections: MethodSelection[]) {
    const code = this.runtime === 'Java'
      ? generateJavaHooks(selections)
      : generateObjCHooks(selections);
    if (code) {
      vscode.workspace.openTextDocument({ content: code, language: 'javascript' })
        .then(doc => vscode.window.showTextDocument(doc));
    }
  }

  private getHtml(webview: vscode.Webview): string {
    const cssUri = webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, 'resources', 'webview', 'main.css'));
    const jsUri = webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, 'resources', 'webview', 'classes.js'));
    const nonce = getNonce();

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta http-equiv="Content-Security-Policy"
    content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src 'nonce-${nonce}';">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link href="${cssUri}" rel="stylesheet">
</head>
<body>
  <div class="container">
    <div class="master-pane">
      <div class="pane-header">
        <h2>Classes</h2>
        <input type="text" id="class-filter" placeholder="Filter classes..." />
      </div>
      <div class="list-container" id="class-list">
        <div class="loading">Loading classes...</div>
      </div>
    </div>
    <div class="detail-pane">
      <div class="pane-header">
        <h2 id="detail-title">Select a class</h2>
        <div id="breadcrumb" class="breadcrumb" style="display:none"></div>
      </div>
      <div id="method-toolbar" style="display:none">
        <div class="pane-header" style="border-bottom:none;padding-bottom:0">
          <div class="method-controls">
            <input type="text" id="method-filter" placeholder="Filter methods..." />
            <label><input type="checkbox" id="own-methods-toggle" checked /> Own methods only</label>
          </div>
        </div>
        <div class="select-all-row">
          <input type="checkbox" id="select-all" /><label for="select-all">Select All</label>
          <span class="count" id="method-count"></span>
        </div>
      </div>
      <div class="list-container" id="method-list">
        <div class="placeholder">Click a class to view its methods</div>
      </div>
      <div class="actions" id="actions" style="display:none">
        <button id="btn-hook" disabled>Generate Hook Script</button>
        <span class="selection-count" id="selection-count">0 selected</span>
      </div>
    </div>
  </div>
  <script nonce="${nonce}" src="${jsUri}"></script>
</body>
</html>`;
  }
}

function getNonce(): string {
  let text = '';
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  for (let i = 0; i < 32; i++) {
    text += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return text;
}
