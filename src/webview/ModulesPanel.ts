import * as vscode from 'vscode';
import { l10n } from 'vscode';
import { rpc } from '../driver/backend';
import { TargetItem } from '../providers/devices';
import { generateNativeHooks, NativeHookRequest } from './hooks';

interface ModuleInfo {
  name: string;
  base: string;
  size: number;
  path: string;
}

interface ExportInfo {
  name: string;
  address: string;
  type: string;
}

export class ModulesPanel {
  private panel: vscode.WebviewPanel | undefined;
  private disposables: vscode.Disposable[] = [];
  private exportsCache = new Map<string, ExportInfo[]>();

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
      'fridaModules',
      l10n.t('Modules - {0}', String(this.target.label)),
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
      this.exportsCache.clear();
      this.panel = undefined;
    });
  }

  private post(message: any) {
    this.panel?.webview.postMessage(message);
  }

  private async onMessage(msg: any) {
    switch (msg.type) {
      case 'ready':
        await this.loadModules();
        break;
      case 'loadExports':
        await this.loadExports(msg.moduleName);
        break;
      case 'generateHook':
        this.generateHook(msg as NativeHookRequest);
        break;
    }
  }

  private async loadModules() {
    try {
      this.post({ type: 'setLoading', loading: true, area: 'master' });
      const modules = await rpc(this.target, 'modules') as ModuleInfo[];
      this.post({ type: 'setModules', modules });
    } catch (err: any) {
      this.post({ type: 'error', message: err.message });
    } finally {
      this.post({ type: 'setLoading', loading: false, area: 'master' });
    }
  }

  private async loadExports(moduleName: string) {
    if (this.exportsCache.has(moduleName)) {
      this.post({ type: 'setExports', moduleName, exports: this.exportsCache.get(moduleName)! });
      return;
    }

    try {
      this.post({ type: 'setLoading', loading: true, area: 'detail' });
      const exports = await rpc(this.target, 'exports', moduleName) as ExportInfo[];
      const result = exports ?? [];
      this.exportsCache.set(moduleName, result);
      this.post({ type: 'setExports', moduleName, exports: result });
    } catch (err: any) {
      this.post({ type: 'error', message: err.message });
    } finally {
      this.post({ type: 'setLoading', loading: false, area: 'detail' });
    }
  }

  private generateHook(req: NativeHookRequest) {
    const code = generateNativeHooks(req);
    if (code) {
      vscode.workspace.openTextDocument({ content: code, language: 'javascript' })
        .then(doc => vscode.window.showTextDocument(doc));
    }
  }

  private getHtml(webview: vscode.Webview): string {
    const cssUri = webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, 'resources', 'webview', 'main.css'));
    const jsUri = webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, 'resources', 'webview', 'modules.js'));
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
        <h2>${l10n.t('Modules')}</h2>
        <input type="text" id="module-filter" placeholder="${l10n.t('Filter modules...')}" />
      </div>
      <div class="list-container" id="module-list">
        <div class="loading">${l10n.t('Loading modules...')}</div>
      </div>
    </div>
    <div class="detail-pane">
      <div class="pane-header">
        <h2 id="detail-title">${l10n.t('Select a module')}</h2>
      </div>
      <div id="module-info" class="info-section" style="display:none">
        <div class="info-row"><span class="label">${l10n.t('Path')}</span><span class="value" id="mod-path"></span></div>
        <div class="info-row"><span class="label">${l10n.t('Base')}</span><span class="value" id="mod-base"></span></div>
        <div class="info-row"><span class="label">${l10n.t('Size')}</span><span class="value" id="mod-size"></span></div>
      </div>
      <div id="export-toolbar" style="display:none">
        <div class="pane-header" style="border-bottom:none;padding-bottom:0">
          <input type="text" id="export-filter" placeholder="${l10n.t('Filter exports...')}" />
        </div>
        <div class="select-all-row">
          <input type="checkbox" id="select-all" /><label for="select-all">${l10n.t('Select All')}</label>
          <span class="count" id="export-count"></span>
        </div>
      </div>
      <div class="list-container" id="export-list">
        <div class="placeholder">${l10n.t('Click a module to view its exports')}</div>
      </div>
      <div class="actions" id="actions" style="display:none">
        <button id="btn-hook" disabled>${l10n.t('Generate Hook Script')}</button>
        <span class="selection-count" id="selection-count">${l10n.t('{0} selected', '0')}</span>
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
