import * as vscode from 'vscode';
import { l10n } from 'vscode';
import { rpc } from '../driver/backend';
import { TargetItem } from '../providers/devices';
import { logger } from '../logger';

export class PackageTreePanel {
  private panel: vscode.WebviewPanel | undefined;
  private disposables: vscode.Disposable[] = [];

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
      'fridaPackages',
      l10n.t('Java Packages - {0}', String(this.target.label)),
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
    }
  }

  private async loadClasses() {
    try {
      logger.appendLine(`Loading Java classes for ${this.target.label}`);
      this.post({ type: 'setLoading', loading: true });
      const classes = await rpc(this.target, 'classes') as string[];
      logger.appendLine(`Loaded ${classes.length} Java classes`);
      this.post({ type: 'setClasses', classes });
    } catch (err: any) {
      logger.appendLine(`Error: failed to load Java classes - ${err.message}`);
      this.post({ type: 'error', message: err.message });
    } finally {
      this.post({ type: 'setLoading', loading: false });
    }
  }

  private getHtml(webview: vscode.Webview): string {
    const cssUri = webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, 'resources', 'webview', 'main.css'));
    const jsUri = webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, 'resources', 'webview', 'packages.js'));
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
  <div class="tree-container">
    <div class="tree-header">
      <h2>${l10n.t('Java Package Tree')}</h2>
      <div class="tree-toolbar">
        <input type="text" id="tree-filter" placeholder="${l10n.t('Filter classes...')}" />
        <button id="btn-expand-all">${l10n.t('Expand All')}</button>
        <button id="btn-collapse-all">${l10n.t('Collapse All')}</button>
      </div>
    </div>
    <div class="tree-body" id="tree-body">
      <div class="loading">${l10n.t('Loading classes...')}</div>
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
