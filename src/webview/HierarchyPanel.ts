import * as vscode from 'vscode';
import { rpc } from '../driver/backend';
import { TargetItem } from '../providers/devices';

export class HierarchyPanel {
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
      'fridaHierarchy',
      `Objective-C Hierarchy - ${this.target.label}`,
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
        await this.loadHierarchy();
        break;
    }
  }

  private async loadHierarchy() {
    try {
      this.post({ type: 'setLoading', loading: true });
      const [names, parents] = await rpc(this.target, 'objc_class_hierarchy') as [string[], number[]];
      this.post({ type: 'setData', names, parents });
    } catch (err: any) {
      this.post({ type: 'error', message: err.message });
    } finally {
      this.post({ type: 'setLoading', loading: false });
    }
  }

  private getHtml(webview: vscode.Webview): string {
    const cssUri = webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, 'resources', 'webview', 'main.css'));
    const jsUri = webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, 'resources', 'webview', 'hierarchy.js'));
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
      <h2>Objective-C Class Hierarchy</h2>
      <div class="tree-toolbar">
        <input type="text" id="tree-filter" placeholder="Filter classes..." />
        <button id="btn-expand-all">Expand All</button>
        <button id="btn-collapse-all">Collapse All</button>
      </div>
    </div>
    <div class="tree-body" id="tree-body">
      <div class="loading">Loading class hierarchy...</div>
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
