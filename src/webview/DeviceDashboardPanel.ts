import * as vscode from 'vscode';
import { l10n } from 'vscode';
import { exec } from '@/driver/backend';
import { DeviceItem } from '@/providers/devices';
import { logger } from '@/logger';

export class DeviceDashboardPanel {
  private panel: vscode.WebviewPanel | undefined;
  private disposables: vscode.Disposable[] = [];

  constructor(
    private readonly extensionUri: vscode.Uri,
    private readonly device: DeviceItem,
  ) { }

  show() {
    if (this.panel) {
      this.panel.reveal();
      return;
    }

    this.panel = vscode.window.createWebviewPanel(
      'fridaDashboard',
      l10n.t('Dashboard - {0}', String(this.device.data.name)),
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
        await this.loadInfo();
        break;
    }
  }

  private async loadInfo() {
    try {
      logger.appendLine(`Loading device info for ${this.device.data.name}`);
      this.post({ type: 'setLoading', loading: true });
      const info = await exec('info', this.device.data.id);
      logger.appendLine(`Loaded device info`);
      this.post({ type: 'setInfo', info });
    } catch (err: any) {
      logger.appendLine(`Error: failed to load device info - ${err.message}`);
      this.post({ type: 'error', message: err.message });
    } finally {
      this.post({ type: 'setLoading', loading: false });
    }
  }

  private getHtml(webview: vscode.Webview): string {
    const cssUri = webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, 'resources', 'webview', 'main.css'));
    const jsUri = webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, 'resources', 'webview', 'dashboard.js'));
    const nonce = getNonce();

    const i18n = {
      device: l10n.t('Device'),
      os: l10n.t('Operating System'),
      frida: 'Frida',
      security: l10n.t('Security'),
      name: l10n.t('Name'),
      id: 'ID',
      type: l10n.t('Type'),
      version: l10n.t('Version'),
      arch: l10n.t('Architecture'),
      platform: l10n.t('Platform'),
      access: l10n.t('Access'),
      full: l10n.t('Full (Rooted/Jailbroken)'),
      jailed: l10n.t('Jailed'),
      unknown: l10n.t('Unknown'),
    };

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
  <div class="dashboard-container">
    <div class="loading" id="dashboard-loading">${l10n.t('Loading device info...')}</div>
    <div id="dashboard-cards" style="display:none"></div>
  </div>
  <script nonce="${nonce}">window.I18N = ${JSON.stringify(i18n)};</script>
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
