import * as vscode from 'vscode';
import { l10n } from 'vscode';
import { InteractiveSession } from '@/driver/interactive';
import { TargetItem } from '@/providers/devices';
import { logger } from '@/logger';

export class MemoryScannerPanel {
  private panel: vscode.WebviewPanel | undefined;
  private session: InteractiveSession | undefined;
  private disposables: vscode.Disposable[] = [];
  private scanResolve: (() => void) | undefined;
  private scanProgress: vscode.Progress<{ increment: number; message: string }> | undefined;
  private scanLastPct = 0;

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
      'fridaMemoryScanner',
      l10n.t('Memory Scanner - {0}', String(this.target.label)),
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
      this.cleanup();
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
        await this.initSession();
        break;
      case 'scan':
        await this.startScan(msg.pattern);
        break;
      case 'cancel':
        await this.cancelScan();
        break;
      case 'read':
        await this.readMemory(msg.address, msg.size);
        break;
    }
  }

  private async initSession() {
    try {
      logger.appendLine(`[scanner] creating interactive session for ${this.target.label}`);
      this.post({ type: 'setStatus', status: 'connecting' });
      this.session = await InteractiveSession.create(this.target);

      this.session.on('message', (payload: any) => {
        if (payload.subject === 'scanAll') {
          switch (payload.event) {
            case 'match':
              this.post({ type: 'scanMatch', address: payload.address, size: payload.size });
              break;
            case 'progress':
              this.post({ type: 'scanProgress', current: payload.current, total: payload.total });
              if (this.scanProgress) {
                const pct = Math.round((payload.current / payload.total) * 100);
                if (pct > this.scanLastPct) {
                  this.scanProgress.report({
                    increment: pct - this.scanLastPct,
                    message: `${payload.current} / ${payload.total} (${pct}%)`,
                  });
                  this.scanLastPct = pct;
                }
              }
              break;
            case 'complete':
              this.post({ type: 'scanComplete', cancelled: payload.cancelled,
                totalRanges: payload.totalRanges, scannedRanges: payload.scannedRanges,
                totalMatches: payload.totalMatches });
              this.endScanProgress();
              break;
          }
        }
      });

      this.session.on('exit', () => {
        this.post({ type: 'setStatus', status: 'disconnected' });
      });

      // Load ranges via RPC
      const ranges = await this.session.call('ranges');
      this.post({ type: 'setRanges', ranges });
      this.post({ type: 'setStatus', status: 'ready' });
    } catch (err: any) {
      logger.appendLine(`[scanner] failed to init session: ${err.message}`);
      this.post({ type: 'error', message: err.message });
      this.post({ type: 'setStatus', status: 'error' });
    }
  }

  private async startScan(pattern: string) {
    if (!this.session) return;

    this.scanLastPct = 0;
    vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: l10n.t('Scanning...'),
    }, (progress) => new Promise<void>((resolve) => {
      this.scanProgress = progress;
      this.scanResolve = resolve;
    }));

    try {
      logger.appendLine(`[scanner] scanning all ranges for pattern: ${pattern}`);
      await this.session.call('scan_all', pattern);
    } catch (err: any) {
      logger.appendLine(`[scanner] scan error: ${err.message}`);
      this.post({ type: 'error', message: err.message });
      this.post({ type: 'scanComplete', cancelled: false, totalRanges: 0, scannedRanges: 0, totalMatches: 0 });
      this.endScanProgress();
    }
  }

  private async cancelScan() {
    if (!this.session) return;
    try {
      logger.appendLine('[scanner] cancelling scan');
      await this.session.call('cancel_scan');
    } catch (err: any) {
      logger.appendLine(`[scanner] cancel error: ${err.message}`);
    }
  }

  private endScanProgress() {
    this.scanResolve?.();
    this.scanResolve = undefined;
    this.scanProgress = undefined;
    this.scanLastPct = 0;
  }

  private cleanup() {
    this.endScanProgress();
    if (!this.session) return;
    const session = this.session;
    this.session = undefined;
    session.call('cancel_scan').catch(() => {});
    session.close();
  }

  private async readMemory(address: string, size: number) {
    if (!this.session) return;
    try {
      const hex = await this.session.call('read_memory', address, size);
      this.post({ type: 'setReadResult', address, hex });
    } catch (err: any) {
      logger.appendLine(`[scanner] read error: ${err.message}`);
      this.post({ type: 'error', message: err.message });
    }
  }

  private getHtml(webview: vscode.Webview): string {
    const cssUri = webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, 'resources', 'webview', 'main.css'));
    const jsUri = webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, 'resources', 'webview', 'scanner.js'));
    const nonce = getNonce();

    const i18n = {
      memoryScanner: l10n.t('Memory Scanner'),
      scan: l10n.t('Scan'),
      stop: l10n.t('Stop'),
      string: l10n.t('String'),
      hex: l10n.t('Hex'),
      pointer: l10n.t('Pointer'),
      pattern: l10n.t('Pattern...'),
      results: l10n.t('Results'),
      address: l10n.t('Address'),
      hexDump: l10n.t('Hex Dump'),
      noResults: l10n.t('No matches found'),
      connecting: l10n.t('Connecting...'),
      scanning: l10n.t('Scanning...'),
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
  <div class="scanner-layout">
    <div class="scanner-header">
      <div class="scan-toolbar" id="scan-tabs">
        <button class="scan-tab active" data-mode="string">${l10n.t('String')}</button>
        <button class="scan-tab" data-mode="hex">${l10n.t('Hex')}</button>
        <button class="scan-tab" data-mode="pointer">${l10n.t('Pointer')}</button>
        <input type="text" id="scan-input" placeholder="${l10n.t('Pattern...')}" disabled />
        <button id="btn-scan" disabled>${l10n.t('Scan')}</button>
        <button id="btn-stop" style="display:none">${l10n.t('Stop')}</button>
      </div>
      <div class="scan-progress" id="scan-progress" style="display:none">
        <div class="scan-progress-bar"><div class="scan-progress-fill" id="progress-fill"></div></div>
        <span class="scan-progress-text" id="progress-text"></span>
      </div>
    </div>
    <div class="scanner-body">
      <div class="list-container" id="scan-results">
        <div class="loading" id="status-text">${l10n.t('Connecting...')}</div>
      </div>
      <div id="hex-dump" class="hex-dump-section" style="display:none"></div>
    </div>
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
