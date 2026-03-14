import * as vscode from 'vscode';
import { l10n } from 'vscode';
import { spawn, ChildProcess } from 'child_process';
import { createWriteStream } from 'fs';
import { unlink } from 'fs/promises';
import { dirname, join } from 'path';
import { homedir } from 'os';
import { rpc } from '../driver/backend';
import { asParam } from '../driver/remote';
import { interpreter } from '../utils';
import { TargetItem, AppItem, ProcessItem } from '../providers/devices';
import { logger } from '../logger';

const py = require('path').join(__dirname, '..', '..', 'backend', 'driver.py');

export class MemoryPanel {
  private panel: vscode.WebviewPanel | undefined;
  private dumpProcess: ChildProcess | undefined;
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
      'fridaMemory',
      l10n.t('Memory - {0}', String(this.target.label)),
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
      this.killDump();
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
        await this.loadRanges();
        break;
      case 'dump':
        await this.dumpMemory(msg.address, msg.size);
        break;
    }
  }

  private async loadRanges() {
    try {
      logger.appendLine(`Loading memory ranges for ${this.target.label}`);
      this.post({ type: 'setLoading', loading: true, area: 'ranges' });
      const ranges = await rpc(this.target, 'ranges');
      logger.appendLine(`Loaded ${(ranges as any[]).length} memory ranges`);
      this.post({ type: 'setRanges', ranges });
    } catch (err: any) {
      logger.appendLine(`Error: failed to load memory ranges - ${err.message}`);
      this.post({ type: 'error', message: err.message });
    } finally {
      this.post({ type: 'setLoading', loading: false, area: 'ranges' });
    }
  }

  private async dumpMemory(address: string, size: number) {
    if (this.dumpProcess) return;

    const config = vscode.workspace.getConfiguration('frida');
    const lastDir = config.get<string>('dumpOutput') || homedir();
    const defaultUri = vscode.Uri.file(join(lastDir, `${address}_${size}.bin`));

    const uri = await vscode.window.showSaveDialog({
      defaultUri,
      filters: { 'Binary': ['bin'], 'All': ['*'] },
    });
    if (!uri) return;

    config.update('dumpOutput', dirname(uri.fsPath), true);

    const pythonPath = await interpreter();
    const remoteDevices = asParam();

    let bundleOrPid: string[];
    if (this.target instanceof AppItem) {
      bundleOrPid = ['--app', this.target.data.identifier];
    } else if (this.target instanceof ProcessItem) {
      bundleOrPid = ['--pid', this.target.data.pid.toString()];
    } else {
      return;
    }

    const args = [py, ...remoteDevices, 'dump', '--device', this.target.device.id,
      ...bundleOrPid, address, size.toString()];
    logger.appendLine(`[memory] dump: ${pythonPath} ${args.join(' ')}`);

    await vscode.window.withProgress({
      location: vscode.ProgressLocation.Notification,
      title: l10n.t('Dumping {0}', address),
      cancellable: true,
    }, (progress, token) => new Promise<void>((resolve) => {
      const fileStream = createWriteStream(uri.fsPath);
      const proc = spawn(pythonPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
      this.dumpProcess = proc;
      let bytesWritten = 0;
      let lastPct = 0;

      token.onCancellationRequested(() => {
        proc.kill('SIGINT');
      });

      proc.stdout!.on('data', (chunk: Buffer) => {
        fileStream.write(chunk);
        bytesWritten += chunk.length;
        const pct = Math.round((bytesWritten / size) * 100);
        if (pct > lastPct) {
          progress.report({ increment: pct - lastPct, message: `${pct}%` });
          lastPct = pct;
        }
      });

      proc.stderr!.on('data', (chunk: Buffer) => {
        logger.appendLine(`[memory] dump stderr: ${chunk.toString().trim()}`);
      });

      proc.on('exit', (code) => {
        fileStream.end(() => {
          this.dumpProcess = undefined;
          if (token.isCancellationRequested) {
            unlink(uri.fsPath).catch(() => {});
          } else if (code === 0) {
            const reveal = l10n.t('Reveal');
            vscode.window.showInformationMessage(
              l10n.t('Dumped {0} bytes to {1}', bytesWritten, uri.fsPath), reveal
            ).then(choice => {
              if (choice === reveal) {
                vscode.commands.executeCommand('revealFileInOS', uri);
              }
            });
          } else {
            unlink(uri.fsPath).catch(() => {});
            this.post({ type: 'error', message: l10n.t('Dump failed') });
          }
          resolve();
        });
      });
    }));
  }

  private killDump() {
    if (!this.dumpProcess) return;
    this.dumpProcess.kill('SIGINT');
  }

  private getHtml(webview: vscode.Webview): string {
    const cssUri = webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, 'resources', 'webview', 'main.css'));
    const jsUri = webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, 'resources', 'webview', 'memory.js'));
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
      <h2>${l10n.t('Memory Ranges')}</h2>
      <div class="perm-filter">
        <label><input type="checkbox" id="filter-r" /> r</label>
        <label><input type="checkbox" id="filter-w" /> w</label>
        <label><input type="checkbox" id="filter-x" /> x</label>
      </div>
    </div>
    <div class="list-container" id="range-list">
      <div class="loading">${l10n.t('Loading memory ranges...')}</div>
    </div>
  </div>
  <script nonce="${nonce}"></script>
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
