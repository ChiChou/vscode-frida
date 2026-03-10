import * as vscode from 'vscode';
import { l10n } from 'vscode';
import { rpc } from '../driver/backend';
import { TargetItem } from '../providers/devices';
import { generateObjCHooks, generateJavaHooks, MethodSelection } from './hooks';
import { generateHeader, ObjCClassInfo, generateJavaHeader, JavaClassInfo, generateProtocolHeader, ObjCProtocolInfo } from '../classdump';
import { openUntitledDocument } from '../utils';
import { logger } from '../logger';

interface MethodInfo {
  name: string;
  display: string;
  args: Array<{ type: string }>;
  returnType: string;
  isStatic: boolean;
}

export interface InspectorConfig {
  viewType: string;
  titlePrefix: string;
  itemsLabel: string;
  itemLabel: string;
  filterPlaceholder: string;
  detailPlaceholder: string;
  loadingMessage: string;
  rpcList: string;
  rpcOwnMethods: string;
  rpcMethods: string;
  rpcHierarchy: string;
  rpcInfo: string;
  supportsHierarchy: boolean;
  dumpGenerator: (panel: InspectorPanel, className: string) => Promise<void>;
}

export const classesConfig: InspectorConfig = {
  viewType: 'fridaClasses',
  titlePrefix: 'Classes',
  itemsLabel: l10n.t('Classes'),
  itemLabel: 'class',
  filterPlaceholder: l10n.t('Filter classes...'),
  detailPlaceholder: l10n.t('Click a class to view its methods'),
  loadingMessage: l10n.t('Loading classes...'),
  rpcList: 'classes',
  rpcOwnMethods: 'own_methods_of',
  rpcMethods: 'methods_of',
  rpcHierarchy: 'super_classes',
  rpcInfo: 'class_info',
  supportsHierarchy: true,
  dumpGenerator: async (panel, className) => {
    const info = await rpc(panel.target, 'class_info', className);
    if (panel.runtime === 'Java') {
      const header = generateJavaHeader(info as JavaClassInfo);
      const shortName = className.split('.').pop() ?? className;
      await openUntitledDocument(`${shortName}.java`, header, 'java');
    } else {
      const header = generateHeader(info as ObjCClassInfo);
      await openUntitledDocument(`${className}.h`, header, 'objective-c');
    }
  },
};

export const protocolsConfig: InspectorConfig = {
  viewType: 'fridaProtocols',
  titlePrefix: 'Protocols',
  itemsLabel: l10n.t('Protocols'),
  itemLabel: 'protocol',
  filterPlaceholder: l10n.t('Filter protocols...'),
  detailPlaceholder: l10n.t('Click a protocol to view its methods'),
  loadingMessage: l10n.t('Loading protocols...'),
  rpcList: 'protocols',
  rpcOwnMethods: 'own_protocol_methods_of',
  rpcMethods: 'protocol_methods_of',
  rpcHierarchy: 'parent_protocols',
  rpcInfo: 'protocol_info',
  supportsHierarchy: true,
  dumpGenerator: async (panel, protocolName) => {
    const info = await rpc(panel.target, 'protocol_info', protocolName);
    const header = generateProtocolHeader(info as ObjCProtocolInfo);
    await openUntitledDocument(`${protocolName}.h`, header, 'objective-c');
  },
};

export class InspectorPanel {
  private panel: vscode.WebviewPanel | undefined;
  private disposables: vscode.Disposable[] = [];
  private methodsCache = new Map<string, MethodInfo[]>();
  private hierarchyCache = new Map<string, string[]>();
  runtime = 'Generic';

  constructor(
    private readonly extensionUri: vscode.Uri,
    readonly target: TargetItem,
    private readonly config: InspectorConfig,
  ) { }

  show() {
    if (this.panel) {
      this.panel.reveal();
      return;
    }

    this.panel = vscode.window.createWebviewPanel(
      this.config.viewType,
      l10n.t('{0} - {1}', this.config.titlePrefix, String(this.target.label)),
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
      this.hierarchyCache.clear();
      this.panel = undefined;
    });
  }

  private post(message: any) {
    this.panel?.webview.postMessage(message);
  }

  private async onMessage(msg: any) {
    switch (msg.type) {
      case 'ready':
        await this.loadItems();
        break;
      case 'loadMethods':
        await this.loadMethods(msg.className, msg.ownOnly ?? true);
        if (this.config.supportsHierarchy) {
          await this.loadHierarchy(msg.className);
        }
        break;
      case 'generateHook':
        this.generateHook(msg.selections as MethodSelection[]);
        break;
      case 'classDump':
        await this.dumpInfo(msg.className);
        break;
      case 'navigateClass':
        this.post({ type: 'selectClass', className: msg.className });
        break;
    }
  }

  private async loadItems() {
    try {
      logger.appendLine(`Loading ${this.config.itemLabel}s for ${this.target.label}`);
      this.post({ type: 'setLoading', loading: true, area: 'master' });

      const [items, runtime] = await Promise.all([
        rpc(this.target, this.config.rpcList) as Promise<string[]>,
        rpc(this.target, 'runtime') as Promise<string>,
      ]);

      this.runtime = runtime;
      logger.appendLine(`Loaded ${items.length} ${this.config.itemLabel}s (runtime: ${runtime})`);
      this.post({ type: 'setRuntime', runtime });
      this.post({ type: 'setClasses', classes: items });
    } catch (err: any) {
      logger.appendLine(`Error: failed to load ${this.config.itemLabel}s - ${err.message}`);
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
      logger.appendLine(`Loading methods for ${this.config.itemLabel} ${className} (${ownOnly ? 'own' : 'all'})`);
      this.post({ type: 'setLoading', loading: true, area: 'detail' });
      const method = ownOnly ? this.config.rpcOwnMethods : this.config.rpcMethods;
      const methods = await rpc(this.target, method, className) as MethodInfo[];
      const result = methods ?? [];
      this.methodsCache.set(cacheKey, result);
      this.post({ type: 'setMethods', className, methods: result });
    } catch (err: any) {
      logger.appendLine(`Error: failed to load methods for ${className} - ${err.message}`);
      this.post({ type: 'error', message: err.message });
    } finally {
      this.post({ type: 'setLoading', loading: false, area: 'detail' });
    }
  }

  private async loadHierarchy(name: string) {
    if (this.hierarchyCache.has(name)) {
      this.post({ type: 'setSuperClasses', className: name, superClasses: this.hierarchyCache.get(name)! });
      return;
    }

    try {
      const chain = await rpc(this.target, this.config.rpcHierarchy, name) as string[];
      const result = chain ?? [];
      this.hierarchyCache.set(name, result);
      this.post({ type: 'setSuperClasses', className: name, superClasses: result });
    } catch (_) {
      // Non-critical, just skip
    }
  }

  private async dumpInfo(name: string) {
    await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: l10n.t('Dumping {0}...', name) },
      async () => {
        try {
          await this.config.dumpGenerator(this, name);
        } catch (err: any) {
          logger.appendLine(`Error: failed to dump ${this.config.itemLabel} ${name} - ${err.message}`);
          this.post({ type: 'error', message: err.message });
        }
      }
    );
  }

  private async generateHook(selections: MethodSelection[]) {
    const code = this.runtime === 'Java'
      ? generateJavaHooks(selections)
      : generateObjCHooks(selections);
    if (code) {
      const className = selections[0]?.className ?? 'hook';
      await openUntitledDocument(`${className}.js`, code, 'javascript');
    }
  }

  private getHtml(webview: vscode.Webview): string {
    const cssUri = webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, 'resources', 'webview', 'main.css'));
    const jsUri = webview.asWebviewUri(vscode.Uri.joinPath(this.extensionUri, 'resources', 'webview', 'classes.js'));
    const nonce = getNonce();

    const i18n = {
      hook: 'Hook',
      batchHook: l10n.t('Batch Hook'),
      classDump: l10n.t('Generate Header'),
      protocolDump: l10n.t('Generate Header'),
      methods: l10n.t(' methods'),
      selected: l10n.t(' selected'),
    };

    const dumpLabel = l10n.t('Generate Header');

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
        <h2>${this.config.itemsLabel}</h2>
        <input type="text" id="class-filter" placeholder="${this.config.filterPlaceholder}" />
      </div>
      <div class="list-container" id="class-list">
        <div class="loading">${this.config.loadingMessage}</div>
      </div>
    </div>
    <div class="detail-pane">
      <div class="pane-header">
        <h2 id="detail-title">${l10n.t('Select a {0}', this.config.itemLabel)}</h2>
        <div id="breadcrumb" class="breadcrumb" style="display:none"></div>
      </div>
      <div id="method-toolbar" style="display:none">
        <div class="pane-header" style="border-bottom:none;padding-bottom:0">
          <div class="method-controls">
            <input type="text" id="method-filter" placeholder="${l10n.t('Filter methods...')}" />
            <label><input type="checkbox" id="own-methods-toggle" checked /> ${l10n.t('Own methods only')}</label>
          </div>
        </div>
        <div class="select-all-row">
          <input type="checkbox" id="select-all" /><label for="select-all">${l10n.t('Select All')}</label>
          <span class="count" id="method-count"></span>
        </div>
      </div>
      <div class="list-container" id="method-list">
        <div class="placeholder">${this.config.detailPlaceholder}</div>
      </div>
      <div class="actions" id="actions" style="display:none">
        <button id="btn-hook" disabled>${l10n.t('Batch Hook')}</button>
        <span class="selection-count" id="selection-count">${l10n.t('{0} selected', '0')}</span>
        <button id="btn-classdump" style="display:none;margin-left:auto">${dumpLabel}</button>
      </div>
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
