import * as vscode from 'vscode';
import { TargetItem } from '../providers/devices';
import { InspectorPanel, protocolsConfig } from './InspectorPanel';

export class ProtocolsPanel extends InspectorPanel {
  constructor(extensionUri: vscode.Uri, target: TargetItem) {
    super(extensionUri, target, protocolsConfig);
  }
}
