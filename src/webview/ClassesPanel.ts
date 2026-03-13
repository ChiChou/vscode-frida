import * as vscode from 'vscode';
import { TargetItem } from '@/providers/devices';
import { InspectorPanel, classesConfig } from './InspectorPanel';

export class ClassesPanel extends InspectorPanel {
  constructor(extensionUri: vscode.Uri, target: TargetItem) {
    super(extensionUri, target, classesConfig);
  }
}
