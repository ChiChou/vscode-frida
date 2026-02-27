import * as vscode from 'vscode';
import { l10n } from 'vscode';

import { join } from 'path';
import { mkdir, writeFile } from 'fs/promises';

import { AppItem, ProcessItem } from '../providers/devices';

type TargetConfig = { device: string } & ({ app: string } | { pid: number } | { process: string });

function buildTargetConfig(node: AppItem | ProcessItem): TargetConfig | null {
	if (node instanceof AppItem) {
		return {
			device: node.device.id,
			app: node.data.identifier,
		};
	}

	if (node instanceof ProcessItem) {
		return {
			device: node.device.id,
			pid: node.data.pid,
		};
	}

	return null;
}

async function ensureVscodeFolder(root: string): Promise<string> {
	const vscodePath = join(root, '.vscode');
	await mkdir(vscodePath, { recursive: true });
	return vscodePath;
}

async function writeTargetConfig(configPath: string, config: TargetConfig): Promise<void> {
	const payload = JSON.stringify(config, null, 4) + '\n';
	await writeFile(configPath, payload, 'utf-8');
}

export async function setTarget(node: AppItem | ProcessItem): Promise<void> {
	const root = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
	if (!root) {
		vscode.window.showErrorMessage(l10n.t('No workspace folder open'));
		return;
	}

	const config = buildTargetConfig(node);
	if (!config) {
		return;
	}

	try {
		const vscodePath = await ensureVscodeFolder(root);
		const configPath = join(vscodePath, 'frida.json');
		await writeTargetConfig(configPath, config);

		const targetName = node instanceof AppItem ? node.data.identifier : node.data.name;
		const actionOpen = l10n.t('Open');
		vscode.window.showInformationMessage(
			l10n.t('Created .vscode/frida.json for {0}', targetName),
			actionOpen
		).then(choice => {
			if (choice === actionOpen) {
				vscode.window.showTextDocument(vscode.Uri.file(configPath));
			}
		});
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);
		vscode.window.showErrorMessage(l10n.t('Failed to write .vscode/frida.json: {0}', message));
	}
}
