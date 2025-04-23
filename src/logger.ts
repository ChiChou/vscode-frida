import { window, l10n } from 'vscode';

export const logger = window.createOutputChannel(l10n.t('Frida Extension'));
