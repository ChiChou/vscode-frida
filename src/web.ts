import { promises as fsp } from "fs";
import { join, dirname } from "path";
import { Uri, Webview } from "vscode";

const dist = require.resolve('@vscode/webview-ui-toolkit');
export const HTML_BASE = Uri.file(dirname(dist));

const _cache: Map<string, string> = new Map();

async function readTemplate(name: string): Promise<string> {
    if (_cache.has(name)) {
        return _cache.get(name) as string;
    }
    const full = join(__dirname, '..', 'webview', `${name}.html`);
    const buf = await fsp.readFile(full);
    return buf.toString();
}

export async function render(template: string, vars: { [name: string]: any } = {}): Promise<string> {
    const html = await readTemplate(template);
    return html.replace(/\$\{(\w+)\}/g, (substr, arg0) => {
        return vars[arg0];
    });
}

/**
 * A helper function which will get the webview URI of a given file or resource.
 *
 * @remarks This URI can be used within a webview's HTML as a link to the
 * given file/resource.
 *
 * @param webview A reference to the extension webview
 * @param extensionUri The URI of the directory containing the extension
 * @param pathList An array of strings representing the path to a file/resource
 * @returns A URI pointing to the file/resource
 */
export function getUri(webview: Webview, extensionUri: Uri, pathList: string[]) {
    return webview.asWebviewUri(Uri.joinPath(extensionUri, ...pathList));
}