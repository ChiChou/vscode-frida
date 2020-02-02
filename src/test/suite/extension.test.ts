import * as assert from 'assert';

// You can import and use all API from the 'vscode' module
// as well as import your extension to test it
import * as vscode from 'vscode';
import { FileSystemProvider as Provider } from '../../providers/filesystem';

suite('Extension Test Suite', () => {
	test('Remote FileSystem', async () => {
		const p = new Provider();
		const root = 'frida-app://usb/com.apple.Preferences';
		const tmpFile = vscode.Uri.parse(`${root}/~/tmp/1/test`);

		await p.createDirectory(vscode.Uri.parse(`${root}/~/tmp/1`));
		await p.writeFile(tmpFile,
			new Uint8Array(Buffer.from('hello', 'utf8')), { overwrite: true, create: true });

		const list = await p.readDirectory(vscode.Uri.parse(`${root}/~/tmp/`));
		assert(list instanceof Array, 'directory listing');
		// console.log('list', list);
		const st = await p.stat(tmpFile);
		assert(st, 'file created');
		const blob = await p.readFile(tmpFile);
		assert(Buffer.from(blob).toString() === 'hello', 'read file');

		await p.delete(vscode.Uri.parse(`${root}/~/tmp/1`), { recursive: true });
	});
});
