import { Progress } from "vscode";
import { logger } from "../logger";
import { python3Path } from "../utils";
import { fruit } from "./backend";
import { location } from "./frida";
import { RemoteTool } from "./remote";

type Bar = Progress<{ message?: string; increment?: number }>;

export class Decryptor extends RemoteTool {
  dependencies = ['zip', '/usr/local/bin/fouldecrypt'];

  async go(bundle: string, dest: string, progress: Bar): Promise<void> {   
    progress.report({ message: 'Starting iproxy' });
    await this.connect();
    progress.report({ message: `Fetching the path of ${bundle}` });
    const path = await location(this.id, bundle);
    logger.appendLine(`path of ${bundle}: ${path}`);
    progress.report({ message: `Creating bundle archive` });
    const cwd = (await this.exec('mktemp', '-d')).stdout.trim();
    logger.appendLine(`temp directory: ${cwd}`);
    const archive = `${cwd}/archive.zip`;
    await this.execInTerminal(...this.ssh('zip', '-r', archive, path));
    progress.report({ message: `Downloading bundle archive` });
    const local = await this.download(`${cwd}/archive.zip`);
    progress.report({ message: 'Clean up device' });
    await this.execInTerminal(...this.ssh('rm', archive));

    progress.report({ message: 'Decrypting MachO executables' });
    {
      const py: string = fruit('decrypt.py');
      const bin = python3Path();
      const args = [py, local, path, `${this.port}`, '-o', dest];
      await this.execInTerminal(bin, args);
    }
  }
}
