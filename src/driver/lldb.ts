import * as cp from 'child_process';
import { IProxy } from "../iproxy";
import { location, port } from './frida';
import { RemoteTool } from "./ssh";

const LLDB_PATH = '/usr/bin/debugserver';


function dbg() {
  return function (target: LLDB, propertyKey: string, descriptor: PropertyDescriptor) {
    const original = descriptor.value;
    descriptor.value = async function (this: LLDB, ...args: any[]) {
      await this.connect();
      await this.bridge();
      const server = await original.call(this, ...args) as cp.ChildProcess;

      await new Promise((resolve, reject) => {
        server.on('exit', (code) => {
          if (code !== 0) {
            reject(new Error(`debugserver exited with ${code}`));
          }
          this.teardown();
        });
        setTimeout(resolve, 1000);
      });

      this.debugServer = server;
      await this.execInTerminal('lldb', [
        '--one-line',
        `process connect connect://127.1:${this.serverPort}`,
        '--one-line',
        'bt',
        '--one-line',
        'reg read'
      ]);

      this.teardown();
    };
  };
}

export class LLDB extends RemoteTool {
  dependencies = [LLDB_PATH, 'ldid'];
  iproxy?: IProxy;
  serverPort?: number;
  remotePort?: number;
  debugProxy?: cp.ChildProcess;
  debugServer?: cp.ChildProcess;

  async bridge(): Promise<void> {
    this.remotePort = await port(this.id);
    this.iproxy = new IProxy(this.remotePort, this.id);
    this.serverPort = await this.iproxy.start();
  }

  @dbg()
  async spawn(bundle: string): Promise<cp.ChildProcess> {
    const path = await location(this.id, bundle);
    const [bin, arg] = this.ssh(LLDB_PATH, '-x', 'backboard', `127.1:${this.remotePort}`, path);
    return cp.spawn(bin, arg);
  }

  @dbg()
  async attach(target: number | string): Promise<cp.ChildProcess> {
    const [bin, arg] = this.ssh(LLDB_PATH, `127.1:${this.remotePort}`, '-a', target.toString());
    return cp.spawn(bin, arg);
  }

  teardown() {
    if (this.iproxy) {
      this.iproxy.stop();
      this.iproxy = undefined;
    }

    if (this.debugServer) {
      this.debugServer.kill();
      this.remotePort = undefined;
      this.debugProxy = undefined;
    }
  }
}
