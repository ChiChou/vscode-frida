import { workspace } from "vscode";
import { logger } from "../logger";

const remoteHosts = new Set<string>();
function loadRemoteHosts() {
  const hosts = workspace.getConfiguration('frida').get<Array<string>>('remoteHosts');
  if (Array.isArray(hosts)) {
    hosts.forEach(host => {
      if (typeof host === 'string') {
        remoteHosts.add(host);
      }
    });
  }
}

loadRemoteHosts();

function saveRemoteHosts() {
  workspace.getConfiguration('frida').update('remoteHosts', Array.from(remoteHosts), true);
}

export function connect(remote: string) {
  logger.appendLine(`Remote host added: ${remote}`);
  remoteHosts.add(remote);
  saveRemoteHosts();
}

export function disconnect(remote: string) {
  logger.appendLine(`Remote host removed: ${remote}`);
  remoteHosts.delete(remote);
  saveRemoteHosts();
}

export function all() {
  return Array.from(remoteHosts);
}

export function asParam() {
  return remoteHosts.size > 0 ? ['--remote', Array.from(remoteHosts).join(',')] : []
}