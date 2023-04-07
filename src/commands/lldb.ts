import { window } from "vscode";
import { os, setupDebugServer } from "../driver/frida";
import { LLDB } from "../driver/lldb";
import { AppItem, DeviceItem, ProcessItem, TargetItem } from "../providers/devices";


const map = new Map<string, LLDB>();

export async function setup(node: TargetItem): Promise<void> {
  if (node instanceof DeviceItem) {
    if (await os(node.data.id) === 'ios') {
      if (await setupDebugServer(node.data.id)) {
        window.showInformationMessage('Successfully resigned debugserver');
      }
    } else {
      window.showErrorMessage('This command is for iOS only');
    }
  } else {
    // todo: select from list
    window.showErrorMessage('Use the context menu instead');
  }
}

export async function debug(node: TargetItem): Promise<void> {
  if (!(node instanceof AppItem) && !(node instanceof ProcessItem)) {
    window.showErrorMessage('This command should be used in context menu');
    return;
  }

  const { id } = node.device;
  if (id === 'local') {
    window.showErrorMessage('debug local process is not implemented yet');
    return;
  }

  if (map.has(id)) {
    window.showErrorMessage(`Debice ${id} has an active debug session. Only one debugger is allowed at the moment`);
    return;
  }

  const lldb = new LLDB(id);
  try {
    await lldb.connect();
  } catch (e) {
    if (await window.showErrorMessage(`${e}`, 'Deploy debugserver', 'Cancel') === 'Deploy debugserver') {
      setupDebugServer(id);
      return;
    }
  }

  map.set(id, lldb);
  if (node instanceof AppItem) {
    if (node.data.pid) {
      await lldb.attach(node.data.pid);
    } else {
      await lldb.spawn(node.data.identifier);
    }
  } else if (node instanceof ProcessItem) {
    await lldb.attach(node.data.pid);
  }
  map.delete(id);
}

export function cleanup() {
  map.forEach(lldb => lldb.teardown());
}
