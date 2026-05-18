
export enum ProviderType {
  Apps = 'apps',
  Processes = 'ps',
}

export enum DeviceType {
  Local = 'local',
  Remote = 'remote',
  USB = 'usb',
  TCP = 'tcp', // legacy
}

export class Device {
  id: string = '';
  name: string = '';
  os: 'ios' | 'macos' | 'windows' | 'linux' | 'android' | 'unknown' | 'n/a' = 'n/a';
  type: DeviceType = DeviceType.Local;
  icon: string = '';
}

export class App {
  identifier: string = '';
  name: string = '';
  pid: number = 0;
  icon: string = '';
}

export class Process {
  name: string = '';
  pid: number = 0;
  icon: string = '';
  path: string = '';
  cwd: string = '';
  user: string = '';
  ppid: number = 0;
  argv: string[] = [];
  metadataStatus: 'full' | 'limited' | 'unknown' = 'unknown';
  metadataError: string = '';
}
