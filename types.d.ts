export enum DeviceType {
  Local = 'local',
  Remote = 'remote',
  USB = 'usb',
}

export interface Device {
  id: string;
  name: string;
  type: DeviceType;
  icon: string;
}

export enum ItemType {
  device = 'Device',
  app = 'App',
  process = ''
}
