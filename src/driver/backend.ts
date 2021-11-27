import { join } from "path";

const base = join(__dirname, '..', '..', 'backend');

export function path(...args: string[]) {
  return join(base, ...args);
}

export function fruit(...args: string[]) {
  return path('fruit', ...args);
}

export function android(...args: string[]) {
  return path('android', ...args);
}
