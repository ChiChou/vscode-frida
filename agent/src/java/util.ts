import Java from 'frida-java-bridge';

export function perform<T>(fn: () => T): Promise<T> {
  return new Promise<T>((resolve) => {
    Java.perform(() => {
      resolve(fn());
    });
  });
}