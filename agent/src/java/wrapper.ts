import type Java from 'frida-java-bridge';

export type Static<T extends Java.Wrapper = Java.Wrapper> = Java.Wrapper & {
  $new(...args: unknown[]): T;
  $alloc(): T;
};

export interface InputStream extends Java.Wrapper {
  read(buffer: Java.Wrapper): number;
  close(): void;
}

export interface ZipFile extends Java.Wrapper {
  getEntry(name: string): ZipEntry | null;
  getInputStream(entry: ZipEntry): InputStream;
  close(): void;
}

export type ZipEntry = Java.Wrapper;

export interface ByteArrayOutputStream extends Java.Wrapper {
  write(buffer: Java.Wrapper, offset: number, length: number): void;
  toByteArray(): Java.Wrapper;
}

export interface JModifier {
  isStatic: Java.MethodDispatcher;
  toString: Java.MethodDispatcher;
}

export interface JClass {
  getName: Java.MethodDispatcher;
  getModifiers: Java.MethodDispatcher;
  getMethods: Java.MethodDispatcher;
  getDeclaredMethods: Java.MethodDispatcher;
  getFields: Java.MethodDispatcher;
  getDeclaredFields: Java.MethodDispatcher;
  getSuperclass: Java.MethodDispatcher;
  getInterfaces: Java.MethodDispatcher;
}

export interface JMethod {
  getName: Java.MethodDispatcher;
  getModifiers: Java.MethodDispatcher;
  getReturnType: Java.MethodDispatcher;
  getParameterTypes: Java.MethodDispatcher;
}

export interface JField {
  getName: Java.MethodDispatcher;
  getModifiers: Java.MethodDispatcher;
  getType: Java.MethodDispatcher;
}
