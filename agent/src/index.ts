import Java from 'frida-java-bridge';
import ObjC from 'frida-objc-bridge';

/* eslint-disable curly */
/* eslint-disable @typescript-eslint/naming-convention */

import { start, stop } from './log.js';

enum Runtime {
  Java = 'Java',
  ObjectiveC = 'ObjectiveC',
  Generic = 'Generic',
};

const methods = {
  start,
  stop,

  runtime() {
    if (Java.available) return Runtime.Java;
    if (ObjC.available) return Runtime.ObjectiveC;
    return Runtime.Generic;
  },

  ping: () => Process.id,

  classes: async () => [] as string[],
  protocols: async () => [] as string[],

  methodsOf: async (_name: string) => [] as string[],
  ownMethodsOf: async (_name: string) => [] as string[],
  // fieldsOf: async (_name: string) => [] as string[],
  superClass: async (_name: string): Promise<string> => { throw new Error('Not implemented'); },

  modules: () => Process.enumerateModules(),
  exports: (name: string) => Process.findModuleByName(name)?.enumerateExports(),
  imports: (name: string) => Process.findModuleByName(name)?.enumerateImports(),
  symbols: (name: string) => Process.findModuleByName(name)?.enumerateSymbols(),
};

if (Java.available) {
  function perform<T>(fn: () => T): Promise<T> {
    return new Promise<T>((resolve) => {
      Java.perform(() => {
        resolve(fn());
      });
    });
  };

  methods.classes = async () => perform(() => Java.enumerateLoadedClassesSync());
  methods.ownMethodsOf =
    methods.methodsOf =
    async (name: string) => perform(() => Java.use(name).class.getMethods());
  // methods.fieldsOf = async (name: string) => perform(() => Java.use(name).class.getDeclaredFields());
  methods.superClass = async (name: string) => perform(() => Java.use(name).class.getSuperclass()?.getName());

} else if (ObjC.available) {
  methods.classes = async () => Object.keys(ObjC.classes);
  methods.protocols = async () => Object.keys(ObjC.protocols);

  function getClass(name: string) {
    if (ObjC.classes.hasOwnProperty(name)) return ObjC.classes[name];
    throw new Error(`Class ${name} not found`);
  }

  methods.ownMethodsOf = async (name: string) => getClass(name).$ownMethods;
  methods.methodsOf = async (name: string) => getClass(name).$methods;
  // methods.fieldsOf = async (name: string) => getClass(name).$ivars;
  methods.superClass = async (name: string) => getClass(name).$superClass?.name;
}

rpc.exports = methods;