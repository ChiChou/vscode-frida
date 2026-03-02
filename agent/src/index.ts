import Java from 'frida-java-bridge';
import ObjC from 'frida-objc-bridge';

/* eslint-disable curly */
/* eslint-disable @typescript-eslint/naming-convention */

import { start, stop } from './log.js';
import { Runtime } from './types.js';
import type { MethodInfo, FieldInfo, ClassMemberInfo } from './types.js';
import { applyOverrides as applyJavaOverrides } from './java/inspect.js';
import { applyOverrides as applyObjCOverrides } from './fruity/inspect.js';

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

  methodsOf: async (_name: string): Promise<MethodInfo[]> => [],
  ownMethodsOf: async (_name: string): Promise<MethodInfo[]> => [],
  fieldsOf: async (_name: string): Promise<FieldInfo[]> => [],
  ownFieldsOf: async (_name: string): Promise<FieldInfo[]> => [],
  classMembers: async (_name: string): Promise<ClassMemberInfo> => ({ methods: [], fields: [] }),
  superClasses: async (_name: string): Promise<string[]> => [],

  classesHierarchy: (): [string[], number[]] => [[], []],

  modules: () => Process.enumerateModules(),
  exports: (name: string) => Process.findModuleByName(name)?.enumerateExports(),
  imports: (name: string) => Process.findModuleByName(name)?.enumerateImports(),
  symbols: (name: string) => Process.findModuleByName(name)?.enumerateSymbols(),
};

if (Java.available) {
  applyJavaOverrides(methods);
} else if (ObjC.available) {
  applyObjCOverrides(methods);
}

rpc.exports = methods;
